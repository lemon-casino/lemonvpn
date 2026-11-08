param(
    [Parameter(Mandatory=$true)][ValidateSet('Network','Sleep','Restore','Wake','Inspect','Probe','ArmProbe')][string]$Action,
    [Parameter(Mandatory=$true)][string]$WorkDir,
    [string]$AdapterId = '',
    [string]$TaskName = '',
    [int]$OfflineSeconds = 8,
    [int]$WakeSeconds = 30
)
$ErrorActionPreference = 'Stop'
$ProgressPreference = 'SilentlyContinue'
$WorkDir = [IO.Path]::GetFullPath($WorkDir)
[IO.Directory]::CreateDirectory($WorkDir) | Out-Null
$logFile = Join-Path $WorkDir 'windows-cycles.jsonl'
function Record($phase, $details) {
    $record = [ordered]@{at=[DateTime]::UtcNow.ToString('o'); action=$Action; phase=$phase; details=$details}
    $line = $record | ConvertTo-Json -Depth 6 -Compress
    [IO.File]::AppendAllText($logFile, $line + [Environment]::NewLine, [Text.UTF8Encoding]::new($false))
    Write-Output $line
}
function Find-Adapter {
    $matches = @(Get-NetAdapter -IncludeHidden | Where-Object { [string]$_.InterfaceGuid -eq $AdapterId })
    if ($matches.Count -ne 1) { throw 'The recorded adapter is no longer uniquely identifiable' }
    return $matches[0]
}
function Remove-RescueTask {
    if ($TaskName -like 'LemonVPN-Recovery-*') {
        Unregister-ScheduledTask -TaskName $TaskName -Confirm:$false -ErrorAction SilentlyContinue
    }
}
if ($Action -in @('Network','Restore','Inspect')) {
Add-Type -TypeDefinition @'
using System;
using System.ComponentModel;
using System.Runtime.InteropServices;
public static class LemonVpnWifiTest {
  [StructLayout(LayoutKind.Sequential,CharSet=CharSet.Unicode)] struct Parameters {
    public int Mode; [MarshalAs(UnmanagedType.LPWStr)] public string Profile;
    public IntPtr Ssid, Bssid; public int Bss; public uint Flags;
  }
  [DllImport("wlanapi.dll")] static extern uint WlanOpenHandle(uint version,IntPtr reserved,out uint negotiated,out IntPtr handle);
  [DllImport("wlanapi.dll")] static extern uint WlanCloseHandle(IntPtr handle,IntPtr reserved);
  [DllImport("wlanapi.dll")] static extern uint WlanQueryInterface(IntPtr handle,ref Guid id,int opcode,IntPtr reserved,out uint size,out IntPtr data,out uint type);
  [DllImport("wlanapi.dll")] static extern uint WlanGetProfileList(IntPtr handle,ref Guid id,IntPtr reserved,out IntPtr data);
  [DllImport("wlanapi.dll")] static extern uint WlanConnect(IntPtr handle,ref Guid id,ref Parameters p,IntPtr reserved);
  [DllImport("wlanapi.dll")] static extern void WlanFreeMemory(IntPtr data);
  static IntPtr Open() { uint version; IntPtr handle; uint error=WlanOpenHandle(2,IntPtr.Zero,out version,out handle); if(error!=0)throw new Win32Exception((int)error); return handle; }
  public static string Profile(Guid id) {
    IntPtr handle=Open(), data=IntPtr.Zero;
    try { uint size,type; uint error=WlanQueryInterface(handle,ref id,7,IntPtr.Zero,out size,out data,out type);
      if(error!=0)throw new Win32Exception((int)error);
      if(size<520)throw new Exception("Invalid WLAN connection structure");
      return Marshal.PtrToStringUni(IntPtr.Add(data,8),256).TrimEnd('\0');
    } finally { if(data!=IntPtr.Zero)WlanFreeMemory(data); WlanCloseHandle(handle,IntPtr.Zero); }
  }
  public static string[] Profiles(Guid id) {
    IntPtr handle=Open(), data=IntPtr.Zero;
    try { uint error=WlanGetProfileList(handle,ref id,IntPtr.Zero,out data); if(error!=0)throw new Win32Exception((int)error);
      int count=Marshal.ReadInt32(data); if(count<0 || count>1024)throw new Exception("Invalid profile count");
      var profiles=new string[count]; for(int i=0;i<count;i++)profiles[i]=Marshal.PtrToStringUni(IntPtr.Add(data,8+i*516),256).TrimEnd('\0'); return profiles;
    } finally { if(data!=IntPtr.Zero)WlanFreeMemory(data); WlanCloseHandle(handle,IntPtr.Zero); }
  }
  public static void Reconnect(Guid id,string profile) {
    IntPtr handle=Open();
    try { var p=new Parameters {Mode=0,Profile=profile,Bss=1}; uint error=WlanConnect(handle,ref id,ref p,IntPtr.Zero); if(error!=0)throw new Win32Exception((int)error); }
    finally { WlanCloseHandle(handle,IntPtr.Zero); }
  }
}
'@
}
function Original-Profile($adapter) {
    # Saved profile names and NLM's existing connection label are readable
    # without requesting Wi-Fi scans/current-connection location access.
    $profiles = @([LemonVpnWifiTest]::Profiles([Guid]$adapter.InterfaceGuid))
    $label = [string](Get-NetConnectionProfile -InterfaceIndex $adapter.InterfaceIndex -ErrorAction Stop | Select-Object -First 1 -ExpandProperty Name)
    if ($profiles -ccontains $label) { return $label }
    if ($profiles.Count -eq 1) { return [string]$profiles[0] }
    throw 'Cannot uniquely match the saved Wi-Fi profile; do not disable the adapter'
}
if ($Action -eq 'Inspect') {
    $up = @(Get-NetAdapter -Physical | Where-Object { $_.Status -eq 'Up' })
    if ($up.Count -ne 1) { throw 'Expected one active physical adapter' }
    $profile = Original-Profile $up[0]
    [IO.File]::WriteAllText((Join-Path $WorkDir 'network-state.json'), (@{adapterId=[string]$up[0].InterfaceGuid;profile=$profile} | ConvertTo-Json -Compress), [Text.UTF8Encoding]::new($false))
    Record 'wifi_profile_readable' @{profilePresent=([bool]$profile); adapter=$up[0].Name}
    return
}
if ($Action -eq 'Probe') {
    Record 'independent_task_probe_succeeded' @{identity=[Security.Principal.WindowsIdentity]::GetCurrent().Name}
    Remove-RescueTask
    return
}
function Restore-Connection {
    $adapter = Find-Adapter
    if ($adapter.AdminStatus -ne 'Up') { Enable-NetAdapter -InputObject $adapter -Confirm:$false }
    $stateFile = Join-Path $WorkDir 'network-state.json'
    if (Test-Path -LiteralPath $stateFile) {
        $state = Get-Content -LiteralPath $stateFile -Raw -Encoding UTF8 | ConvertFrom-Json
        if ($state.profile) {
            Start-Sleep -Seconds 2
            [LemonVpnWifiTest]::Reconnect([Guid]$AdapterId, [string]$state.profile)
            Record 'original_wifi_profile_reconnect_requested' @{}
        }
    }
}
if ($Action -eq 'Restore') {
    try {
        Restore-Connection
        Record 'independent_restore_enabled' @{adapterId=$AdapterId}
        Remove-RescueTask
    } catch { Record 'independent_restore_failed' @{error=$_.Exception.Message}; throw }
    return
}
if ($Action -eq 'Wake') {
    Record 'independent_wake_task_executed' @{}
    Remove-RescueTask
    return
}
function Register-RescueTask($rescueAction) {
    $script:TaskName = 'LemonVPN-Recovery-' + [Guid]::NewGuid().ToString('N')
    $powershell = Join-Path $env:SystemRoot 'System32\WindowsPowerShell\v1.0\powershell.exe'
    function Quote-PS([string]$value) { return "'" + $value.Replace("'", "''") + "'" }
    $invoke = '& ' + (Quote-PS $PSCommandPath) + ' -Action ' + (Quote-PS $rescueAction) + ' -WorkDir ' + (Quote-PS $WorkDir) + ' -TaskName ' + (Quote-PS $TaskName)
    if ($AdapterId) { $invoke += ' -AdapterId ' + (Quote-PS $AdapterId) }
    $errorLog = Quote-PS (Join-Path $WorkDir 'independent-task-errors.log')
    $wrapped = 'try { ' + $invoke + ' } catch { [IO.File]::AppendAllText(' + $errorLog + ',($_ | Out-String)); exit 1 }'
    $arguments = '-NoProfile -NonInteractive -WindowStyle Hidden -EncodedCommand ' + [Convert]::ToBase64String([Text.Encoding]::Unicode.GetBytes($wrapped))
    $taskAction = New-ScheduledTaskAction -Execute $powershell -Argument $arguments
    $trigger = New-ScheduledTaskTrigger -Once -At ([DateTime]::Now.AddMinutes(1))
    $settings = New-ScheduledTaskSettingsSet -WakeToRun -StartWhenAvailable -AllowStartIfOnBatteries -DontStopIfGoingOnBatteries -ExecutionTimeLimit (New-TimeSpan -Minutes 2) -RestartCount 2 -RestartInterval (New-TimeSpan -Minutes 1)
    $principal = New-ScheduledTaskPrincipal -UserId ([Security.Principal.WindowsIdentity]::GetCurrent().User.Value) -LogonType Interactive -RunLevel Highest
    Register-ScheduledTask -TaskName $TaskName -Action $taskAction -Trigger $trigger -Settings $settings -Principal $principal -Description 'Temporary LemonVPN test recovery; removes itself after running.' | Out-Null
    Record 'independent_rescue_armed' @{task=$TaskName; action=$rescueAction; triggerUtc=[DateTime]::UtcNow.AddMinutes(1).ToString('o')}
}
if ($Action -eq 'ArmProbe') {
    Register-RescueTask 'Probe'
    Start-ScheduledTask -TaskName $TaskName
    return
}
if ($Action -eq 'Network') {
    if (!$AdapterId) {
        $up = @(Get-NetAdapter -Physical | Where-Object { $_.Status -eq 'Up' })
        if ($up.Count -ne 1) { throw 'Choose exactly one active physical adapter before cycling' }
        $AdapterId = [string]$up[0].InterfaceGuid
    }
    $adapter = Find-Adapter
    if ($adapter.Status -ne 'Up') { throw 'The target adapter must already be connected' }
    $profile = Original-Profile $adapter
    if (!$profile) { throw 'The original Wi-Fi profile must be captured before disabling WLAN' }
    [IO.File]::WriteAllText((Join-Path $WorkDir 'network-state.json'), (@{adapterId=$AdapterId;profile=$profile} | ConvertTo-Json -Compress), [Text.UTF8Encoding]::new($false))
    Register-RescueTask 'Restore'
    try {
        Record 'network_before' @{adapter=$adapter.Name; interfaceIndex=$adapter.InterfaceIndex; status=[string]$adapter.Status}
        Disable-NetAdapter -InputObject $adapter -Confirm:$false
        $disabled = Find-Adapter
        if ($disabled.AdminStatus -eq 'Up') { throw 'Adapter did not become administratively disabled' }
        Record 'network_disabled' @{status=[string]$disabled.Status; offlineSeconds=$OfflineSeconds}
        Start-Sleep -Seconds ([Math]::Min(15, [Math]::Max(3, $OfflineSeconds)))
    } finally {
        Restore-Connection
        Record 'network_reenabled' @{}
    }
    $deadline = [DateTime]::UtcNow.AddSeconds(45)
    do {
        $adapter = Find-Adapter
        if ($adapter.Status -eq 'Up') { break }
        Start-Sleep -Milliseconds 500
    } while ([DateTime]::UtcNow -lt $deadline)
    if ($adapter.Status -ne 'Up') { throw 'Adapter did not reconnect before the deadline; independent rescue remains armed' }
    Record 'network_up' @{adapter=$adapter.Name; interfaceIndex=$adapter.InterfaceIndex; status=[string]$adapter.Status}
    Remove-RescueTask
    return
}

# Existing S3 only. The helper never enables hibernation, changes a power plan,
# disables wake events, or changes any authentication/privacy setting.
Add-Type -TypeDefinition @'
using System;
using System.ComponentModel;
using System.Runtime.InteropServices;
public static class LemonVpnSleepTest {
  [StructLayout(LayoutKind.Sequential)] struct Luid { public uint Low; public int High; }
  [StructLayout(LayoutKind.Sequential)] struct TokenPrivileges { public uint Count; public Luid Luid; public uint Attributes; }
  [StructLayout(LayoutKind.Sequential)] public struct PowerStatus { public byte AC, Battery, Percent, Reserved; public uint Life, FullLife; }
  [DllImport("kernel32.dll", SetLastError=true)] static extern IntPtr GetCurrentProcess();
  [DllImport("advapi32.dll", SetLastError=true)] static extern bool OpenProcessToken(IntPtr process, uint access, out IntPtr token);
  [DllImport("advapi32.dll", CharSet=CharSet.Unicode, SetLastError=true)] static extern bool LookupPrivilegeValue(string system, string name, out Luid luid);
  [DllImport("advapi32.dll", SetLastError=true)] static extern bool AdjustTokenPrivileges(IntPtr token, bool disableAll, ref TokenPrivileges privileges, uint size, IntPtr previous, IntPtr returned);
  [DllImport("kernel32.dll", SetLastError=true)] static extern bool GetSystemPowerStatus(out PowerStatus status);
  [DllImport("kernel32.dll", SetLastError=true, CharSet=CharSet.Unicode)] static extern IntPtr CreateWaitableTimer(IntPtr attributes, bool manualReset, string name);
  [DllImport("kernel32.dll", SetLastError=true)] static extern bool SetWaitableTimer(IntPtr timer, ref long due, int period, IntPtr callback, IntPtr arg, bool resume);
  [DllImport("kernel32.dll", SetLastError=true)] static extern bool CancelWaitableTimer(IntPtr timer);
  [DllImport("kernel32.dll")] static extern bool CloseHandle(IntPtr handle);
  [DllImport("kernel32.dll")] static extern void SetLastError(uint error);
  [DllImport("powrprof.dll", SetLastError=true)] [return:MarshalAs(UnmanagedType.U1)] static extern bool SetSuspendState([MarshalAs(UnmanagedType.U1)] bool hibernate, [MarshalAs(UnmanagedType.U1)] bool force, [MarshalAs(UnmanagedType.U1)] bool disableWake);
  public static IntPtr Arm(int seconds) {
    PowerStatus power;
    if (!GetSystemPowerStatus(out power) || power.AC != 1) throw new Exception("AC power is required for the existing wake-timer policy");
    IntPtr token;
    if (!OpenProcessToken(GetCurrentProcess(), 0x28, out token)) throw new Win32Exception();
    try {
      Luid luid;
      if (!LookupPrivilegeValue(null, "SeShutdownPrivilege", out luid)) throw new Win32Exception();
      var privileges = new TokenPrivileges {Count=1,Luid=luid,Attributes=2};
      SetLastError(0);
      if (!AdjustTokenPrivileges(token,false,ref privileges,0,IntPtr.Zero,IntPtr.Zero) || Marshal.GetLastWin32Error()!=0) throw new Win32Exception();
    } finally { CloseHandle(token); }
    IntPtr timer = CreateWaitableTimer(IntPtr.Zero,true,null);
    if (timer==IntPtr.Zero) throw new Win32Exception();
    long due=DateTime.UtcNow.AddSeconds(seconds).ToFileTimeUtc();
    SetLastError(0);
    if (!SetWaitableTimer(timer,ref due,0,IntPtr.Zero,IntPtr.Zero,true) || Marshal.GetLastWin32Error()==50) { CloseHandle(timer); throw new Win32Exception(); }
    return timer;
  }
  public static void Sleep() { if (!SetSuspendState(false,false,false)) throw new Win32Exception(); }
  public static void Release(IntPtr timer) { CancelWaitableTimer(timer); CloseHandle(timer); }
}
'@
$timer = [IntPtr]::Zero
try {
    Register-RescueTask 'Wake'
    $timer = [LemonVpnSleepTest]::Arm([Math]::Min(30, [Math]::Max(15, $WakeSeconds)))
    $before = [DateTime]::UtcNow
    Record 's3_sleep_requested' @{wakeUtc=$before.AddSeconds($WakeSeconds).ToString('o')}
    [LemonVpnSleepTest]::Sleep()
    $after = [DateTime]::UtcNow
    Record 's3_sleep_call_returned' @{elapsedSeconds=($after-$before).TotalSeconds}
    $deadline = [DateTime]::UtcNow.AddSeconds(10)
    do {
        $events = @(Get-WinEvent -FilterHashtable @{LogName='System';ProviderName='Microsoft-Windows-Kernel-Power';Id=42,107;StartTime=$before.ToLocalTime().AddSeconds(-1)} -ErrorAction SilentlyContinue)
        if (($events | Where-Object Id -eq 42) -and ($events | Where-Object Id -eq 107)) { break }
        Start-Sleep -Milliseconds 500
    } while ([DateTime]::UtcNow -lt $deadline)
    if (!(($events | Where-Object Id -eq 42) -and ($events | Where-Object Id -eq 107))) { throw 'No matching Windows sleep/resume event pair; do not count this as an S3 pass' }
    Record 's3_sleep_resume_verified' @{events=@($events | Select-Object Id,@{Name='utc';Expression={$_.TimeCreated.ToUniversalTime().ToString('o')}})}
} finally {
    if ($timer -ne [IntPtr]::Zero) { [LemonVpnSleepTest]::Release($timer) }
    Remove-RescueTask
}
