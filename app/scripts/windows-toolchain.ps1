# Configure only the disposable Actions runner. Never installs tools locally.
$ErrorActionPreference = 'Stop'
if ($env:GITHUB_ACTIONS -ne 'true') { throw 'This toolchain setup is restricted to GitHub Actions runners.' }
$targetArch = switch ($env:BUILD_TARGET) {
    'x86_64-pc-windows-msvc' { 'x64' }
    'aarch64-pc-windows-msvc' { 'arm64' }
    default { throw "Unsupported Windows target: $env:BUILD_TARGET" }
}
$hostArch = if ([System.Runtime.InteropServices.RuntimeInformation]::OSArchitecture -eq 'Arm64') { 'arm64' } else { 'x64' }
$vswhere = @(
    "${env:ProgramFiles(x86)}\Microsoft Visual Studio\Installer\vswhere.exe",
    "$env:ProgramFiles\Microsoft Visual Studio\Installer\vswhere.exe"
) | Where-Object { Test-Path -LiteralPath $_ } | Select-Object -First 1
if (-not $vswhere) { throw 'Visual Studio Installer/vswhere is missing from the Windows runner.' }
$component = if ($targetArch -eq 'arm64') { 'Microsoft.VisualStudio.Component.VC.Tools.ARM64' } else { 'Microsoft.VisualStudio.Component.VC.Tools.x86.x64' }
$installation = (& $vswhere -latest -products '*' -requires $component -property installationPath | Select-Object -First 1)
if ($LASTEXITCODE -ne 0 -or -not $installation) { throw "The runner is missing MSVC tools for $targetArch ($component)." }
$developerCommand = Join-Path $installation 'Common7\Tools\VsDevCmd.bat'
if (-not (Test-Path -LiteralPath $developerCommand)) { throw 'VsDevCmd.bat is missing.' }
# Only fixed compiler setup arguments are passed to cmd; no file operations.
$compilerEnvironment = & "$env:SystemRoot\System32\cmd.exe" /d /s /c "`"`"$developerCommand`" -no_logo -arch=$targetArch -host_arch=$hostArch >nul && set`""
if ($LASTEXITCODE -ne 0) { throw "Cannot initialize the $hostArch -> $targetArch MSVC environment." }
$allow = @('INCLUDE', 'LIB', 'LIBPATH', 'VCINSTALLDIR', 'VCToolsInstallDir', 'VCToolsVersion', 'WindowsSdkDir', 'WindowsSDKVersion', 'UniversalCRTSdkDir', 'UCRTVersion')
foreach ($line in $compilerEnvironment) {
    $at = $line.IndexOf('=')
    if ($at -le 0) { continue }
    $key = $line.Substring(0, $at)
    $value = $line.Substring($at + 1)
    if ($key -ieq 'PATH') {
        $env:PATH = $value
        foreach ($entry in $value.Split(';', [System.StringSplitOptions]::RemoveEmptyEntries)) {
            [System.IO.File]::AppendAllText($env:GITHUB_PATH, "$entry`n")
        }
    } elseif ($allow -contains $key) {
        Set-Item -LiteralPath "Env:$key" -Value $value
        [System.IO.File]::AppendAllText($env:GITHUB_ENV, "$key=$value`n")
    }
}
function Find-Clang {
    $fromPath = Get-Command clang.exe -ErrorAction SilentlyContinue
    if ($fromPath) { return $fromPath.Source }
    @(
        (Join-Path $installation "VC\Tools\Llvm\$hostArch\bin\clang.exe"),
        (Join-Path $installation 'VC\Tools\Llvm\bin\clang.exe'),
        "$env:ProgramFiles\LLVM\bin\clang.exe",
        "${env:ProgramFiles(x86)}\LLVM\bin\clang.exe"
    ) | Where-Object { Test-Path -LiteralPath $_ } | Select-Object -First 1
}
$clang = Find-Clang
if (-not $clang) {
    # ring requires Clang's Windows ARM64 assembler; do not rely on PATH luck.
    & choco install llvm -y --no-progress
    if ($LASTEXITCODE -notin @(0, 1641, 3010)) { throw 'LLVM installation failed.' }
    $clang = Find-Clang
}
if (-not $clang) { throw 'Clang is still unavailable after preparing LLVM.' }
[System.IO.File]::AppendAllText($env:GITHUB_PATH, "$(Split-Path -Parent $clang)`n")
if ($targetArch -eq 'arm64') {
    [System.IO.File]::AppendAllText($env:GITHUB_ENV, "CC_aarch64_pc_windows_msvc=$clang`n")
}
Write-Host "Prepared MSVC $hostArch -> $targetArch and LLVM/Clang for the release build."
