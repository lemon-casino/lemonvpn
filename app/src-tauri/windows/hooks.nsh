; Building this script does not execute any integration operations.
!macro NSIS_HOOK_PREUNINSTALL
  Push $0
  Push $1
  ReadRegStr $0 HKCU "Software\Microsoft\Windows\CurrentVersion\Run" "LemonVPN"
  StrCmp $0 '$"$INSTDIR\lemonvpn.exe$" --autostart' 0 +2
    DeleteRegValue HKCU "Software\Microsoft\Windows\CurrentVersion\Run" "LemonVPN"
  SetRegView 64
  ReadRegStr $0 HKLM "SYSTEM\CurrentControlSet\Services\LemonVPN.Tun" "ImagePath"
  StrCmp $0 "" lemonvpn_service_removed
  ClearErrors
  ExecShellWait "runas" "$INSTDIR\lemonvpn-service.exe" "--uninstall" SW_HIDE
  IfErrors lemonvpn_service_remove_failed
  ReadRegStr $0 HKLM "SYSTEM\CurrentControlSet\Services\LemonVPN.Tun" "ImagePath"
  StrCmp $0 "" lemonvpn_service_removed
lemonvpn_service_remove_failed:
  MessageBox MB_OK|MB_ICONEXCLAMATION "LemonVPN could not remove its TUN service. Uninstall was cancelled."
  Pop $1
  Pop $0
  Abort
lemonvpn_service_removed:
  Pop $1
  Pop $0
!macroend
