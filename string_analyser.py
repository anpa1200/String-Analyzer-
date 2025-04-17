#!/usr/bin/env python3
"""
String Analyzer

This script extracts printable strings from a binary file,
computes the file's Shannon entropy, and filters the extracted
strings using regex patterns and predefined lists. The filtered results
are grouped by type and output in either unfiltered mode, filtered mode,
or as an AI prompt for further analysis.
"""

import re
import os
import base64
from math import log2

# --- Configuration Parameters ---
MIN_USEFUL_COUNT = 10
ENTROPY_THRESHOLD = 5.0

# --- Predefined Lists ---

# Windows API commands (original + extended)
windows_API_commands = [
    "CreateWindowEx", "DefWindowProc", "DispatchMessage", "GetMessage", "PostQuitMessage",
    "RegisterClassEx", "TranslateMessage", "BeginPaint", "EndPaint", "GetClientRect",
    "LoadCursor", "LoadIcon", "PostMessage", "SendMessage", "SetWindowText",
    "GetWindowText", "DrawText", "UpdateWindow", "CreateBrushIndirect", "CreateFontIndirect",
    "CreatePen", "DeleteObject", "GetStockObject", "SelectObject", "BitBlt",
    "CreateCompatibleBitmap", "CreateCompatibleDC", "DeleteDC", "GetDeviceCaps", "SetStretchBltMode",
    "StretchBlt", "TextOut", "GetTextExtentPoint32", "Ellipse", "Polygon",
    "Rectangle", "RoundRect", "CreateFile", "ReadFile", "WriteFile",
    "CloseHandle", "SetFilePointer", "FlushFileBuffers", "GetFileSize", "GetFileAttributes",
    "SetFileAttributes", "DeleteFile", "MoveFile", "CopyFile", "CreateDirectory",
    "RemoveDirectory", "GetDiskFreeSpace", "GetVolumeInformation", "FindFirstFile", "FindNextFile",
    "FindClose", "GetCurrentDirectory", "SetCurrentDirectory", "GetTempPath", "GetTempFileName",
    "SetEndOfFile", "DeviceIoControl", "GlobalAlloc", "GlobalFree", "GlobalLock",
    "GlobalUnlock", "GlobalSize", "LocalAlloc", "LocalFree", "LocalLock",
    "LocalUnlock", "LocalSize", "VirtualAlloc", "VirtualFree", "VirtualQuery",
    "VirtualProtect", "HeapCreate", "HeapDestroy", "HeapAlloc", "HeapFree",
    "HeapSize", "HeapLock", "HeapUnlock", "HeapCompact", "HeapValidate",
    "HeapWalk", "GetProcessHeap", "GetProcAddress", "LoadLibrary", "FreeLibrary",
    "ExitProcess", "GetModuleHandle", "WaitForSingleObject", "CreateThread", "CreateProcess",
    "GetCurrentProcess", "GetCurrentThread", "GetExitCodeProcess", "GetExitCodeThread", "GetStartupInfo",
    "OpenProcess", "TerminateProcess", "TerminateThread", "SuspendThread", "ResumeThread",
    "CloseHandle", "SetHandleInformation", "DuplicateHandle", "GetStdHandle", "SetStdHandle",
    "IsDebuggerPresent", "DebugBreak", "OutputDebugString", "ContinueDebugEvent", "WaitForDebugEvent",
    "SetThreadContext", "GetThreadContext", "ReadProcessMemory", "WriteProcessMemory", "CreateRemoteThread",
    "DebugActiveProcess", "GetLastError", "SetLastError", "FormatMessage", "LocalFree",
    "Sleep", "GetTickCount", "QueryPerformanceCounter", "QueryPerformanceFrequency", "GetCurrentThreadId",
    "GetCurrentProcessId", "SetUnhandledExceptionFilter", "IsProcessorFeaturePresent", "GetSystemTime", "SetSystemTime",
    "GetLocalTime", "SetLocalTime", "GetSystemTimeAdjustment", "GetSystemVersion", "GetSystemDirectory",
    "GetWindowsDirectory", "GetDriveType", "GetSystemInfo", "SystemParametersInfo", "GetUserName",
    "GetComputerName", "GetVersionEx", "OutputDebugString", "GetPrivateProfileString", "WritePrivateProfileString",
    "GetPrivateProfileInt", "WritePrivateProfileSection", "GetProfileString", "WriteProfileString", "GetProfileInt",
    "DestroyWindow", "ShowWindow", "InvalidateRect", "ValidateRect", "AdjustWindowRect", "SetWindowPos",
    "GetWindowRect", "ScreenToClient", "ClientToScreen", "EnableWindow", "SetFocus", "GetFocus",
    "SetActiveWindow", "BringWindowToTop", "SetForegroundWindow", "FlashWindow", "FlashWindowEx",
    "GetDC", "ReleaseDC", "MoveToEx", "LineTo", "SetPixel", "GetPixel",
    "CreateSolidBrush", "CreateHatchBrush", "CreateDIBSection", "AlphaBlend", "TransparentBlt",
    "OpenProcessToken", "AdjustTokenPrivileges", "LookupPrivilegeValue", "DuplicateToken", "ImpersonateLoggedOnUser",
    "RevertToSelf", "CreateToolhelp32Snapshot", "Process32First", "Process32Next", "Thread32First",
    "Thread32Next", "SetFileTime", "GetFileTime", "CreateMutex", "OpenMutex", "ReleaseMutex",
    "CreateEvent", "SetEvent", "ResetEvent", "CreateSemaphore", "ReleaseSemaphore",
    "CreateWaitableTimer", "SetWaitableTimer", "CancelWaitableTimer", "CoInitialize", "CoUninitialize",
    "CoCreateInstance", "CoInitializeEx", "WinExec", "CreateProcessAsUser", "SetWindowLong",
    "GetWindowLong", "SetWindowLongPtr", "GetWindowLongPtr", "TrackMouseEvent", "GetCursorPos",
    "SetCursorPos", "ClipCursor", "ShowCursor", "LoadImage", "ImageList_Create",
    "ImageList_Add", "ImageList_Destroy", "StartDoc", "EndDoc", "StartPage",
    "EndPage", "AbortDoc", "SetTimer", "KillTimer", "RegisterHotKey", "UnregisterHotKey",
    "SendInput", "mouse_event", "keybd_event", "GetDIBits", "SetDIBits", "CreateFileMapping",
    "OpenFileMapping", "MapViewOfFile", "UnmapViewOfFile", "OpenThreadToken", "GetThreadToken",
    "SetThreadToken", "GetProcessTimes", "SetProcessAffinityMask", "GetProcessAffinityMask", "CreateProcessWithTokenW",
    "RegisterServiceCtrlHandler", "SetServiceStatus", "ControlService", "QueryServiceStatus", "StartServiceCtrlDispatcher",
    "OpenSCManager", "CreateService", "DeleteService", "ChangeServiceConfig", "EnumServicesStatus",
    "CloseServiceHandle", "WTSQuerySessionInformation", "WTSFreeMemory", "WTSEnumerateSessions", "NetUserGetInfo",
    "NetLocalGroupGetMembers", "NetGroupGetUsers", "SendMessageTimeout", "SendNotifyMessage", "CallMsgFilter",
    "PeekMessage", "GetMessageExtraInfo", "SetMessageExtraInfo", "LoadAccelerators", "TranslateAccelerator",
    "IsWindow", "IsWindowVisible", "SetWindowRgn", "GetWindowRgn", "CreateRoundRectRgn", "CombineRgn",
    "CreateRectRgn", "CreatePolygonRgn", "OffsetRgn", "ExtCreateRegion", "GetRgnBox",
    "PtInRegion", "RectInRegion", "EqualRgn", "GetClipBox", "SelectClipRgn", "ExcludeClipRect",
    "IntersectClipRect", "InvertRgn", "OffsetClipRgn", "CreateDC", "DeleteDC", "CreateCompatibleDC",
    "CreateDIBSection", "PlgBlt", "AlphaBlend", "TransparentBlt", "BitBlt", "GetDIBits",
    "SetDIBits", "SetDIBitsToDevice", "GetDeviceCaps", "GetSystemPaletteEntries", "SetDIBColorTable",
    "RealizePalette", "SetPaletteEntries", "GetNearestColor", "SetColorAdjustment", "GetColorAdjustment",
    "EnumDisplayDevices", "EnumDisplayMonitors", "GetMonitorInfo", "GetWindowDC", "ReleaseDC",
    "SwapBuffers", "wglCreateContext", "wglDeleteContext", "wglMakeCurrent", "wglShareLists", "wglGetCurrentContext",
    "wglGetCurrentDC", "wglChoosePixelFormat", "wglDescribePixelFormat", "wglSetPixelFormat", "wglSwapBuffers",
    "ChoosePixelFormat", "DescribePixelFormat", "SetPixelFormat", "SwapBuffers", "EnumDisplaySettings", "ChangeDisplaySettings",
    "ChangeDisplaySettingsEx", "RegisterDeviceNotification", "UnregisterDeviceNotification", "SetupDiGetClassDevs", "SetupDiEnumDeviceInterfaces",
    "SetupDiGetDeviceInterfaceDetail", "SetupDiDestroyDeviceInfoList", "CM_Get_Device_ID", "CM_Locate_DevNode", "CM_Get_DevNode_Status",
    "CM_Request_Device_Eject", "CM_Reenumerate_DevNode", "CM_Get_DevNode_Registry_Property", "SetupDiEnumDeviceInfo", "SetupDiGetDeviceRegistryProperty",
    "SetupDiSetDeviceRegistryProperty", "GetFileInformationByHandle", "CreateNamedPipe", "ConnectNamedPipe", "DisconnectNamedPipe",
    "PeekNamedPipe", "TransactNamedPipe", "CreateIoCompletionPort", "GetQueuedCompletionStatus", "PostQueuedCompletionStatus",
    "CancelIo", "CancelIoEx", "QueryDirectoryFile", "NotifyChangeDirectoryFile", "ReadDirectoryChangesW",
    "WriteDirectoryChangesW", "FindFirstChangeNotification", "FindNextChangeNotification", "FindCloseChangeNotification", "CreateJobObject",
    "OpenJobObject", "AssignProcessToJobObject", "TerminateJobObject", "QueryInformationJobObject", "SetInformationJobObject",
    "IsWow64Process", "Wow64DisableWow64FsRedirection", "Wow64RevertWow64FsRedirection", "GetSystemWow64Directory", "VirtualLock",
    "VirtualUnlock", "FlushProcessWriteBuffers", "InterlockedIncrement", "InterlockedDecrement", "InterlockedExchange",
    "InterlockedCompareExchange", "EnumProcesses", "EnumProcessModules", "GetModuleBaseName", "GetModuleFileNameEx",
    "GetModuleInformation", "VirtualAllocEx", "VirtualFreeEx", "WriteProcessMemory", "ReadProcessMemory", "Module32First",
    "Module32Next", "Process32First", "Process32Next", "Thread32First", "Thread32Next"
]

# Extra API functions (over 100 additional functions)
extra_API_commands = [
    # Netapi32.dll functions
    "NetShareAdd", "NetShareDel", "NetShareEnum", "NetUserAdd", "NetUserDel", "NetUserEnum",
    "NetLocalGroupAdd", "NetLocalGroupDel", "NetLocalGroupEnum", "NetGroupAdd", "NetGroupDel",
    "NetGroupEnum", "NetFileEnum", "NetFileClose", "NetSessionEnum", "NetSessionDel",
    "NetStatisticsGet", "NetServerEnum", "NetServerGetInfo", "NetServerSetInfo", "NetRemoteTOD",
    "NetWkstaGetInfo", "NetWkstaSetInfo",
    # Shell32.dll additional functions
    "SHGetDesktopFolder", "SHGetSpecialFolderPath", "SHGetPathFromIDList", "SHAppBarMessage",
    "SHGetMalloc", "SHGetFileInfo", "SHCreateDirectoryEx", "SHChangeNotify", "SHUpdateImage",
    "SHCreateShellItem",
    # Comctl32.dll additional functions
    "ImageList_GetIconSize", "ImageList_SetIconSize", "ImageList_AddMasked", "ImageList_DrawEx",
    # Wininet.dll additional functions
    "InternetOpenUrl", "InternetGetConnectedState", "InternetQueryOption", "InternetSetCookie",
    "InternetGetCookie", "InternetCrackUrl", "InternetCombineUrl",
    # Crypt32.dll additional functions
    "CryptCreateHash", "CryptHashData", "CryptSignHash", "CryptVerifySignature", "CryptDestroyHash",
    "CryptDuplicateHash", "CryptGetHashParam", "CryptSetHashParam",
    # Userenv.dll additional functions
    "LoadUserProfile", "UnloadUserProfile", "GetAllUsersProfileDirectory",
    # Psapi.dll additional functions
    "EnumDeviceDrivers", "GetDeviceDriverFileName", "GetDeviceDriverBaseName",
    # Ntdll.dll additional functions
    "NtCreateFile", "NtOpenFile", "NtQueryInformationFile", "NtSetInformationFile",
    "NtReadFile", "NtWriteFile", "NtClose", "NtQuerySystemInformation",
    # Powrprof.dll additional functions
    "PowerSetRequest", "PowerClearRequest", "PowerCreateRequest",
    # Additional Advapi32.dll functions
    "AuditSetSystemPolicy", "AuditQuerySystemPolicy", "SetServiceObjectSecurity",
    "QueryServiceObjectSecurity", "GetSidIdentifierAuthority", "ConvertSidToStringSid",
    # Setupapi.dll functions
    "SetupDiGetClassDescription", "SetupDiGetDeviceProperty", "SetupDiSetDeviceProperty",
    "SetupDiEnumDeviceInterfacesEx",
    # Additional miscellaneous functions
    "SHBrowseForFolder", "SHQueryRecycleBin", "SHEmptyRecycleBin", "CoGetObjectContext",
    "CoLockObjectExternal", "CoDisconnectObject", "CoMarshalInterThreadInterfaceInStream",
    "CoGetInterfaceAndReleaseStream", "CoCreateFreeThreadedMarshaler", "CoInitializeSecurity",
    "CoSetProxyBlanket", "CoQueryProxyBlanket", "EnumSystemLocales", "GetLocaleInfo",
    "SetLocaleInfo", "GetUserDefaultLocaleName", "SetUserDefaultLocaleName",
    "GetCalendarInfo", "SetCalendarInfo", "VerSetConditionMask", "VerifyVersionInfo",
    "CertAddEncodedCertificateToStore", "CertEnumCertificatesInStore", "CertFindChainInStore",
    "CertFreeCertificateChain", "CertVerifyCertificateChainPolicy", "CertGetCertificateContextProperty",
    "DbgUiConnectToDbg", "DbgUiWaitStateChange", "DbgUiContinue", "DbgUiStopDebugging",
    "VirtualProtectEx", "FlushInstructionCache", "CreateFiber", "ConvertFiberToThread",
    "SwitchToFiber", "DeleteFiber", "GetFiberData", "SetFiberData", "ConvertThreadToFiber"
]

# Additional extra commands (user-specified)
additional_extra_commands = [
    "RegCloseKey", "RegCreateKeyExA", "RegCreateKeyExW", "RegEnumKeyExA", "RegEnumKeyExW",
    "RegOpenKeyExA", "RegOpenKeyExW", "SHELL32.dll", "ShellExecuteA", "ShellExecuteExA",
    "ShellExecuteExW", "ShellExecuteW", "Shell_NotifyIconA", "Shell_NotifyIconW"
]

# Extend the Windows API commands list
windows_API_commands.extend(extra_API_commands)
windows_API_commands.extend(additional_extra_commands)

# --- Suspicious Keywords ---
suspicious_keywords = [
    "admin", "administrator", "username", "user", "password", "pass", "secret", "login", "credentials", "key",
    "token", "session", "config", "configuration", "crack", "pirate", "malware", "virus", "trojan", "worm",
    "exploit", "shell", "cmd", "backdoor", "remote", "connect", "bot", "injector", "payload", "dropper",
    "obfuscate", "encrypt", "decrypt", "hacker", "hack", "malicious"
]
additional_suspicious_keywords = [
    "ransom", "ransomware", "spyware", "keylogger", "rootkit", "botnet", "intrusion", "compromise", 
    "breach", "exfiltrate", "exfiltration", "data leak", "data theft", "privilege escalation", 
    "credential dumping", "shellcode", "packer", "obfuscator", "cryptor", "malvertising", "adware", 
    "trojanized", "phishing", "phish", "attack", "overflow", "injection", "sql injection", "xss", 
    "denial of service", "dos", "ddos", "reconnaissance", "scanner", "suspicious", "danger", "infect",
    "infection", "malcode", "virus signature", "zero-day", "exploit kit", "stealer", "sleeper", "stager",
    "c2", "command and control", "cmd&control", "backdoor access", "remote access", "unauthorized", 
    "bypass", "malicious payload", "cyberattack", "cybercrime", "intruder", "intrusion detection", 
    "exploit vulnerability", "system hijack", "malicious script"
]
suspicious_keywords.extend(additional_suspicious_keywords)
suspicious_keywords = list({kw.lower() for kw in suspicious_keywords})

# Suspicious .NET keywords
suspicious_dotnet_keywords = [
    "system.reflection", "system.net", "system.diagnostics", "system.security.cryptography", "system.io",
    "system.environment", "system.appdomain", "system.threading", "system.runtime.interopservices", "system.management",
    "system.configuration", "system.web", "system.windows.forms", "system.drawing", "system.data", "system.linq",
    "system.xml", "system.serviceprocess", "system.net.mail", "system.security.principal", "system.security.permissions",
    "system.net.sockets", "system.runtime.serialization", "system.runtime.compilerservices", "system.codedom",
    "system.codedom.compiler", "system.runtime.remoting", "microsoft.csharp", "microsoft.visualbasic",
    "system.runtime.serialization.formatters.binary", "system.servicemodel", "system.collections.generic",
    "system.dynamic", "system.text.regularexpressions"
]

# --- CMD and PowerShell Command Lists ---
cmd_command_list = [cmd.lower() for cmd in [
    "assoc", "attrib", "bcdedit", "cd", "chkdsk", "cls", "copy", "del", "dir", "diskpart",
    "driverquery", "echo", "exit", "find", "findstr", "format", "help", "ipconfig", "md", "more",
    "move", "net", "netstat", "nslookup", "path", "ping", "powercfg", "rd", "reg", "regedit",
    "rename", "rmdir", "robocopy", "route", "sc", "sfc", "shutdown", "sort", "start", "systeminfo",
    "taskkill", "tasklist", "time", "timeout", "title", "tree", "type", "ver", "vol", "xcopy",
    "fc", "set", "setlocal", "endlocal", "shift", "call", "color", "comp", "date", "for", "if", "goto",
    "pushd", "popd", "chcp", "choice", "cscript", "wmic", "doskey", "where", "expand", "compact",
    "convert", "cipher", "diskshadow", "fsutil", "gpresult", "gpupdate", "lodctr", "logman",
    "makecab", "mountvol", "netcfg", "netsh", "nltest", "pathping", "perfmon", "subst", "telnet",
    "tracert", "verify", "whoami", "qwinsta", "prndrvr", "print", "clip", "hostname", "winrm",
    "eventcreate", "msg", "schtasks"
]]
powershell_command_list = [ps.lower() for ps in [
    "Get-Command", "Get-Help", "Set-ExecutionPolicy", "Get-ExecutionPolicy", "Get-Service",
    "Start-Service", "Stop-Service", "Restart-Service", "Get-Process", "Stop-Process",
    "Get-EventLog", "Clear-EventLog", "Get-WinEvent", "Get-Content", "Set-Content",
    "Add-Content", "Clear-Content", "Out-File", "Export-Csv", "Import-Csv",
    "ConvertTo-Json", "ConvertFrom-Json", "Get-Date", "Start-Sleep", "Write-Output",
    "Write-Host", "Write-Error", "New-Item", "Remove-Item", "Copy-Item", "Move-Item",
    "Test-Path", "Get-Item", "Set-Item", "Get-ChildItem", "New-ItemProperty",
    "Set-ItemProperty", "Remove-ItemProperty", "Get-ItemProperty", "Get-PSDrive",
    "New-PSDrive", "Remove-PSDrive", "Get-Alias", "Set-Alias", "Get-Module",
    "Import-Module", "Remove-Module", "Update-Module", "Find-Module", "Install-Module",
    "Uninstall-Module", "Save-Module", "Get-PSSession", "New-PSSession", "Enter-PSSession",
    "Exit-PSSession", "Remove-PSSession", "Invoke-Command", "Enable-PSRemoting",
    "Disable-PSRemoting", "Get-ComputerInfo", "Restart-Computer", "Stop-Computer",
    "Get-NetIPAddress", "New-NetIPAddress", "Remove-NetIPAddress", "Set-NetIPAddress",
    "Get-NetIPConfiguration", "Get-NetAdapter", "Enable-NetAdapter", "Disable-NetAdapter",
    "Restart-NetAdapter", "Get-NetRoute", "New-NetRoute", "Remove-NetRoute", "Set-NetRoute",
    "Get-NetFirewallRule", "New-NetFirewallRule", "Set-NetFirewallRule", "Remove-NetFirewallRule",
    "Get-NetNat", "New-NetNat", "Remove-NetNat", "Get-NetIPInterface", "Set-NetIPInterface",
    "Get-NetTCPConnection", "Get-NetUDPEndpoint", "Get-ProcessMitigation", "Set-ProcessMitigation",
    "Clear-ProcessMitigation", "Get-CimInstance", "New-CimInstance", "Remove-CimInstance",
    "Set-CimInstance", "Invoke-CimMethod", "Get-CimAssociatedInstance", "Enable-LocalUser",
    "Disable-LocalUser", "New-LocalUser", "Remove-LocalUser", "Set-LocalUser", "Get-LocalUser",
    "Add-LocalGroupMember", "Remove-LocalGroupMember", "Get-LocalGroup", "New-LocalGroup",
    "Remove-LocalGroup", "Get-LocalGroupMember", "Set-LocalGroup", "Get-WmiObject", "Set-WmiInstance",
    "Invoke-WmiMethod", "Remove-WmiObject", "ConvertFrom-CSV", "ConvertTo-CSV", "Get-Clipboard",
    "Set-Clipboard", "Clear-Clipboard", "Start-Job", "Stop-Job", "Get-Job", "Receive-Job",
    "Wait-Job", "Remove-Job", "Suspend-Job", "Resume-Job", "Export-ModuleMember", "Show-Command",
    "Start-Transcript", "Stop-Transcript", "Get-Transaction", "New-Transaction",
    "Complete-Transaction", "Undo-Transaction", "Checkpoint-Computer", "Get-EventSubscriber",
    "Register-EngineEvent", "Unregister-Event", "Wait-Event", "New-Event", "Out-GridView",
    "Measure-Object", "Sort-Object", "Group-Object", "Select-Object", "Where-Object",
    "ForEach-Object", "Format-Table", "Format-List", "Format-Wide", "Out-Host", "Out-Null",
    "Export-Clixml", "Import-Clixml", "Update-Help", "Save-Help", "Show-Help", "Add-Type",
    "Remove-TypeData", "Update-TypeData", "New-Object", "New-EventLog", "Write-EventLog",
    "Limit-EventLog", "Start-Process", "Stop-Process", "Wait-Process", "Get-Location",
    "Set-Location", "Push-Location", "Pop-Location", "Get-History", "Clear-History",
    "Invoke-History", "Get-Package", "Install-Package", "Uninstall-Package", "Find-Package",
    "Save-Package", "Update-Package", "Add-Package", "Remove-Package", "Publish-Module",
    "Save-Module", "Install-Script", "Invoke-Expression", "Test-Connection", "New-Service",
    "Set-Service", "Remove-Service", "Suspend-Service", "Resume-Service", "Get-ItemPropertyValue",
    "Set-ItemPropertyValue", "Clear-Variable", "Get-Variable", "Set-Variable", "Remove-Variable",
    "Update-FormatData", "Export-PSSession", "Import-PSSession", "New-PSSessionConfigurationFile",
    "Register-PSSessionConfiguration", "Unregister-PSSessionConfiguration", "Get-PSSessionConfiguration",
    "Save-PSSessionConfiguration", "Install-PSSessionConfiguration", "New-Workflow", "Invoke-Workflow",
    "Disable-Workflow", "Enter-PSHostProcess", "Exit-PSHostProcess", "Get-PSHostProcessInfo",
    "Get-NetTCPStatistics", "Test-NetConnection", "New-NetIPsecMainModeCryptoSet", "New-NetIPsecQuickModeCryptoSet",
    "New-NetIPsecRule", "Get-NetIPsecMainModeCryptoSet", "Set-NetIPsecMainModeCryptoSet",
    "Remove-NetIPsecMainModeCryptoSet", "New-NetIPsecPhase1AuthSet", "Get-NetIPsecPhase1AuthSet",
    "Set-NetIPsecPhase1AuthSet", "Remove-NetIPsecPhase1AuthSet", "Get-NetIPsecRule", "Set-NetIPsecRule",
    "Remove-NetIPsecRule", "Get-Credential", "ConvertTo-SecureString", "ConvertFrom-SecureString",
    "New-SelfSignedCertificate", "Get-SelfSignedCertificate", "Find-PackageProvider", "Get-PackageProvider",
    "Install-PackageProvider", "Save-PackageProvider", "Start-DscConfiguration", "Publish-DscConfiguration",
    "Test-DscConfiguration", "Get-DscConfigurationStatus", "Get-DscLocalConfigurationManager",
    "Set-DscLocalConfigurationManager", "New-Guid", "Get-Random", "Measure-Command", "ConvertFrom-String",
    "ConvertTo-String", "Join-Path", "Split-Path", "Resolve-Path", "Convert-Path"
]]

# --- Additional Extra Commands (User-Specified) ---
additional_extra_commands = [
    "RegCloseKey", "RegCreateKeyExA", "RegCreateKeyExW", "RegEnumKeyExA", "RegEnumKeyExW",
    "RegOpenKeyExA", "RegOpenKeyExW", "SHELL32.dll", "ShellExecuteA", "ShellExecuteExA",
    "ShellExecuteExW", "ShellExecuteW", "Shell_NotifyIconA", "Shell_NotifyIconW"
]

# Extend the Windows API commands list
windows_API_commands.extend(extra_API_commands)
windows_API_commands.extend(additional_extra_commands)

# --- Suspicious Keywords ---
suspicious_keywords = [
    "admin", "administrator", "username", "user", "password", "pass", "secret", "login", "credentials", "key",
    "token", "session", "config", "configuration", "crack", "pirate", "malware", "virus", "trojan", "worm",
    "exploit", "shell", "cmd", "backdoor", "remote", "connect", "bot", "injector", "payload", "dropper",
    "obfuscate", "encrypt", "decrypt", "hacker", "hack", "malicious"
]
additional_suspicious_keywords = [
    "ransom", "ransomware", "spyware", "keylogger", "rootkit", "botnet", "intrusion", "compromise", 
    "breach", "exfiltrate", "exfiltration", "data leak", "data theft", "privilege escalation", 
    "credential dumping", "shellcode", "packer", "obfuscator", "cryptor", "malvertising", "adware", 
    "trojanized", "phishing", "phish", "attack", "overflow", "injection", "sql injection", "xss", 
    "denial of service", "dos", "ddos", "reconnaissance", "scanner", "suspicious", "danger", "infect",
    "infection", "malcode", "virus signature", "zero-day", "exploit kit", "stealer", "sleeper", "stager",
    "c2", "command and control", "cmd&control", "backdoor access", "remote access", "unauthorized", 
    "bypass", "malicious payload", "cyberattack", "cybercrime", "intruder", "intrusion detection", 
    "exploit vulnerability", "system hijack", "malicious script"
]
suspicious_keywords.extend(additional_suspicious_keywords)
suspicious_keywords = list({kw.lower() for kw in suspicious_keywords})

# Suspicious .NET keywords
suspicious_dotnet_keywords = [
    "system.reflection", "system.net", "system.diagnostics", "system.security.cryptography", "system.io",
    "system.environment", "system.appdomain", "system.threading", "system.runtime.interopservices", "system.management",
    "system.configuration", "system.web", "system.windows.forms", "system.drawing", "system.data", "system.linq",
    "system.xml", "system.serviceprocess", "system.net.mail", "system.security.principal", "system.security.permissions",
    "system.net.sockets", "system.runtime.serialization", "system.runtime.compilerservices", "system.codedom",
    "system.codedom.compiler", "system.runtime.remoting", "microsoft.csharp", "microsoft.visualbasic",
    "system.runtime.serialization.formatters.binary", "system.servicemodel", "system.collections.generic",
    "system.dynamic", "system.text.regularexpressions"
]

# --- Regex Patterns ---
ip_pattern = re.compile(r'\b(?:\d{1,3}\.){3}\d{1,3}\b')  # IPv4
ipv6_pattern = re.compile(r'\b(?:[0-9a-fA-F]{1,4}:){7}[0-9a-fA-F]{1,4}\b')  # IPv6
url_pattern = re.compile(r'http[s]?://(?:[a-zA-Z0-9]|[$-_@.&+]|[!*\\(\\),])+', re.IGNORECASE)
email_pattern = re.compile(r'[a-zA-Z0-9._%+-]+@[a-zA-Z0-9.-]+\.[a-zA-Z]{2,}', re.IGNORECASE)
registry_pattern = re.compile(r'\b(?:HKCU|HKLM|HKEY_LOCAL_MACHINE|HKEY_CLASSES_ROOT|HKEY_CURRENT_USER)\\[^\s]+\b', re.IGNORECASE)
dll_pattern = re.compile(r".+\.dll$", re.IGNORECASE)
file_pattern = re.compile(r'([^\\/:*?"<>|\r\n]+)\.(exe|bat|cmd|vbs|txt|log|ini|reg|msi|sys|inf|drv|com|cpl|scr|hlp|ico|lnk)$', re.IGNORECASE)
system_path_pattern = re.compile(
    r'(?i)\b[a-z]:[\\/](?:Windows|WINNT|System32|SysWOW64|Program\s*Files(?:\s*\(x86\))?|ProgramData|WinSxS|Users|Public)(?:[\\/][^\\/:*?"<>|\r\n]*)*\b'
)

obfuscated_patterns = [
    re.compile(r'\b(?:\d{1,3}\[\.\]){3}\d{1,3}\b'),
    re.compile(r'\b(?:\d{1,3}(?:\[\.\]|\(dot\)|\s+dot\s+|\s*\.\s*)){3}\d{1,3}\b', re.IGNORECASE),
    re.compile(r'\b(?:h(?:xx|[+\-]{2}|rr)p(?:s)?)[:\-]*//(?:[a-zA-Z0-9\[\]\(\)\.-]+)(?::\d+)?(?:/[^\s]*)?\b', re.IGNORECASE),
    re.compile(r'\b(?:[a-zA-Z0-9._%+-]+)\s*(?:\[at\]|\(at\))\s*([a-zA-Z0-9.-]+)\s*(?:\[dot\]|\(dot\)|\sdot\s|\.)\s*([a-zA-Z]{2,})\b', re.IGNORECASE)
]

base64_candidate_re = re.compile(r'^(?:[A-Za-z0-9+/]{4})*(?:[A-Za-z0-9+/]{2}==|[A-Za-z0-9+/]{3}=)?$')
hex_candidate_re = re.compile(r'^[0-9A-Fa-f]+$')

# --- Output Sets for Filtered Results ---
found_patterns = {
    "WINDOWS_API_COMMANDS": set(),
    "DLLS": set(),
    "URLS": set(),
    "IPS": set(),
    "IPV6": set(),
    "EMAILS": set(),
    "WINDOWS_REGISTRY_KEYS": set(),
    "POWERSHELL_COMMANDS": set(),
    "CMD_COMMANDS": set(),
    "FILES": set(),
    "SYSTEM_PATHS": set(),
    "OBFUSCATED": set(),
    "DECODED_BASE64": set(),
    "DECODED_HEX": set(),
    "SUSPICIOUS_KEYWORDS": set(),
    "SUSPICIOUS_DOTNET": set()
}

# --- Functions ---

def shannon_entropy(s):
    """Calculate the Shannon entropy of a string."""
    if not s:
        return 0
    freq = {}
    for char in s:
        freq[char] = freq.get(char, 0) + 1
    entropy = 0.0
    for count in freq.values():
        p = count / len(s)
        entropy -= p * log2(p)
    return entropy

def compute_file_entropy(filename):
    """Compute the Shannon entropy for the entire file content (bytes)."""
    with open(filename, "rb") as f:
        data = f.read()
    if not data:
        return 0
    freq = {}
    for byte in data:
        freq[byte] = freq.get(byte, 0) + 1
    entropy = 0.0
    for count in freq.values():
        p = count / len(data)
        entropy -= p * log2(p)
    return entropy

def extract_strings(filename, min_length=4):
    """
    Extract printable ASCII strings from a binary file.
    Returns a set of unique strings of at least min_length characters.
    """
    result = set()
    current_string = ""
    with open(filename, 'rb') as f:
        while True:
            byte = f.read(1)
            if not byte:
                break
            if 32 <= byte[0] <= 126:
                current_string += byte.decode('ascii', 'ignore')
            else:
                if len(current_string) >= min_length:
                    result.add(current_string.strip())
                current_string = ""
    if len(current_string) >= min_length:
        result.add(current_string.strip())
    return result

def is_mostly_printable(s, threshold=0.9):
    """Check if a string is mostly printable."""
    if not s:
        return False
    printable = sum(1 for c in s if 32 <= ord(c) <= 126)
    return (printable / len(s)) >= threshold

def try_base64_decode(s):
    """Attempt to decode a Base64-encoded string."""
    if len(s) > 8 and base64_candidate_re.match(s):
        try:
            decoded_bytes = base64.b64decode(s, validate=True)
            decoded = decoded_bytes.decode('utf-8', errors='replace')
            if is_mostly_printable(decoded) and decoded != s:
                return decoded
        except Exception:
            pass
    return None

def try_hex_decode(s):
    """Attempt to decode a hex-encoded string."""
    if len(s) > 8 and len(s) % 2 == 0 and hex_candidate_re.match(s):
        try:
            decoded_bytes = bytes.fromhex(s)
            decoded = decoded_bytes.decode('utf-8', errors='replace')
            if is_mostly_printable(decoded) and decoded != s:
                return decoded
        except Exception:
            pass
    return None

def detect_patterns(strings):
    """
    Detect patterns in extracted strings and fill the found_patterns dictionary.
    This function categorizes strings based on known commands, DLLs, registry paths, URLs,
    IPs, obfuscated patterns, and suspicious keywords.
    API command strings are not added to the suspicious keywords category.
    """
    for line in strings:
        lower_line = line.lower()
        # Check for Windows API commands
        if lower_line in [cmd.lower() for cmd in windows_API_commands]:
            found_patterns["WINDOWS_API_COMMANDS"].add(line)
        # Check for CMD commands
        elif lower_line in cmd_command_list:
            found_patterns["CMD_COMMANDS"].add(line)
        # Check for PowerShell commands
        elif lower_line in powershell_command_list:
            found_patterns["POWERSHELL_COMMANDS"].add(line)
        elif registry_pattern.match(line):
            found_patterns["WINDOWS_REGISTRY_KEYS"].add(line)
        elif system_path_pattern.match(line):
            found_patterns["SYSTEM_PATHS"].add(line)
        elif dll_pattern.match(line):
            found_patterns["DLLS"].add(line)
        elif url_pattern.match(line):
            found_patterns["URLS"].add(line)
        elif ip_pattern.match(line):
            found_patterns["IPS"].add(line)
        elif ipv6_pattern.match(line):
            found_patterns["IPV6"].add(line)
        elif email_pattern.match(line):
            found_patterns["EMAILS"].add(line)
        elif file_pattern.match(line):
            found_patterns["FILES"].add(line)
        
        # Check obfuscated patterns
        for pattern in obfuscated_patterns:
            if pattern.match(line):
                found_patterns["OBFUSCATED"].add(line)
        
        # Only add to suspicious keywords if the string is NOT already recognized as a command
        if (lower_line not in [cmd.lower() for cmd in windows_API_commands] and
            lower_line not in cmd_command_list and
            lower_line not in powershell_command_list):
            for keyword in suspicious_keywords:
                if keyword in lower_line:
                    found_patterns["SUSPICIOUS_KEYWORDS"].add(line)
                    break
        
        # Check for suspicious .NET keywords
        for dotnet_kw in suspicious_dotnet_keywords:
            if dotnet_kw in lower_line:
                found_patterns["SUSPICIOUS_DOTNET"].add(line)
                break
        
        # Attempt Base64 decoding
        base64_decoded = try_base64_decode(line)
        if base64_decoded:
            found_patterns["DECODED_BASE64"].add(f"{line} -> {base64_decoded}")
        
        # Attempt Hex decoding
        hex_decoded = try_hex_decode(line)
        if hex_decoded:
            found_patterns["DECODED_HEX"].add(f"{line} -> {hex_decoded}")

def generate_ai_prompt(found_patterns, file_entropy, obfuscated=False):
    """
    Generate an AI analysis prompt text based on filtered patterns.
    """
    header = ""
    if obfuscated:
        header += "maybe obfuscated or packed file\n\n"
    header += f"File Entropy: {file_entropy:.2f}\n\n"
    prompt_lines = [header]
    prompt_lines.append("Please analyze the following extracted strings from a suspicious binary file. "
                        "For each category, explain the functions and potential implications. "
                        "Enrich any found URLs with context (if available) and provide a summary of the behavior and functionality based on these strings.\n")
    for category in sorted(found_patterns.keys()):
        items = sorted(found_patterns[category])
        if items:
            prompt_lines.append(f"### {category.replace('_', ' ')}:")
            for item in items:
                prompt_lines.append(f"- {item}")
            prompt_lines.append("")  # Blank line after category
    prompt_lines.append("Based on the above, please provide a comprehensive analysis of the malware's behavior and functionality.")
    return "\n".join(prompt_lines)

def generate_normal_output(found_patterns, file_entropy, obfuscated=False):
    """
    Generate a normal output text with filtered strings, sorted by type.
    """
    output_lines = []
    header = f"File Entropy: {file_entropy:.2f}\n"
    if obfuscated:
        header = "maybe obfuscated or packed file\n" + header
    output_lines.append(header)
    for category in sorted(found_patterns.keys()):
        items = sorted(found_patterns[category])
        if items:
            output_lines.append(f"### {category.replace('_', ' ')}:")
            for item in items:
                output_lines.append(f"- {item}")
            output_lines.append("")  # Blank line after category
    return "\n".join(output_lines)

def main():
    try:
        filename = input("Path to file: ").strip()
        if not os.path.exists(filename):
            raise FileNotFoundError("Error: File not found.")

        # Compute file entropy
        file_entropy = compute_file_entropy(filename)
        # Extract printable strings
        file_strings = extract_strings(filename)
        # Determine default output filename
        base_name = os.path.splitext(os.path.basename(filename))[0]
        default_output_filename = f"{base_name}_strings.txt"

        # Option 1: Unfiltered output (all extracted strings)
        all_strings_choice = input("Output all extracted strings (unfiltered)? (yes/no): ").strip().lower()
        if all_strings_choice in ['yes', 'y']:
            output_filename = input(f"Output file (default: {default_output_filename}): ").strip() or default_output_filename
            with open(output_filename, "w", encoding="utf-8") as out_file:
                for s in sorted(file_strings):
                    out_file.write(s + "\n")
            print(f"All extracted strings saved in {output_filename}!")
        else:
            # Option 2: Filtered output (grouped by types)
            detect_patterns(file_strings)
            # Count useful items from key categories
            useful_count = (len(found_patterns["WINDOWS_API_COMMANDS"]) +
                            len(found_patterns["DLLS"]) +
                            len(found_patterns["CMD_COMMANDS"]) +
                            len(found_patterns["POWERSHELL_COMMANDS"]))
            obfuscated_flag = (useful_count < MIN_USEFUL_COUNT and file_entropy > ENTROPY_THRESHOLD)
            
            ai_prompt_choice = input("Create AI prompt for filtered output? (yes/no): ").strip().lower()
            output_filename = input(f"Output file (default: {default_output_filename}): ").strip() or default_output_filename
            if ai_prompt_choice in ['yes', 'y']:
                prompt_text = generate_ai_prompt(found_patterns, file_entropy, obfuscated_flag)
                with open(output_filename, "w", encoding="utf-8") as out_file:
                    out_file.write(prompt_text)
                print(f"AI prompt saved in {output_filename}!")
            else:
                normal_text = generate_normal_output(found_patterns, file_entropy, obfuscated_flag)
                with open(output_filename, "w", encoding="utf-8") as out_file:
                    out_file.write(normal_text)
                print(f"Filtered results saved in {output_filename}!")
    except FileNotFoundError as fnf_err:
        print(fnf_err)
    except Exception as e:
        print(f"An unexpected error occurred: {e}")

if __name__ == "__main__":
    main()
