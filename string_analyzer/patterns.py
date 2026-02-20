"""
Predefined pattern lists and compiled regexes for string analysis.
Single source of truth — no duplication.
"""

import re
from typing import Dict, FrozenSet, List, Pattern

# --- Configuration ---
MIN_USEFUL_COUNT = 10
ENTROPY_THRESHOLD = 5.0

# --- Windows API (base + extra + shell/registry) — built once ---
_WINDOWS_API_BASE = [
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
    "SetHandleInformation", "DuplicateHandle", "GetStdHandle", "SetStdHandle",
    "IsDebuggerPresent", "DebugBreak", "OutputDebugString", "ContinueDebugEvent", "WaitForDebugEvent",
    "SetThreadContext", "GetThreadContext", "ReadProcessMemory", "WriteProcessMemory", "CreateRemoteThread",
    "DebugActiveProcess", "GetLastError", "SetLastError", "FormatMessage",
    "Sleep", "GetTickCount", "QueryPerformanceCounter", "QueryPerformanceFrequency", "GetCurrentThreadId",
    "GetCurrentProcessId", "SetUnhandledExceptionFilter", "IsProcessorFeaturePresent", "GetSystemTime", "SetSystemTime",
    "GetLocalTime", "SetLocalTime", "GetSystemTimeAdjustment", "GetSystemVersion", "GetSystemDirectory",
    "GetWindowsDirectory", "GetDriveType", "GetSystemInfo", "SystemParametersInfo", "GetUserName",
    "GetComputerName", "GetVersionEx", "GetPrivateProfileString", "WritePrivateProfileString",
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
    "PlgBlt", "SetDIBitsToDevice", "GetSystemPaletteEntries", "SetDIBColorTable",
    "RealizePalette", "SetPaletteEntries", "GetNearestColor", "SetColorAdjustment", "GetColorAdjustment",
    "EnumDisplayDevices", "EnumDisplayMonitors", "GetMonitorInfo", "GetWindowDC",
    "SwapBuffers", "wglCreateContext", "wglDeleteContext", "wglMakeCurrent", "wglShareLists", "wglGetCurrentContext",
    "wglGetCurrentDC", "wglChoosePixelFormat", "wglDescribePixelFormat", "wglSetPixelFormat", "wglSwapBuffers",
    "ChoosePixelFormat", "DescribePixelFormat", "SetPixelFormat", "EnumDisplaySettings", "ChangeDisplaySettings",
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
    "GetModuleInformation", "VirtualAllocEx", "VirtualFreeEx", "Module32First",
    "Module32Next",
]

_EXTRA_API = [
    "NetShareAdd", "NetShareDel", "NetShareEnum", "NetUserAdd", "NetUserDel", "NetUserEnum",
    "NetLocalGroupAdd", "NetLocalGroupDel", "NetLocalGroupEnum", "NetGroupAdd", "NetGroupDel",
    "NetGroupEnum", "NetFileEnum", "NetFileClose", "NetSessionEnum", "NetSessionDel",
    "NetStatisticsGet", "NetServerEnum", "NetServerGetInfo", "NetServerSetInfo", "NetRemoteTOD",
    "NetWkstaGetInfo", "NetWkstaSetInfo",
    "SHGetDesktopFolder", "SHGetSpecialFolderPath", "SHGetPathFromIDList", "SHAppBarMessage",
    "SHGetMalloc", "SHGetFileInfo", "SHCreateDirectoryEx", "SHChangeNotify", "SHUpdateImage",
    "SHCreateShellItem",
    "ImageList_GetIconSize", "ImageList_SetIconSize", "ImageList_AddMasked", "ImageList_DrawEx",
    "InternetOpenUrl", "InternetGetConnectedState", "InternetQueryOption", "InternetSetCookie",
    "InternetGetCookie", "InternetCrackUrl", "InternetCombineUrl",
    "CryptCreateHash", "CryptHashData", "CryptSignHash", "CryptVerifySignature", "CryptDestroyHash",
    "CryptDuplicateHash", "CryptGetHashParam", "CryptSetHashParam",
    "LoadUserProfile", "UnloadUserProfile", "GetAllUsersProfileDirectory",
    "EnumDeviceDrivers", "GetDeviceDriverFileName", "GetDeviceDriverBaseName",
    "NtCreateFile", "NtOpenFile", "NtQueryInformationFile", "NtSetInformationFile",
    "NtReadFile", "NtWriteFile", "NtClose", "NtQuerySystemInformation",
    "PowerSetRequest", "PowerClearRequest", "PowerCreateRequest",
    "AuditSetSystemPolicy", "AuditQuerySystemPolicy", "SetServiceObjectSecurity",
    "QueryServiceObjectSecurity", "GetSidIdentifierAuthority", "ConvertSidToStringSid",
    "SetupDiGetClassDescription", "SetupDiGetDeviceProperty", "SetupDiSetDeviceProperty",
    "SetupDiEnumDeviceInterfacesEx",
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
    "SwitchToFiber", "DeleteFiber", "GetFiberData", "SetFiberData", "ConvertThreadToFiber",
    "RegCloseKey", "RegCreateKeyExA", "RegCreateKeyExW", "RegEnumKeyExA", "RegEnumKeyExW",
    "RegOpenKeyExA", "RegOpenKeyExW", "ShellExecuteA", "ShellExecuteExA",
    "ShellExecuteExW", "ShellExecuteW", "Shell_NotifyIconA", "Shell_NotifyIconW",
]

WINDOWS_API_COMMANDS: List[str] = _WINDOWS_API_BASE + _EXTRA_API

# --- Suspicious keywords (single definition) ---
_SUSPICIOUS_BASE = [
    "admin", "administrator", "username", "user", "password", "pass", "secret", "login", "credentials", "key",
    "token", "session", "config", "configuration", "crack", "pirate", "malware", "virus", "trojan", "worm",
    "exploit", "shell", "cmd", "backdoor", "remote", "connect", "bot", "injector", "payload", "dropper",
    "obfuscate", "encrypt", "decrypt", "hacker", "hack", "malicious",
]
_SUSPICIOUS_EXTRA = [
    "ransom", "ransomware", "spyware", "keylogger", "rootkit", "botnet", "intrusion", "compromise",
    "breach", "exfiltrate", "exfiltration", "data leak", "data theft", "privilege escalation",
    "credential dumping", "shellcode", "packer", "obfuscator", "cryptor", "malvertising", "adware",
    "trojanized", "phishing", "phish", "attack", "overflow", "injection", "sql injection", "xss",
    "denial of service", "dos", "ddos", "reconnaissance", "scanner", "suspicious", "danger", "infect",
    "infection", "malcode", "virus signature", "zero-day", "exploit kit", "stealer", "sleeper", "stager",
    "c2", "command and control", "cmd&control", "backdoor access", "remote access", "unauthorized",
    "bypass", "malicious payload", "cyberattack", "cybercrime", "intruder", "intrusion detection",
    "exploit vulnerability", "system hijack", "malicious script",
]
SUSPICIOUS_KEYWORDS: FrozenSet[str] = frozenset(
    (kw.lower() for kw in _SUSPICIOUS_BASE + _SUSPICIOUS_EXTRA)
)

SUSPICIOUS_DOTNET_KEYWORDS: List[str] = [
    "system.reflection", "system.net", "system.diagnostics", "system.security.cryptography", "system.io",
    "system.environment", "system.appdomain", "system.threading", "system.runtime.interopservices", "system.management",
    "system.configuration", "system.web", "system.windows.forms", "system.drawing", "system.data", "system.linq",
    "system.xml", "system.serviceprocess", "system.net.mail", "system.security.principal", "system.security.permissions",
    "system.net.sockets", "system.runtime.serialization", "system.runtime.compilerservices", "system.codedom",
    "system.codedom.compiler", "system.runtime.remoting", "microsoft.csharp", "microsoft.visualbasic",
    "system.runtime.serialization.formatters.binary", "system.servicemodel", "system.collections.generic",
    "system.dynamic", "system.text.regularexpressions",
]

# --- CMD and PowerShell (lowercased for lookup) ---
CMD_COMMAND_LIST: FrozenSet[str] = frozenset(cmd.lower() for cmd in [
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
    "eventcreate", "msg", "schtasks",
])

POWERSHELL_COMMAND_LIST: FrozenSet[str] = frozenset(ps.lower() for ps in [
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
    "Install-Script", "Invoke-Expression", "Test-Connection", "New-Service",
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
    "ConvertTo-String", "Join-Path", "Split-Path", "Resolve-Path", "Convert-Path",
])

# --- Regex patterns ---
IP_PATTERN: Pattern[str] = re.compile(r'\b(?:\d{1,3}\.){3}\d{1,3}\b')
IPV6_PATTERN: Pattern[str] = re.compile(
    r'\b(?:[0-9a-fA-F]{1,4}:){7}[0-9a-fA-F]{1,4}\b'
)
URL_PATTERN: Pattern[str] = re.compile(
    r'http[s]?://(?:[a-zA-Z0-9]|[$-_@.&+]|[!*\\(\\),])+', re.IGNORECASE
)
EMAIL_PATTERN: Pattern[str] = re.compile(
    r'[a-zA-Z0-9._%+-]+@[a-zA-Z0-9.-]+\.[a-zA-Z]{2,}', re.IGNORECASE
)
REGISTRY_PATTERN: Pattern[str] = re.compile(
    r'\b(?:HKCU|HKLM|HKEY_LOCAL_MACHINE|HKEY_CLASSES_ROOT|HKEY_CURRENT_USER)\\[^\s]+\b',
    re.IGNORECASE,
)
DLL_PATTERN: Pattern[str] = re.compile(r".+\.dll$", re.IGNORECASE)
FILE_PATTERN: Pattern[str] = re.compile(
    r'([^\\/:*?"<>|\r\n]+)\.(exe|bat|cmd|vbs|txt|log|ini|reg|msi|sys|inf|drv|com|cpl|scr|hlp|ico|lnk)$',
    re.IGNORECASE,
)
SYSTEM_PATH_PATTERN: Pattern[str] = re.compile(
    r'(?i)\b[a-z]:[\\/](?:Windows|WINNT|System32|SysWOW64|Program\s*Files(?:\s*\(x86\))?|ProgramData|WinSxS|Users|Public)(?:[\\/][^\\/:*?"<>|\r\n]*)*\b'
)

OBFUSCATED_PATTERNS: List[Pattern[str]] = [
    re.compile(r'\b(?:\d{1,3}\[\.\]){3}\d{1,3}\b'),
    re.compile(
        r'\b(?:\d{1,3}(?:\[\.\]|\(dot\)|\s+dot\s+|\s*\.\s*)){3}\d{1,3}\b',
        re.IGNORECASE,
    ),
    re.compile(
        r'\b(?:h(?:xx|[+\-]{2}|rr)p(?:s)?)[:\-]*//(?:[a-zA-Z0-9\[\]\(\)\.-]+)(?::\d+)?(?:/[^\s]*)?\b',
        re.IGNORECASE,
    ),
    re.compile(
        r'\b(?:[a-zA-Z0-9._%+-]+)\s*(?:\[at\]|\(at\))\s*([a-zA-Z0-9.-]+)\s*(?:\[dot\]|\(dot\)|\sdot\s|\.)\s*([a-zA-Z]{2,})\b',
        re.IGNORECASE,
    ),
]

BASE64_CANDIDATE_RE: Pattern[str] = re.compile(
    r'^(?:[A-Za-z0-9+/]{4})*(?:[A-Za-z0-9+/]{2}==|[A-Za-z0-9+/]{3}=)?$'
)
HEX_CANDIDATE_RE: Pattern[str] = re.compile(r'^[0-9A-Fa-f]+$')

# Category keys for found_patterns
PATTERN_CATEGORIES: List[str] = [
    "WINDOWS_API_COMMANDS",
    "DLLS",
    "URLS",
    "IPS",
    "IPV6",
    "EMAILS",
    "WINDOWS_REGISTRY_KEYS",
    "POWERSHELL_COMMANDS",
    "CMD_COMMANDS",
    "FILES",
    "SYSTEM_PATHS",
    "OBFUSCATED",
    "DECODED_BASE64",
    "DECODED_HEX",
    "SUSPICIOUS_KEYWORDS",
    "SUSPICIOUS_DOTNET",
]


def get_empty_found_patterns() -> Dict[str, set]:
    """Return a fresh dict of category -> set for pattern detection (no shared state)."""
    return {cat: set() for cat in PATTERN_CATEGORIES}
