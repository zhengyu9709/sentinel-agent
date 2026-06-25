; --- 网络哨兵安全助手 Inno Setup 打包脚本 ---
[Setup]
AppName=网络哨兵安全助手
AppVersion=1.0.3
AppPublisher=网络安全准入部
DefaultDirName={commonpf}\CyberSentinelAgent
DefaultGroupName=网络哨兵安全助手
; 这是最后生成的安装包文件名
OutputBaseFilename=Sentinel-Agent-Setup
Compression=lzma
SolidCompression=yes
; 强制定向为管理员权限运行，以写入注册表和 Program Files
PrivilegesRequired=admin
DisableProgramGroupPage=yes
DisableReadyPage=yes

[Files]
; 指向你刚刚编译好的 exe
Source: "sentinel-agent.exe"; DestDir: "{app}"; Flags: ignoreversion

[Registry]
; 写入注册表，实现全员全静默开机自启
Root: HKLM; Subkey: "Software\Microsoft\Windows\CurrentVersion\Run"; ValueType: string; ValueName: "CyberSentinelAgent"; ValueData: """{app}\sentinel-agent.exe"""; Flags: uninsdeletevalue

[Run]
; 安装完成后，静默拉起程序
Filename: "{app}\sentinel-agent.exe"; Flags: nowait postinstall runhidden; Description: "启动网络哨兵安全助手"

[UninstallRun]
; 卸载时强杀后台进程
Filename: "taskkill"; Parameters: "/f /im sentinel-agent.exe"; Flags: runhidden; RunOnceId: "KillSentinelAgent"

[Code]
// 【核心机制】安装前置准备阶段，强杀可能正在运行的老版本进程，防止覆盖安装失败
function InitializeSetup(): Boolean;
var
  ResultCode: Integer;
begin
  Exec('taskkill.exe', '/f /im sentinel-agent.exe', '', SW_HIDE, ewWaitUntilTerminated, ResultCode);
  Result := True;
end;