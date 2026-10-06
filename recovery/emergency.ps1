# Блокировщик сайтов — АВАРИЙНОЕ ВОССТАНОВЛЕНИЕ.
# Для случая, когда программа сломалась и блокировка не снимается обычным путём (пароль утерян, служба не отвечает).
# ВАЖНО: скрипт НЕ использует reg.exe / regedit / .reg — поэтому работает даже при включённом запрете редактирования
# реестра (DisableRegistryTools). Всё делается через провайдер реестра PowerShell и Win32 API (RegLoadKey), которые
# от этой политики не зависят.
# Делает: возвращает администраторам доступ к папкам и ключу службы, останавливает и удаляет службу, убирает автозапуск,
# удаляет политики блокировки браузеров у всех учёток-целей (в т.ч. подгружает их куст реестра через API), снимает
# правила брандмауэра, удаляет ярлыки и файлы программы. Настройки (%ProgramData%\SiteBlocker) НЕ удаляет.
# Служба защищена от администратора, поэтому при отказе sc.exe служба отключается/удаляется через провайдер реестра.
# Нужны права администратора. Если блокировка «висит» — запускайте в БЕЗОПАСНОМ РЕЖИМЕ (см. README-восстановление.txt).
param([switch]$Yes, [switch]$NoPause)

$ErrorActionPreference='Continue'
$ServiceName='SiteBlocker'
$InstallDir =Join-Path $env:ProgramFiles 'SiteBlocker'
$DataDir    =Join-Path $env:ProgramData 'SiteBlocker'

function Test-Admin { (New-Object Security.Principal.WindowsPrincipal([Security.Principal.WindowsIdentity]::GetCurrent())).IsInRole([Security.Principal.WindowsBuiltInRole]::Administrator) }
if (-not (Test-Admin)) {
    $a=@('-NoProfile','-ExecutionPolicy','Bypass','-File',('"'+$PSCommandPath+'"')); if($Yes){$a+='-Yes'}
    Start-Process powershell.exe -Verb RunAs -ArgumentList $a; exit
}
function Say($t,$c='Gray'){ Write-Host $t -ForegroundColor $c }

Say 'Блокировщик сайтов — аварийное восстановление' 'Cyan'
Say 'Будут удалены служба, автозапуск, файлы и политики блокировки браузеров. Настройки сохранятся.'
Say 'Скрипт не использует regedit/reg.exe и работает при запрете редактирования реестра.'
if (-not $Yes) { $ans=Read-Host 'Продолжить? [д/Н]'; if ($ans -notmatch '^(д|да|y|yes)$') { Say 'Отменено.'; exit 1 } }

# --- Win32 API для загрузки/выгрузки кустов реестра без reg.exe (не зависит от DisableRegistryTools) ---
$native = @'
using System;
using System.Runtime.InteropServices;
public static class NativeReg {
    [DllImport("advapi32.dll", CharSet=CharSet.Unicode, SetLastError=true)]
    public static extern int RegLoadKeyW(UIntPtr hKey, string lpSubKey, string lpFile);
    [DllImport("advapi32.dll", CharSet=CharSet.Unicode, SetLastError=true)]
    public static extern int RegUnLoadKeyW(UIntPtr hKey, string lpSubKey);
    [DllImport("advapi32.dll", SetLastError=true)]
    static extern bool OpenProcessToken(IntPtr h, uint acc, out IntPtr tok);
    [DllImport("advapi32.dll", CharSet=CharSet.Unicode, SetLastError=true)]
    static extern bool LookupPrivilegeValue(string host, string name, out long luid);
    [DllImport("advapi32.dll", SetLastError=true)]
    static extern bool AdjustTokenPrivileges(IntPtr tok, bool dis, ref TOKEN_PRIVILEGES np, uint len, IntPtr prev, IntPtr plen);
    [DllImport("kernel32.dll")] static extern IntPtr GetCurrentProcess();
    [StructLayout(LayoutKind.Sequential)] struct TOKEN_PRIVILEGES { public uint Count; public long Luid; public uint Attributes; }
    public static readonly UIntPtr HKEY_USERS = unchecked((UIntPtr)0x80000003);
    public static bool EnablePriv(string name) {
        IntPtr tok;
        if (!OpenProcessToken(GetCurrentProcess(), 0x20|0x8, out tok)) return false;
        long luid; if (!LookupPrivilegeValue(null, name, out luid)) return false;
        var tp = new TOKEN_PRIVILEGES { Count=1, Luid=luid, Attributes=0x2 };
        return AdjustTokenPrivileges(tok, false, ref tp, 0, IntPtr.Zero, IntPtr.Zero);
    }
}
'@
try { Add-Type -TypeDefinition $native -ErrorAction Stop } catch { Say ('  не удалось подготовить API реестра: '+$_.Exception.Message) 'Yellow' }
try { [NativeReg]::EnablePriv('SeBackupPrivilege') | Out-Null; [NativeReg]::EnablePriv('SeRestorePrivilege') | Out-Null } catch {}

$chromium=@('Microsoft\Edge','Google\Chrome','Chromium','Vivaldi','BraveSoftware\Brave','YandexBrowser','Opera Software\Opera')
$loaded=@{}
function Resolve-UserHive([string]$sid) {
    if (Test-Path ("Registry::HKEY_USERS\$sid")) { return "Registry::HKEY_USERS\$sid" }
    if ($loaded.ContainsKey($sid)) { return "Registry::HKEY_USERS\$($loaded[$sid])" }
    $prof=(Get-ItemProperty ("HKLM:\SOFTWARE\Microsoft\Windows NT\CurrentVersion\ProfileList\$sid") -ErrorAction SilentlyContinue).ProfileImagePath
    if ($prof -and (Test-Path (Join-Path $prof 'NTUSER.DAT'))) {
        $tag='SB_'+$sid
        try { $rc=[NativeReg]::RegLoadKeyW([NativeReg]::HKEY_USERS, $tag, (Join-Path $prof 'NTUSER.DAT')) } catch { $rc=-1 }
        if ($rc -eq 0) { $loaded[$sid]=$tag; return "Registry::HKEY_USERS\$tag" }
    }
    return $null
}
function Clear-PoliciesForHive([string]$hiveRoot) {
    foreach ($v in $chromium) {
        $base="$hiveRoot\Software\Policies\$v"
        Remove-Item -Path "$base\URLBlocklist" -Recurse -Force -ErrorAction SilentlyContinue
        Remove-Item -Path "$base\IncognitoModeUrlBlocklist" -Recurse -Force -ErrorAction SilentlyContinue
        if (Test-Path $base) {
            Remove-ItemProperty -Path $base -Name 'DnsOverHttpsMode' -ErrorAction SilentlyContinue
            Remove-ItemProperty -Path $base -Name 'BuiltInDnsClientEnabled' -ErrorAction SilentlyContinue
        }
    }
    $ff="$hiveRoot\Software\Policies\Mozilla\Firefox"
    Remove-Item -Path "$ff\WebsiteFilter" -Recurse -Force -ErrorAction SilentlyContinue
    Remove-Item -Path "$ff\DNSOverHTTPS" -Recurse -Force -ErrorAction SilentlyContinue
}

# 0. Доступ администраторам к папкам программы и данных (icacls запретом реестра не блокируется).
Say '0) Права на папки…'
foreach ($d in @($InstallDir,$DataDir)) { if (Test-Path $d) { & icacls.exe $d /setowner '*S-1-5-32-544' /T /C /Q 2>$null | Out-Null; & icacls.exe $d /grant '*S-1-5-32-544:(OI)(CI)F' /T /C /Q 2>$null | Out-Null; Say "  доступ возвращён: $d" } }

# 1. Служба (sc.exe разрешён; ключ при отказе чистим через провайдер реестра PowerShell).
Say '1) Служба…'
& sc.exe stop $ServiceName 2>$null | Out-Null; Start-Sleep 2
Get-Process -Name 'SiteBlocker' -ErrorAction SilentlyContinue | Stop-Process -Force -ErrorAction SilentlyContinue
& sc.exe delete $ServiceName 2>$null | Out-Null
$svcKey="HKLM:\SYSTEM\CurrentControlSet\Services\$ServiceName"
if (Test-Path $svcKey) {
    try { $acl=Get-Acl $svcKey; $adm=New-Object Security.Principal.SecurityIdentifier('S-1-5-32-544'); $acl.AddAccessRule((New-Object Security.AccessControl.RegistryAccessRule($adm,'FullControl','ContainerInherit','None','Allow'))); Set-Acl $svcKey $acl } catch {}
    Set-ItemProperty -Path $svcKey -Name Start -Value 4 -ErrorAction SilentlyContinue
    Remove-Item -Path $svcKey -Recurse -Force -ErrorAction SilentlyContinue
    if (Test-Path $svcKey) { Say '  служба отключена (удалится после перезагрузки).' 'Yellow' } else { Say '  служба удалена.' }
}
Remove-ItemProperty -Path 'HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\Run' -Name 'SiteBlocker' -ErrorAction SilentlyContinue

# 2. Политики блокировки у всех целей.
Say '2) Политики блокировки браузеров…'
$targets=@()
$mj=Join-Path $DataDir 'machine.json'
if (Test-Path $mj) { try { $m=Get-Content -Raw $mj | ConvertFrom-Json; if ($m.ownerSid){$targets+=$m.ownerSid}; if ($m.targetSids){$targets+=$m.targetSids} } catch {} }
if ($targets.Count -eq 0) { $targets = Get-ChildItem 'HKLM:\SOFTWARE\Microsoft\Windows NT\CurrentVersion\ProfileList' | ForEach-Object { $_.PSChildName } | Where-Object { $_ -like 'S-1-5-21-*' } }
$targets = $targets | Select-Object -Unique
foreach ($sid in $targets) {
    $h=Resolve-UserHive $sid
    if ($h) { Clear-PoliciesForHive $h; Say "  очищено для $sid" } else { Say "  куст недоступен: $sid" 'Yellow' }
}
foreach ($sid in @($loaded.Keys)) { [gc]::Collect(); try { [NativeReg]::RegUnLoadKeyW([NativeReg]::HKEY_USERS, $loaded[$sid]) | Out-Null } catch {} }

# 3. Брандмауэр.
Say '3) Правила брандмауэра…'
try { Remove-NetFirewallRule -Group 'SiteBlocker' -ErrorAction SilentlyContinue } catch {}

# 4. Ярлыки, «Приложения», файлы. Данные НЕ трогаем.
Say '4) Файлы программы…'
Remove-Item -Path (Join-Path $env:ProgramData 'Microsoft\Windows\Start Menu\Programs\Блокировщик сайтов') -Recurse -Force -ErrorAction SilentlyContinue
Remove-Item -Path 'HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\Uninstall\SiteBlocker' -Recurse -Force -ErrorAction SilentlyContinue
Set-Location $env:TEMP
Remove-Item -Path $InstallDir -Recurse -Force -ErrorAction SilentlyContinue
if (Test-Path $InstallDir) { Start-Process cmd.exe -ArgumentList ('/c ping -n 4 127.0.0.1 >nul & rd /s /q "'+$InstallDir+'"') -WindowStyle Hidden }

Say ''
Say 'Готово. Блокировщик отключён и удалён, политики блокировки сняты. Перезагрузитесь в обычном режиме.' 'Green'
Say "Настройки сохранены в $DataDir (удалите папку вручную, если не нужны)."
if (-not $NoPause) { Read-Host 'Нажмите Enter, чтобы закрыть окно' | Out-Null }
