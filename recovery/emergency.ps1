# Блокировщик сайтов — АВАРИЙНОЕ ВОССТАНОВЛЕНИЕ.
# Для случая, когда программа сломалась и блокировка не снимается обычным путём (пароль утерян, служба не отвечает).
# Делает: возвращает администраторам доступ к папкам и ключу службы, останавливает и удаляет службу, убирает автозапуск,
# удаляет политики блокировки браузеров у всех учёток-целей (в т.ч. подгружает их куст реестра), снимает правила
# брандмауэра, удаляет ярлыки и файлы программы. Настройки (%ProgramData%\SiteBlocker) НЕ удаляет.
# Служба защищена от администратора, поэтому при отказе sc.exe служба отключается/удаляется через реестр.
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
if (-not $Yes) { $ans=Read-Host 'Продолжить? [д/Н]'; if ($ans -notmatch '^(д|да|y|yes)$') { Say 'Отменено.'; exit 1 } }

# Пути политик Chromium (подпути под Software\Policies) и Firefox.
$chromium=@('Microsoft\Edge','Google\Chrome','Chromium','Vivaldi','BraveSoftware\Brave','YandexBrowser','Opera Software\Opera')
$loaded=@{}
function Resolve-UserHive([string]$sid) {
    if (Test-Path ("Registry::HKEY_USERS\$sid")) { return "Registry::HKEY_USERS\$sid" }
    if ($loaded.ContainsKey($sid)) { return "Registry::HKEY_USERS\$($loaded[$sid])" }
    $prof=(Get-ItemProperty ("HKLM:\SOFTWARE\Microsoft\Windows NT\CurrentVersion\ProfileList\$sid") -ErrorAction SilentlyContinue).ProfileImagePath
    if ($prof -and (Test-Path (Join-Path $prof 'NTUSER.DAT'))) {
        $tag='SB_'+$sid
        & reg.exe load ("HKU\$tag") (Join-Path $prof 'NTUSER.DAT') | Out-Null
        if ($LASTEXITCODE -eq 0) { $loaded[$sid]=$tag; return "Registry::HKEY_USERS\$tag" }
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

# 0. Доступ администраторам к папкам программы и данных.
Say '0) Права на папки…'
foreach ($d in @($InstallDir,$DataDir)) { if (Test-Path $d) { & icacls.exe $d /setowner '*S-1-5-32-544' /T /C /Q 2>$null | Out-Null; & icacls.exe $d /grant '*S-1-5-32-544:(OI)(CI)F' /T /C /Q 2>$null | Out-Null; Say "  доступ возвращён: $d" } }

# 1. Служба.
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
foreach ($sid in @($loaded.Keys)) { [gc]::Collect(); & reg.exe unload ("HKU\$($loaded[$sid])") | Out-Null }

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
