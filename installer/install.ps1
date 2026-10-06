# Блокировщик сайтов — установка и обновление (Windows 10/11 x64).
# Запускайте через «Установить.cmd» (он сам попросит права администратора).
# Обновление поверх защищённой версии возможно только после «Разрешить удаление/обновление» в окне программы
# (ввод пароля; разрешение действует 15 минут) — установщик получает одноразовое разрешение у службы.
param([switch]$NoPause)

$ErrorActionPreference = 'Stop'
$Version     = '1.0.1'
$ServiceName = 'SiteBlocker'
$DisplayName = 'Блокировщик сайтов'
$InstallDir  = Join-Path $env:ProgramFiles 'SiteBlocker'
$DataDir     = Join-Path $env:ProgramData 'SiteBlocker'
$Exe         = Join-Path $InstallDir 'SiteBlocker.exe'
$Src         = $PSScriptRoot
$StartMenu   = Join-Path $env:ProgramData 'Microsoft\Windows\Start Menu\Programs\Блокировщик сайтов'
$UninstKey   = 'HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\Uninstall\SiteBlocker'
$RunKey      = 'HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\Run'
# DACL службы: SYSTEM — полный; Администраторы — только запуск/чтение статуса (НЕ остановка, НЕ изменение, НЕ удаление).
$ServiceSddlHard = 'D:(A;;CCDCLCSWRPWPDTLOCRSDRCWDWO;;;SY)(A;;CCLCSWRPRC;;;BA)(A;;CCLCSWRC;;;IU)(A;;CCLCSWRC;;;SU)'

function Test-Admin { (New-Object Security.Principal.WindowsPrincipal([Security.Principal.WindowsIdentity]::GetCurrent())).IsInRole([Security.Principal.WindowsBuiltInRole]::Administrator) }
if (-not (Test-Admin)) {
    Start-Process powershell.exe -Verb RunAs -ArgumentList @('-NoProfile','-ExecutionPolicy','Bypass','-File',('"'+$PSCommandPath+'"'))
    exit
}
function Say($t,$c='Gray'){ Write-Host $t -ForegroundColor $c }
function Done($code){ try{Stop-Transcript|Out-Null}catch{}; if(-not $NoPause){Write-Host '';Read-Host 'Нажмите Enter, чтобы закрыть окно'|Out-Null}; exit $code }

try { Start-Transcript -Path (Join-Path $env:TEMP 'SiteBlocker-install.log') -Force | Out-Null } catch {}
Say "Блокировщик сайтов $Version — установка" 'Cyan'
try {
    if (-not [Environment]::Is64BitOperatingSystem) { throw 'Нужна 64-разрядная Windows 10/11.' }
    $srcExe = Join-Path $Src 'app\SiteBlocker.exe'
    if (-not (Test-Path $srcExe)) { throw "Не найден $srcExe. Распакуйте архив целиком и запустите «Установить.cmd» из распакованной папки." }

    $svc = Get-Service -Name $ServiceName -ErrorAction SilentlyContinue
    if ($svc) {
        Say 'Найдена установленная версия — обновление на месте (настройки сохраняются).'
        Say 'Запрашиваю у службы разрешение на обновление…'
        $code = (Start-Process -FilePath $Exe -ArgumentList '--begin-maintenance','--quiet' -Wait -PassThru).ExitCode
        if ($code -eq 3 -and $svc.Status -ne 'Running') {
            try { Start-Service -Name $ServiceName; $svc.WaitForStatus('Running',[TimeSpan]::FromSeconds(20)); Start-Sleep 3 } catch {}
            $code = (Start-Process -FilePath $Exe -ArgumentList '--begin-maintenance','--quiet' -Wait -PassThru).ExitCode
        }
        if ($code -ne 0) {
            Say 'Обновление сейчас невозможно.' 'Yellow'
            Say 'Откройте «Блокировщик сайтов», введите пароль и нажмите «Разрешить удаление/обновление» (действует 15 минут), затем повторите установку.'
            Done 2
        }
        Say 'Разрешение получено — служба сняла защиту на 15 минут.'
        $svc.Refresh()
        if ($svc.Status -ne 'Stopped') { & sc.exe stop $ServiceName | Out-Null; try { $svc.WaitForStatus('Stopped',[TimeSpan]::FromSeconds(30)) } catch {} }
    }
    Get-Process -Name 'SiteBlocker' -ErrorAction SilentlyContinue | Stop-Process -Force -ErrorAction SilentlyContinue
    Start-Sleep -Milliseconds 800

    Say "Копирую файлы в $InstallDir…"
    New-Item -ItemType Directory -Force -Path $InstallDir | Out-Null
    $ok=$false
    for($i=0;$i -lt 10 -and -not $ok;$i++){ try { Copy-Item (Join-Path $Src 'app\*') $InstallDir -Recurse -Force; $ok=$true } catch { Get-Process -Name 'SiteBlocker' -ErrorAction SilentlyContinue | Stop-Process -Force -ErrorAction SilentlyContinue; Start-Sleep 1 } }
    if (-not $ok) { throw 'Не удалось заменить файлы программы (заняты). Перезагрузите компьютер и повторите.' }
    foreach ($f in @('uninstall.ps1','Удалить.cmd','README.md')) { $p=Join-Path $Src $f; if (Test-Path $p) { Copy-Item $p $InstallDir -Force } }
    # Папка восстановления/удаления — копируем СОДЕРЖИМОЕ в $InstallDir\recovery (надёжно и при повторной установке).
    $recSrc = Join-Path $Src 'recovery'
    $recDst = Join-Path $InstallDir 'recovery'
    if (Test-Path $recSrc) {
        New-Item -ItemType Directory -Force -Path $recDst | Out-Null
        Copy-Item (Join-Path $recSrc '*') $recDst -Recurse -Force
        $n = (Get-ChildItem $recDst -File -ErrorAction SilentlyContinue | Measure-Object).Count
        if ($n -gt 0) { Say "Скопированы средства восстановления ($n файлов) в $recDst" } else { Say 'Внимание: папка recovery пуста.' 'Yellow' }
    } else { Say 'Внимание: папка recovery не найдена в дистрибутиве.' 'Yellow' }
    Get-ChildItem $InstallDir -Recurse -File | Unblock-File -ErrorAction SilentlyContinue

    if (-not (Test-Path $DataDir)) { New-Item -ItemType Directory -Force -Path $DataDir | Out-Null; Say "Создан каталог данных $DataDir" }
    else { Say "Каталог данных $DataDir уже есть — настройки и пароль сохраняются." }
    # Права: SYSTEM — полный; Администраторы и Пользователи — чтение/выполнение (данные меняет только служба).
    foreach ($d in @($DataDir,$InstallDir)) {
        & icacls.exe $d /inheritance:r /grant:r '*S-1-5-18:(OI)(CI)F' '*S-1-5-32-544:(OI)(CI)RX' '*S-1-5-32-545:(OI)(CI)RX' /C /Q | Out-Null
        if (Get-ChildItem $d -Force -ErrorAction SilentlyContinue) { & icacls.exe (Join-Path $d '*') /reset /T /C /Q | Out-Null }
        & icacls.exe $d /setowner '*S-1-5-32-544' /T /C /Q | Out-Null
    }

    $bin = '"'+$Exe+'" --service'
    if (-not (Get-Service -Name $ServiceName -ErrorAction SilentlyContinue)) {
        Say 'Регистрирую службу…'
        New-Service -Name $ServiceName -BinaryPathName $bin -DisplayName $DisplayName -StartupType Automatic -Description 'Блокирует указанные сайты в браузерах учётной записи владельца. Разблокировка по паролю.' | Out-Null
    } else {
        Set-ItemProperty -Path "HKLM:\SYSTEM\CurrentControlSet\Services\$ServiceName" -Name ImagePath -Value $bin
        & sc.exe config $ServiceName start= auto | Out-Null
    }
    & sc.exe failure $ServiceName reset= 86400 actions= restart/1000/restart/1000/restart/5000 | Out-Null
    & sc.exe failureflag $ServiceName 1 | Out-Null

    New-ItemProperty -Path $RunKey -Name 'SiteBlocker' -Value ('"'+$Exe+'" --agent') -PropertyType String -Force | Out-Null
    New-Item -ItemType Directory -Force -Path $StartMenu | Out-Null
    $sh = New-Object -ComObject WScript.Shell
    $l = $sh.CreateShortcut((Join-Path $StartMenu 'Блокировщик сайтов.lnk'))
    $l.TargetPath=$Exe; $l.WorkingDirectory=$InstallDir; $l.IconLocation="$Exe,0"; $l.Description='Блокировщик сайтов'; $l.Save()
    $u = $sh.CreateShortcut((Join-Path $StartMenu 'Удалить Блокировщик сайтов.lnk'))
    $u.TargetPath='powershell.exe'; $u.Arguments='-NoProfile -ExecutionPolicy Bypass -File "'+(Join-Path $InstallDir 'uninstall.ps1')+'"'; $u.IconLocation="$Exe,0"; $u.Save()

    New-Item -Path $UninstKey -Force | Out-Null
    $size=[int]((Get-ChildItem $InstallDir -Recurse -File | Measure-Object Length -Sum).Sum/1KB)
    $props=@{ DisplayName='Блокировщик сайтов'; DisplayVersion=$Version; Publisher='Блокировщик сайтов'; InstallLocation=$InstallDir; DisplayIcon="$Exe,0"; UninstallString=('powershell.exe -NoProfile -ExecutionPolicy Bypass -File "'+(Join-Path $InstallDir 'uninstall.ps1')+'"') }
    foreach($k in $props.Keys){ New-ItemProperty -Path $UninstKey -Name $k -Value $props[$k] -PropertyType String -Force | Out-Null }
    foreach($k in @('NoModify','NoRepair')){ New-ItemProperty -Path $UninstKey -Name $k -Value 1 -PropertyType DWord -Force | Out-Null }
    New-ItemProperty -Path $UninstKey -Name 'EstimatedSize' -Value $size -PropertyType DWord -Force | Out-Null

    Say 'Запускаю службу…'
    Start-Service -Name $ServiceName
    (Get-Service -Name $ServiceName).WaitForStatus('Running',[TimeSpan]::FromSeconds(20))
    & sc.exe sdset $ServiceName $ServiceSddlHard | Out-Null

    Say ''
    Say 'Готово! «Блокировщик сайтов» установлен.' 'Green'
    Say 'Значок появится у часов. Откройте его и при первом запуске задайте пароль и список сайтов.'
    Say 'Совет: для максимальной защиты работайте из-под обычной (не администраторской) учётной записи.'
    Done 0
} catch {
    Say ''
    Say ('Ошибка установки: '+$_.Exception.Message) 'Red'
    Say ('Журнал: '+(Join-Path $env:TEMP 'SiteBlocker-install.log'))
    Done 1
}
