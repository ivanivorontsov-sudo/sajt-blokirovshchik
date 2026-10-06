<#
  Блокировщик сайтов — ПОЛНОЕ принудительное удаление сломанной установки (в т.ч. версии 1.0.0).
  Запускать ОДИН раз от имени администратора (скрипт сам попросит повышение).

  Зачем отдельный скрипт: у службы жёсткий DACL — останавливать/удалять её может только SYSTEM,
  а процесс помечен «неостанавливаемым» (sc stop отклоняется). Поэтому удаление службы и защищённых
  файлов выполняется ОТ ИМЕНИ SYSTEM через временную задачу планировщика (ScheduledTasks),
  а снятие политик браузеров — через провайдер реестра PowerShell.

  ВАЖНО: скрипт НЕ использует reg.exe / regedit / .reg — работает и при запрете редактирования реестра
  (DisableRegistryTools). Использует sc.exe, icacls, takeown, провайдер реестра и Win32 — они не блокируются.

  Журнал: C:\Users\Public\SiteBlocker-remove.log
#>
param([switch]$NoPause)
$ErrorActionPreference = 'Continue'

$Log = 'C:\Users\Public\SiteBlocker-remove.log'
function L([string]$m,[string]$c='Gray'){ $t="$(Get-Date -Format 'yyyy-MM-dd HH:mm:ss') [ADMIN] $m"; try{Add-Content -LiteralPath $Log -Value $t -Encoding UTF8}catch{}; Write-Host $m -ForegroundColor $c }

# --- Самоповышение ---
function Test-Admin { (New-Object Security.Principal.WindowsPrincipal([Security.Principal.WindowsIdentity]::GetCurrent())).IsInRole([Security.Principal.WindowsBuiltInRole]::Administrator) }
if (-not (Test-Admin)) {
    Start-Process powershell.exe -Verb RunAs -ArgumentList @('-NoProfile','-ExecutionPolicy','Bypass','-File',('"'+$PSCommandPath+'"'))
    exit
}

$ServiceName = 'SiteBlocker'
$InstallDir  = Join-Path $env:ProgramFiles 'SiteBlocker'
$DataDir     = Join-Path $env:ProgramData 'SiteBlocker'
$StartMenu   = Join-Path $env:ProgramData 'Microsoft\Windows\Start Menu\Programs\Блокировщик сайтов'
$UninstKey   = 'HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\Uninstall\SiteBlocker'

L '=== Принудительное удаление «Блокировщик сайтов» ===' 'Cyan'

# --- Список целевых SID (владелец/цели из machine.json + все загруженные кусты реальных пользователей) ---
$targetSids = New-Object System.Collections.Generic.HashSet[string]
try {
    $mj = Join-Path $DataDir 'machine.json'
    if (Test-Path $mj) {
        $cfg = Get-Content -LiteralPath $mj -Raw | ConvertFrom-Json
        foreach ($s in @($cfg.ownerSid, $cfg.OwnerSid)) { if ($s) { [void]$targetSids.Add($s) } }
        foreach ($s in @($cfg.targetSids, $cfg.TargetSids)) { foreach ($x in $s) { if ($x) { [void]$targetSids.Add($x) } } }
    }
} catch { L "machine.json: $($_.Exception.Message)" }

# --- Снятие политик браузеров (провайдер реестра), функция на любой корень (HKCU: или HKU:\<SID>) ---
$vendors = @('Microsoft\Edge','Google\Chrome','Chromium','Vivaldi','BraveSoftware\Brave','YandexBrowser','Opera Software\Opera')
function Clear-Policies([string]$base,[string]$label) {
    $touched = 0
    foreach ($v in $vendors) {
        $k = "$base\Software\Policies\$v"
        foreach ($sub in @('URLBlocklist','IncognitoModeUrlBlocklist')) { if (Test-Path "$k\$sub") { Remove-Item "$k\$sub" -Recurse -Force -ErrorAction SilentlyContinue; $touched++ } }
        if (Test-Path $k) { foreach ($val in @('DnsOverHttpsMode','BuiltInDnsClientEnabled')) { if ($null -ne (Get-ItemProperty -Path $k -Name $val -ErrorAction SilentlyContinue)) { Remove-ItemProperty -Path $k -Name $val -ErrorAction SilentlyContinue; $touched++ } } }
    }
    $ff = "$base\Software\Policies\Mozilla\Firefox"
    foreach ($sub in @('WebsiteFilter','DNSOverHTTPS')) { if (Test-Path "$ff\$sub") { Remove-Item "$ff\$sub" -Recurse -Force -ErrorAction SilentlyContinue; $touched++ } }
    $runk = "$base\Software\Microsoft\Windows\CurrentVersion\Run"
    if (Test-Path $runk) { if ($null -ne (Get-ItemProperty -Path $runk -Name 'SiteBlocker' -ErrorAction SilentlyContinue)) { Remove-ItemProperty -Path $runk -Name 'SiteBlocker' -ErrorAction SilentlyContinue; $touched++ } }
    L "  политики сняты ($label): изменений $touched"
}

# HKCU текущего администратора (как правило — Иван).
Clear-Policies 'HKCU:' 'HKCU текущего пользователя'

# HKU всех загруженных кустов реальных пользователей + явные целевые SID.
if (-not (Get-PSDrive -Name HKU -ErrorAction SilentlyContinue)) { New-PSDrive -Name HKU -PSProvider Registry -Root HKEY_USERS -Scope Global | Out-Null }
$loaded = Get-ChildItem HKU: -ErrorAction SilentlyContinue | ForEach-Object { $_.PSChildName } | Where-Object { $_ -match '^S-1-5-21-[\d-]+$' }
foreach ($s in $loaded) { [void]$targetSids.Add($s) }
foreach ($sid in $targetSids) {
    if (Test-Path "HKU:\$sid") { Clear-Policies "HKU:\$sid" "HKU\$sid" }
    else { L "  куст HKU\$sid не загружен (пропуск; снимется при входе или через emergency.ps1)" }
}

# --- Полезная нагрузка, выполняемая ОТ ИМЕНИ SYSTEM (служба, файлы, HKLM) ---
$sysScript = 'C:\Users\Public\SiteBlocker-sys-remove.ps1'
$doneMark  = 'C:\Users\Public\SiteBlocker-remove.done'
Remove-Item $doneMark -ErrorAction SilentlyContinue

$payload = @'
$ErrorActionPreference='Continue'
$Log='C:\Users\Public\SiteBlocker-remove.log'
function L($m){ try{Add-Content -LiteralPath $Log -Value ("$(Get-Date -Format 'yyyy-MM-dd HH:mm:ss') [SYSTEM] "+$m) -Encoding UTF8}catch{} }
$ServiceName='SiteBlocker'
$InstallDir=Join-Path $env:ProgramFiles 'SiteBlocker'
$DataDir=Join-Path $env:ProgramData 'SiteBlocker'
$StartMenu=Join-Path $env:ProgramData 'Microsoft\Windows\Start Menu\Programs\Блокировщик сайтов'
$UninstKey='HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\Uninstall\SiteBlocker'
$RunKey='HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\Run'
$SvcKey='HKLM:\SYSTEM\CurrentControlSet\Services\SiteBlocker'
L ('запуск от '+[System.Security.Principal.WindowsIdentity]::GetCurrent().Name)

# 1. Отключить перезапуск при сбое и автозапуск, чтобы служба не воскресла.
& sc.exe failure $ServiceName reset= 0 actions= '""' | Out-Null
& sc.exe config  $ServiceName start= disabled | Out-Null
L 'failure actions и автозапуск отключены'

# 2. Убить процессы (sc stop отклоняется «неостанавливаемой» службой — поэтому именно kill).
for ($i=0; $i -lt 5; $i++) {
    $procs = Get-Process -Name 'SiteBlocker' -ErrorAction SilentlyContinue
    if (-not $procs) { break }
    $procs | ForEach-Object { try { Stop-Process -Id $_.Id -Force -ErrorAction Stop; L ('убит процесс PID '+$_.Id) } catch { L ('kill PID '+$_.Id+': '+$_.Exception.Message) } }
    Start-Sleep -Milliseconds 400
}
& sc.exe stop $ServiceName 2>$null | Out-Null  # на всякий случай (может отклониться — не критично)

# 3. Удалить службу (SYSTEM есть DELETE по DACL).
& sc.exe delete $ServiceName | Out-Null
Start-Sleep -Milliseconds 500
if (Get-Service -Name $ServiceName -ErrorAction SilentlyContinue) {
    L 'sc delete не завершилось — удаляю ключ службы через провайдер реестра'
    try { Remove-Item $SvcKey -Recurse -Force -ErrorAction Stop; L 'ключ службы удалён (эффект после перезагрузки)' }
    catch { L ('ключ службы: '+$_.Exception.Message+' — потребуется перезагрузка') }
} else { L 'служба удалена' }

# 4. HKLM Run + Uninstall + ярлыки.
try { if ($null -ne (Get-ItemProperty -Path $RunKey -Name 'SiteBlocker' -ErrorAction SilentlyContinue)) { Remove-ItemProperty -Path $RunKey -Name 'SiteBlocker' -ErrorAction SilentlyContinue; L 'HKLM Run\SiteBlocker удалён' } } catch {}
try { if (Test-Path $UninstKey) { Remove-Item $UninstKey -Recurse -Force -ErrorAction SilentlyContinue; L 'ключ Uninstall удалён' } } catch {}
try { if (Test-Path $StartMenu) { Remove-Item $StartMenu -Recurse -Force -ErrorAction SilentlyContinue; L 'ярлыки меню «Пуск» удалены' } } catch {}

# 5. Файлы программы и данные (снять защиту ACL: SYSTEM — владелец, полный доступ, затем удалить).
foreach ($d in @($InstallDir,$DataDir)) {
    if (-not (Test-Path $d)) { continue }
    try { & takeown.exe /f $d /r /d y 2>$null | Out-Null } catch {}
    try { & icacls.exe $d /setowner '*S-1-5-18' /T /C /Q 2>$null | Out-Null } catch {}
    try { & icacls.exe $d /grant '*S-1-5-18:(OI)(CI)F' /T /C /Q 2>$null | Out-Null } catch {}
    for ($i=0; $i -lt 6 -and (Test-Path $d); $i++) { Remove-Item $d -Recurse -Force -ErrorAction SilentlyContinue; if (Test-Path $d) { Start-Sleep -Milliseconds 500 } }
    if (Test-Path $d) { L ('не удалось удалить '+$d) } else { L ('удалено: '+$d) }
}

'DONE' | Out-File -LiteralPath 'C:\Users\Public\SiteBlocker-remove.done' -Encoding ASCII
L 'полезная нагрузка SYSTEM завершена'
'@
Set-Content -LiteralPath $sysScript -Value $payload -Encoding UTF8

# --- Запустить payload как SYSTEM через планировщик ---
L 'Запускаю удаление службы и файлов от имени SYSTEM (задача планировщика)…'
$ranAsSystem = $false
try {
    $taskName = 'SiteBlocker-ForceRemove'
    $act = New-ScheduledTaskAction -Execute 'powershell.exe' -Argument ('-NoProfile -ExecutionPolicy Bypass -WindowStyle Hidden -File "'+$sysScript+'"')
    $prin = New-ScheduledTaskPrincipal -UserId 'NT AUTHORITY\SYSTEM' -LogonType ServiceAccount -RunLevel Highest
    $task = New-ScheduledTask -Action $act -Principal $prin
    Register-ScheduledTask -TaskName $taskName -InputObject $task -Force | Out-Null
    Start-ScheduledTask -TaskName $taskName
    $deadline = (Get-Date).AddSeconds(120)
    while ((Get-Date) -lt $deadline -and -not (Test-Path $doneMark)) { Start-Sleep -Milliseconds 700 }
    if (Test-Path $doneMark) { $ranAsSystem = $true; L 'Задача SYSTEM завершилась.' 'Green' } else { L 'Задача SYSTEM не подтвердила завершение за 120 с.' 'Yellow' }
    Start-Sleep -Milliseconds 500
    Unregister-ScheduledTask -TaskName $taskName -Confirm:$false -ErrorAction SilentlyContinue
} catch {
    L ('Не удалось выполнить через планировщик: '+$_.Exception.Message) 'Yellow'
}

# Резерв: если задача SYSTEM не отработала — пробуем те же шаги напрямую (админ; может не хватить прав на службу).
if (-not $ranAsSystem) {
    L 'Резерв: выполняю удаление напрямую от администратора…' 'Yellow'
    & sc.exe failure $ServiceName reset= 0 actions= '""' 2>$null | Out-Null
    & sc.exe config  $ServiceName start= disabled 2>$null | Out-Null
    Get-Process -Name 'SiteBlocker' -ErrorAction SilentlyContinue | Stop-Process -Force -ErrorAction SilentlyContinue
    & sc.exe delete  $ServiceName 2>$null | Out-Null
    try { Remove-ItemProperty -Path 'HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\Run' -Name 'SiteBlocker' -ErrorAction SilentlyContinue } catch {}
    try { Remove-Item $UninstKey -Recurse -Force -ErrorAction SilentlyContinue } catch {}
    try { Remove-Item $StartMenu -Recurse -Force -ErrorAction SilentlyContinue } catch {}
    foreach ($d in @($InstallDir,$DataDir)) { if (Test-Path $d) { & takeown.exe /f $d /r /d y 2>$null | Out-Null; & icacls.exe $d /grant '*S-1-5-32-544:(OI)(CI)F' /T /C /Q 2>$null | Out-Null; Remove-Item $d -Recurse -Force -ErrorAction SilentlyContinue } }
}

Remove-Item $sysScript -ErrorAction SilentlyContinue

# --- Проверка результата ---
L '--- Проверка ---' 'Cyan'
$svc   = Get-Service -Name $ServiceName -ErrorAction SilentlyContinue
$proc  = Get-Process -Name 'SiteBlocker' -ErrorAction SilentlyContinue
$runOk = $null -eq (Get-ItemProperty -Path 'HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\Run' -Name 'SiteBlocker' -ErrorAction SilentlyContinue)
$items = [ordered]@{
    'Служба удалена'            = ($null -eq $svc)
    'Процессы завершены'        = ($null -eq $proc)
    'Папка программы удалена'    = (-not (Test-Path $InstallDir))
    'Папка данных удалена'      = (-not (Test-Path $DataDir))
    'Автозапуск (HKLM Run) снят'= $runOk
    'Ключ «Uninstall» удалён'   = (-not (Test-Path $UninstKey))
}
$allOk = $true
foreach ($k in $items.Keys) { $ok=$items[$k]; if (-not $ok){$allOk=$false}; L ("  [{0}] {1}" -f $(if($ok){'OK'}else{'--'}), $k) $(if($ok){'Green'}else{'Yellow'}) }

if ($allOk) { L 'РЕЗУЛЬТАТ: удаление выполнено ПОЛНОСТЬЮ.' 'Green' }
elseif ($svc -and $svc.Status) { L 'РЕЗУЛЬТАТ: служба помечена на удаление — ПЕРЕЗАГРУЗИТЕ компьютер и запустите скрипт ещё раз для контрольной проверки.' 'Yellow' }
else { L 'РЕЗУЛЬТАТ: удалено частично — см. журнал ниже.' 'Yellow' }
L ("Журнал: "+$Log)

if (-not $NoPause) { Write-Host ''; Read-Host 'Нажмите Enter, чтобы закрыть окно' | Out-Null }
