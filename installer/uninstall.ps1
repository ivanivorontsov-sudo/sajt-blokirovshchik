# Блокировщик сайтов — удаление.
# Работает только после «Разрешить удаление/обновление» в окне программы (ввод пароля, окно 15 минут).
# Снимает политики блокировки, удаляет службу, автозапуск, ярлыки и файлы программы.
# Настройки и пароль (%ProgramData%\SiteBlocker) по умолчанию СОХРАНЯЮТСЯ; -RemoveData — удалить и их.
param([switch]$RemoveData, [switch]$Yes, [switch]$NoPause)

$ErrorActionPreference = 'Stop'
$ServiceName = 'SiteBlocker'
$InstallDir  = Join-Path $env:ProgramFiles 'SiteBlocker'
$DataDir     = Join-Path $env:ProgramData 'SiteBlocker'
$Exe         = Join-Path $InstallDir 'SiteBlocker.exe'
$StartMenu   = Join-Path $env:ProgramData 'Microsoft\Windows\Start Menu\Programs\Блокировщик сайтов'
$UninstKey   = 'HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\Uninstall\SiteBlocker'
$RunKey      = 'HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\Run'

function Test-Admin { (New-Object Security.Principal.WindowsPrincipal([Security.Principal.WindowsIdentity]::GetCurrent())).IsInRole([Security.Principal.WindowsBuiltInRole]::Administrator) }
if (-not (Test-Admin)) {
    $a=@('-NoProfile','-ExecutionPolicy','Bypass','-File',('"'+$PSCommandPath+'"'))
    if ($RemoveData){$a+='-RemoveData'}; if ($Yes){$a+='-Yes'}
    Start-Process powershell.exe -Verb RunAs -ArgumentList $a; exit
}
function Say($t,$c='Gray'){ Write-Host $t -ForegroundColor $c }
function Done($code){ if(-not $NoPause){Write-Host '';Read-Host 'Нажмите Enter, чтобы закрыть окно'|Out-Null}; exit $code }

Say 'Блокировщик сайтов — удаление' 'Cyan'
try {
    if (Test-Path $Exe) {
        $code=(Start-Process -FilePath $Exe -ArgumentList '--begin-maintenance','--quiet' -Wait -PassThru).ExitCode
        $svc0=Get-Service -Name $ServiceName -ErrorAction SilentlyContinue
        if ($code -eq 3 -and $svc0 -and $svc0.Status -ne 'Running') { try { Start-Service -Name $ServiceName; $svc0.WaitForStatus('Running',[TimeSpan]::FromSeconds(20)); Start-Sleep 3 } catch {}; $code=(Start-Process -FilePath $Exe -ArgumentList '--begin-maintenance','--quiet' -Wait -PassThru).ExitCode }
        if ($code -ne 0) {
            Say 'Удаление сейчас невозможно.' 'Yellow'
            Say 'Откройте «Блокировщик сайтов», введите пароль и нажмите «Разрешить удаление/обновление» (действует 15 минут), затем повторите.'
            Say 'Если программа сломана и служба не отвечает — см. recovery\README-восстановление.txt.'
            Done 2
        }
    }
    $svc=Get-Service -Name $ServiceName -ErrorAction SilentlyContinue
    if ($svc -and $svc.Status -ne 'Stopped') { Say 'Останавливаю службу…'; & sc.exe stop $ServiceName | Out-Null; try { $svc.WaitForStatus('Stopped',[TimeSpan]::FromSeconds(30)) } catch {} }
    Get-Process -Name 'SiteBlocker' -ErrorAction SilentlyContinue | Stop-Process -Force -ErrorAction SilentlyContinue
    Start-Sleep -Milliseconds 500
    if (Test-Path $Exe) { Start-Process -FilePath $Exe -ArgumentList '--restore-policies' -Wait | Out-Null }

    if (Get-Service -Name $ServiceName -ErrorAction SilentlyContinue) { & sc.exe delete $ServiceName | Out-Null }
    Remove-ItemProperty -Path $RunKey -Name 'SiteBlocker' -ErrorAction SilentlyContinue
    Remove-Item -Path $StartMenu -Recurse -Force -ErrorAction SilentlyContinue
    Remove-Item -Path $UninstKey -Recurse -Force -ErrorAction SilentlyContinue

    $wipe=$RemoveData
    if (-not $wipe -and -not $Yes -and (Test-Path $DataDir)) { $ans=Read-Host "Удалить также настройки и пароль ($DataDir)? По умолчанию — нет [д/Н]"; $wipe=($ans -match '^(д|да|y|yes)$') }
    if ($wipe -and (Test-Path $DataDir)) { Remove-Item -Path $DataDir -Recurse -Force; Say 'Настройки и пароль удалены.' }
    elseif (Test-Path $DataDir) { & icacls.exe $DataDir /grant '*S-1-5-32-544:(OI)(CI)F' /T /C /Q | Out-Null; Say "Настройки сохранены в $DataDir" }

    Set-Location $env:TEMP
    Remove-Item -Path $InstallDir -Recurse -Force -ErrorAction SilentlyContinue
    if (Test-Path $InstallDir) { Start-Process cmd.exe -ArgumentList ('/c ping -n 4 127.0.0.1 >nul & rd /s /q "'+$InstallDir+'"') -WindowStyle Hidden }
    Say ''
    Say '«Блокировщик сайтов» удалён. Блокировка снята.' 'Green'
    Done 0
} catch { Say ('Ошибка удаления: '+$_.Exception.Message) 'Red'; Done 1 }
