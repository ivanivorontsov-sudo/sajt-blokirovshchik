# Запасное снятие политик блокировки браузеров для ТЕКУЩЕГО пользователя (HKCU).
# Через провайдер реестра PowerShell — работает даже при запрете редактирования реестра (DisableRegistryTools),
# в отличие от .reg/regedit. Службу НЕ трогает (для полного удаления используйте «Аварийное восстановление.cmd»).
$ErrorActionPreference='SilentlyContinue'
$vendors=@('Microsoft\Edge','Google\Chrome','Chromium','Vivaldi','BraveSoftware\Brave','YandexBrowser','Opera Software\Opera')
foreach ($v in $vendors) {
    $base="HKCU:\Software\Policies\$v"
    Remove-Item "$base\URLBlocklist" -Recurse -Force
    Remove-Item "$base\IncognitoModeUrlBlocklist" -Recurse -Force
    if (Test-Path $base) {
        Remove-ItemProperty -Path $base -Name 'DnsOverHttpsMode'
        Remove-ItemProperty -Path $base -Name 'BuiltInDnsClientEnabled'
    }
}
$ff="HKCU:\Software\Policies\Mozilla\Firefox"
Remove-Item "$ff\WebsiteFilter" -Recurse -Force
Remove-Item "$ff\DNSOverHTTPS" -Recurse -Force
Remove-ItemProperty -Path 'HKCU:\Software\Microsoft\Windows\CurrentVersion\Run' -Name 'SiteBlocker'
Write-Host 'Готово: политики блокировки для текущего пользователя сняты. Перезапустите браузеры.' -ForegroundColor Green
Read-Host 'Нажмите Enter, чтобы закрыть окно' | Out-Null
