@echo off
rem Полное принудительное удаление «Блокировщик сайтов» (запросит права администратора).
powershell.exe -NoProfile -ExecutionPolicy Bypass -File "%~dp0force-remove.ps1"
