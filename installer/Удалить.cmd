@echo off
rem Блокировщик сайтов — удаление. uninstall.ps1 сам запросит права администратора (UAC).
powershell.exe -NoProfile -ExecutionPolicy Bypass -File "%~dp0uninstall.ps1"
