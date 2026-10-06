@echo off
rem Блокировщик сайтов — установка/обновление. install.ps1 сам запросит права администратора (UAC).
powershell.exe -NoProfile -ExecutionPolicy Bypass -File "%~dp0install.ps1"
