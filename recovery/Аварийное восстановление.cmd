@echo off
rem Блокировщик сайтов — аварийное восстановление. Сам запросит права администратора (UAC).
powershell.exe -NoProfile -ExecutionPolicy Bypass -File "%~dp0emergency.ps1"
