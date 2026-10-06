@echo off
rem Запасное снятие политик блокировки для текущего пользователя (без reg.exe/regedit).
powershell.exe -NoProfile -ExecutionPolicy Bypass -File "%~dp0remove-policies.ps1"
