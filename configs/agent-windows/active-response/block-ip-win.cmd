@echo off
rem Lanceur de block-ip-win.ps1 pour l'Active Response Wazuh (execd ne lance que .exe et .cmd).
rem L'entree standard (le JSON d'execd) est transmise telle quelle a PowerShell.
powershell.exe -NoProfile -NonInteractive -ExecutionPolicy Bypass -File "%~dp0block-ip-win.ps1"
