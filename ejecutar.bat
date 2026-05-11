@echo off
:: =====================================================
:: LANZADOR DE AUDITORIA DE RED - PORTABLE
:: Doble click para ejecutar (se autoelevara como Administrador)
:: Estructura esperada:
::   Auditoria\
::     ejecutar.bat
::     escaner_pro.ps1
::     nmap\
::       nmap.exe + resto de ficheros
:: =====================================================

:: --- AUTOELEVACION A ADMINISTRADOR ---
:: Si no se esta ejecutando como Administrador, se relanza solo
net session >nul 2>&1
if errorlevel 1 (
    echo [*] Solicitando privilegios de Administrador...
    powershell -Command "Start-Process '%~f0' -Verb RunAs"
    exit /b
)

:: --- A PARTIR DE AQUI YA SE EJECUTA COMO ADMINISTRADOR ---

:: Moverse a la carpeta donde esta el .bat (clave para el pendrive)
cd /d "%~dp0"

:: Añadir la carpeta nmap del pendrive al PATH temporalmente
:: Esto permite que nmap.exe sea encontrado sin estar instalado en el sistema
set PATH=%~dp0nmap;%PATH%

:: Verificar que nmap.exe existe en la subcarpeta nmap\
if not exist "%~dp0nmap\nmap.exe" (
    echo [!] No se encuentra nmap.exe en la carpeta nmap\.
    echo [!] Asegurate de que existe: Auditoria\nmap\nmap.exe
    pause
    exit /b
)

:: Verificar que el script .ps1 existe en la misma carpeta que el .bat
if not exist "%~dp0escaner_pro.ps1" (
    echo [!] No se encuentra escaner_pro.ps1 en esta carpeta.
    echo [!] Asegurate de que ejecutar.bat y escaner_pro.ps1 estan juntos.
    pause
    exit /b
)

echo [+] nmap encontrado : %~dp0nmap\nmap.exe
echo [+] Script encontrado: %~dp0escaner_pro.ps1
echo [+] Lanzando auditoria...
echo.

:: Lanzar PowerShell con el script usando la ruta absoluta
powershell -ExecutionPolicy Bypass -File "%~dp0escaner_pro.ps1"

pause
