@echo off
chcp 65001 >nul
cd /d "%~dp0"
title NightRouter - compilar NightRouterKeys.exe

where py >nul 2>nul
if not errorlevel 1 (
    set PY=py -3
) else (
    set PY=python
)

%PY% -m pip install --upgrade pyinstaller
if errorlevel 1 goto erro

%PY% -m PyInstaller --onefile --console --clean --name NightRouterKeys gerar_chaves.py
if errorlevel 1 goto erro

copy /Y "dist\NightRouterKeys.exe" "NightRouterKeys.exe" >nul
echo.
echo Pronto: NightRouterKeys.exe criado nesta pasta.
echo O .exe e ignorado pelo git; o .env tambem.
pause
exit /b 0

:erro
echo.
echo Falha ao compilar. Verifique a instalacao do Python e a internet.
pause
exit /b 1
