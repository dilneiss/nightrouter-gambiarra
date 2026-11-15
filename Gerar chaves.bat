@echo off
chcp 65001 >nul
cd /d "%~dp0"
title NightRouter - gerar contas e chaves

where py >nul 2>nul
if not errorlevel 1 (
    py -3 "gerar_chaves.py" --pause
    exit /b %errorlevel%
)

where python >nul 2>nul
if not errorlevel 1 (
    python "gerar_chaves.py" --pause
    exit /b %errorlevel%
)

echo.
echo Python 3 nao foi encontrado neste computador.
echo Instale em https://www.python.org/downloads/ (marque "Add Python to PATH")
echo Depois execute este arquivo novamente.
echo.
pause
