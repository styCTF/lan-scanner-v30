@echo off
title LAN Scanner v3.0

:: 切换到脚本所在目录
cd /d "%~dp0"

:: 检查管理员权限
net session >nul 2>&1
if %errorlevel% neq 0 (
    echo [提示] 建议使用管理员权限运行，正在尝试提权...
    powershell -Command "Start-Process '%~f0' -Verb RunAs -WorkingDirectory '%~dp0'"
    exit /b
)

:: 检查 Python 是否安装
where python >nul 2>&1
if %errorlevel% neq 0 (
    echo.
    echo   [错误] 未找到 Python，请先安装 Python 3 并添加到 PATH。
    echo   下载地址: https://www.python.org/downloads/
    echo.
    pause
    exit /b 1
)

:: 启动 GUI
python "%~dp0lan_scanner.py"
if %errorlevel% neq 0 pause
