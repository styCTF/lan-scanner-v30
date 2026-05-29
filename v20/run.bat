@echo off
title LAN 扫描器 v2.0

:: 切换到脚本所在目录
cd /d "%~dp0"

:: 检查管理员权限
net session >nul 2>&1
if %errorlevel% neq 0 (
    echo [提示] 此工具需要管理员权限，正在请求提权...
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

echo.
echo   ======================================================================
echo                 局域网 IP 扫描器 v2.0
echo   ======================================================================
echo.

:: 列出所有可用网卡
echo   正在检测网络接口...
echo.
python "%~dp0lan_scanner.py" -l
if %errorlevel% neq 0 (
    echo.
    echo   [错误] 无法获取网络接口列表，请检查网络连接。
    echo.
    pause
    exit /b 1
)

:: 让用户选择网卡
echo.
set /p choice="  请输入要扫描的网卡序号 (直接回车=1): "
if "%choice%"=="" set choice=1

echo.
echo   正在开始扫描...
echo.

:: 执行扫描
python "%~dp0lan_scanner.py" -i %choice%

if %errorlevel% neq 0 (
    echo.
    echo   扫描过程中断或出错。
)

echo.
pause
