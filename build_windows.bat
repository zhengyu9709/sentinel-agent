@echo off
title Build Sentinel Agent (Windows)

echo ============================================
echo Building Sentinel Agent for Windows...
echo ============================================

:: 切换到当前脚本所在目录
cd /d "%~dp0"

:: 下载并整理依赖（首次或依赖变更时会更新 go.sum）
go mod tidy

:: 设置编译环境
set GOOS=windows
set GOARCH=amd64
set CGO_ENABLED=0

:: 编译（无控制台窗口）
go build -ldflags="-s -w -H windowsgui" -o sentinel-agent.exe .

if %ERRORLEVEL% neq 0 (
    echo.
    echo ============================================
    echo Build Failed!
    echo ============================================
    pause
    exit /b 1
)

echo.
echo ============================================
echo Build Success!
echo Output:
echo %CD%\sentinel-agent.exe
echo ============================================

pause