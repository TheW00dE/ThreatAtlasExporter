@echo off
rem ThreatAtlas Reports - desktop proof of concept (Windows).
rem Double-click to start. Your browser opens; keep this window open while you use it.
setlocal
cd /d "%~dp0\.."

where uv >nul 2>nul
if errorlevel 1 (
  echo.
  echo  This app needs "uv" (a small Python launcher^). Install it once, then start this file again:
  echo.
  echo    winget install --id=astral-sh.uv -e
  echo.
  echo  or see https://docs.astral.sh/uv/getting-started/installation/
  echo.
  pause
  exit /b 1
)

rem Use the Windows certificate store for downloads (corporate proxies and internal CAs).
set "UV_SYSTEM_CERTS=1"
rem PDFs are made with Microsoft Edge, which every Windows machine has.
uv run --no-dev --frozen tae-desktop --pdf-engine browser %*
if errorlevel 1 pause
