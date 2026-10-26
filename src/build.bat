@echo off
setlocal
cd /d "%~dp0"

set "PY=py -3"
where py >nul 2>&1
if errorlevel 1 set "PY=python"

%PY% build.py
if errorlevel 1 pause
