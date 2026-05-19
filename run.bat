@echo off
REM Bootstrap script for phish-triage on Windows.
REM First run: creates a virtualenv, installs deps, runs the tool.
REM Subsequent runs: just runs the tool. Idempotent.
REM
REM Usage:   run.bat tests\fixtures\sample-phish.eml --no-enrich

setlocal
set "HERE=%~dp0"
set "VENV=%HERE%.venv"
set "SENTINEL=%VENV%\.phish_triage_installed"

where python >nul 2>nul
if errorlevel 1 (
    echo error: python is required but not installed. Get it from https://python.org
    exit /b 1
)

if not exist "%VENV%" (
    echo [run.bat] creating virtualenv at .venv\ ...
    python -m venv "%VENV%"
    if errorlevel 1 (
        echo error: 'python -m venv' failed.
        exit /b 1
    )
)

call "%VENV%\Scripts\activate.bat"

if not exist "%SENTINEL%" (
    echo [run.bat] installing phish-triage and dependencies (one-time) ...
    python -m pip install --quiet --upgrade pip
    python -m pip install --quiet -e "%HERE%"
    if errorlevel 1 exit /b 1
    type nul > "%SENTINEL%"
)

python -m phish_triage %*
exit /b %errorlevel%
