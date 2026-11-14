@echo off
setlocal EnableExtensions EnableDelayedExpansion
cd /d "%~dp0"
for /d %%D in ("%LocalAppData%\Programs\Python\Python3*") do if exist "%%~fD\python.exe" set "PYTHON_EXE=%%~fD\python.exe"
if not defined PYTHON_EXE (
  echo Python 3.12+ was not found. Run setup.ps1.
  exit /b 1
)
"!PYTHON_EXE!" main.py %*
exit /b %errorlevel%
