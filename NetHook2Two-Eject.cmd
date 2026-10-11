@echo off
rem Ejects NetHook2Two from the running Steam client. Asks for administrator rights.
net session >nul 2>&1 && goto :elevated
if "%~1"=="" (
  powershell -NoProfile -Command "Start-Process -Verb RunAs -FilePath '%~f0'"
) else (
  powershell -NoProfile -Command "Start-Process -Verb RunAs -FilePath '%~f0' -ArgumentList '%*'"
)
exit /b
:elevated
if not exist "%~dp0NetHook2Two.dll" (echo NetHook2Two.dll not found next to this script. & pause & exit /b 1)
rundll32 "%~dp0NetHook2Two.dll",Eject %*
