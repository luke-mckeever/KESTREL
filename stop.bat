@echo off
rem KESTREL: stop the web servers on both screens' ports.
setlocal enabledelayedexpansion
cd /d "%~dp0"
set stopped=0

rem 1) the PID KESTREL wrote when it started
if exist ".kestrel.pid" (
  set /p KPID=<".kestrel.pid"
  taskkill /PID !KPID! /T /F >nul 2>nul && set stopped=1
  del ".kestrel.pid" >nul 2>nul
)

rem 2) anything still listening on the two ports
for %%P in (8787 8788) do (
  for /f "tokens=5" %%I in ('netstat -ano ^| findstr /r /c:":%%P .*LISTENING"') do (
    taskkill /PID %%I /T /F >nul 2>nul && set stopped=1
  )
)

if !stopped!==1 (echo KESTREL stopped.) else (echo KESTREL was not running.)
ping -n 3 127.0.0.1 >nul
