@echo off
rem KESTREL: start both screens (map on 8787, analytics on 8788) in a minimised window.
cd /d "%~dp0"

rem already running? just open the pages
netstat -ano | findstr /r /c:":8787 .*LISTENING" >nul
if %errorlevel%==0 (
  echo KESTREL is already running.
  start "" http://127.0.0.1:8787/
  start "" http://127.0.0.1:8788/
  goto :eof
)

where python >nul 2>nul
if errorlevel 1 (
  echo Python was not found. Install Python 3.7+ from https://www.python.org/ and tick "Add to PATH".
  pause
  goto :eof
)

start "KESTREL server" /min python kestrel.py --port 8787 --analytics-port 8788 %*
echo KESTREL starting...
echo   Screen 1 - Map:       http://127.0.0.1:8787/
echo   Screen 2 - Analytics: http://127.0.0.1:8788/
echo Both pages open in your browser. Run stop.bat to shut it down.
ping -n 4 127.0.0.1 >nul
