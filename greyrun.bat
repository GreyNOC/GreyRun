@echo off
REM GreyRun launcher for Windows. Place this folder on your PATH (or call it
REM by full path) to run GreyRun without installing it: greyrun <command>
setlocal
python -m greyrun %*
exit /b %ERRORLEVEL%
