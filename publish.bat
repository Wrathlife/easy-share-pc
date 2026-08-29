@echo off
setlocal
cd /d "%~dp0"

set "STAGE=%~dp0artifacts\publish"
set "LAUNCH=%~dp0current"

dotnet publish src\EasyShare.Desktop\EasyShare.Desktop.csproj -c Release -r win-x64 --self-contained true -p:PublishSingleFile=true -p:IncludeNativeLibrariesForSelfExtract=true -p:EnableCompressionInSingleFile=true -o "%STAGE%"
if errorlevel 1 exit /b 1

if not exist "%LAUNCH%" mkdir "%LAUNCH%"

REM Replace the stable launch copy. Rename works even if Netshare is still running;
REM the next shortcut launch then picks up the new exe.
if exist "%LAUNCH%\Netshare.exe" (
  del "%LAUNCH%\Netshare.exe" 2>nul
  if exist "%LAUNCH%\Netshare.exe" (
    if exist "%LAUNCH%\Netshare.exe.old" del "%LAUNCH%\Netshare.exe.old" 2>nul
    move /y "%LAUNCH%\Netshare.exe" "%LAUNCH%\Netshare.exe.old" >nul
  )
)

copy /y "%STAGE%\Netshare.exe" "%LAUNCH%\Netshare.exe" >nul
if errorlevel 1 (
  echo Failed to update current\Netshare.exe — close Netshare and run publish.bat again.
  exit /b 1
)

echo.
echo Launch copy: %LAUNCH%\Netshare.exe
echo Desktop shortcut can keep pointing at that path.
endlocal
