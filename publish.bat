@echo off
setlocal
cd /d "%~dp0"
dotnet publish src\EasyShare.Desktop\EasyShare.Desktop.csproj -c Release -r win-x64 --self-contained true -p:PublishSingleFile=true -p:IncludeNativeLibrariesForSelfExtract=true -p:EnableCompressionInSingleFile=true -o artifacts
echo.
echo Published to: %~dp0artifacts\Netshare.exe
endlocal
