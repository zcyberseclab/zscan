@echo off

set VERSION=v1.0.0
set BUILD_TIME=%date% %time%
for /f "tokens=*" %%a in ('git rev-parse HEAD') do set COMMIT_SHA=%%a

set LDFLAGS=-X 'main.Version=%VERSION%' -X 'main.BuildTime=%BUILD_TIME%' -X 'main.CommitSHA=%COMMIT_SHA%' -w -s

mkdir release

set GOOS=windows
set GOARCH=amd64
go build -ldflags="%LDFLAGS%" -o release\zscan_windows_amd64.exe cmd\main.go

set GOOS=linux
set GOARCH=amd64
go build -ldflags="%LDFLAGS%" -o release\zscan_linux_amd64 cmd\main.go

xcopy /E /I config release\config
copy README.md release\

cd release
powershell Compress-Archive -Path zscan_windows_amd64.exe,config,README.md -DestinationPath zscan_windows_amd64.zip 