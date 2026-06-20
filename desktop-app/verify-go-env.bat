@echo off
setlocal
if not defined GOEXE set "GOEXE=go"
"%GOEXE%" version || exit /b 1
"%GOEXE%" env GOARCH GOOS GOROOT GOVERSION || exit /b 1
"%GOEXE%" build ./...
