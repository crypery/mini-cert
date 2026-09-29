@echo off
echo Building mini-cert ...
gcc -O2 -o mini-cert.exe -I. -I./crypery ./crypery/*.c mini-cert.c -DHTTP_NO_GZIP -lws2_32
if %errorlevel% neq 0 (
    echo Build FAILED
    exit /b 1
)
echo Build OK