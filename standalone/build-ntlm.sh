#!/bin/bash
set -e
x86_64-w64-mingw32-gcc \
    -o krbrelay-ntlm.exe \
    krbrelay-ntlm.c \
    -lole32 -loleaut32 -lrpcrt4 -lsecur32 -lws2_32 \
    -static -s \
    -Wall -Wextra -Wno-unused-parameter \
    -DWIN32_LEAN_AND_MEAN
echo "Built krbrelay-ntlm.exe ($(stat -c%s krbrelay-ntlm.exe) bytes)"
