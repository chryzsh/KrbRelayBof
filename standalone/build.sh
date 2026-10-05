#!/bin/bash
set -e
x86_64-w64-mingw32-gcc \
    -o krbrelay.exe \
    krbrelay.c \
    -lole32 -loleaut32 -lrpcrt4 -lsecur32 -lws2_32 \
    -static -s \
    -Wall -Wextra -Wno-unused-parameter \
    -DWIN32_LEAN_AND_MEAN
echo "Built krbrelay.exe ($(stat -c%s krbrelay.exe) bytes)"
