#!/bin/sh
set -e
cd "$(dirname "$0")"
CXX=${CXX:-x86_64-w64-mingw32-g++-posix}
WINDRES=${WINDRES:-x86_64-w64-mingw32-windres}
mkdir -p build
$WINDRES -I src src/app.rc -O coff -o build/app.res
$CXX -std=c++17 -O2 -municode -mwindows -static -s -Wall -Wno-unused-function -Wno-missing-field-initializers \
  src/main.cpp build/app.res -o build/PSD.exe \
  -lwinhttp -lbcrypt -lcomctl32 -lshell32 -lole32 -luuid -lsetupapi -lcfgmgr32 -lcomdlg32 -lgdi32 -lgdiplus -ldwmapi -luxtheme
ls -l build/PSD.exe
