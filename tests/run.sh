#!/bin/sh
set -e
cd "$(dirname "$0")/.."
CXX=${CXX:-x86_64-w64-mingw32-g++-posix}
mkdir -p build
$CXX -std=c++17 -O1 -DPSD_TEST -static tests/test_main.cpp -o build/tests.exe \
  -lwinhttp -lbcrypt -lcomctl32 -lshell32 -lole32 -luuid -lsetupapi -lcfgmgr32 -lcomdlg32 -lgdi32 -lgdiplus -ldwmapi -luxtheme -ladvapi32
[ -f build/cert.pem ] || openssl req -x509 -newkey rsa:2048 -nodes -keyout build/key.pem -out build/cert.pem -days 2 -subj "/CN=127.0.0.1" >/dev/null 2>&1
PORT=${PORT:-8443}
python3 tests/server.py build/cert.pem build/key.pem $PORT > build/server.log 2>&1 &
SRV=$!
trap 'kill $SRV 2>/dev/null' EXIT
for i in 1 2 3 4 5 6 7 8 9 10; do grep -q ready build/server.log && break; sleep 0.5; done
WINE=${WINE:-$(command -v wine || command -v wine64)}
WINEDEBUG=-all "$WINE" build/tests.exe $PORT
