#!/bin/sh
# Copyright 2026- Seongwoo Hong. All rights reserved.
#
# The hex reader's honest programs (commit 42g, docs/PREVIEWS.md › Programs),
# compiled by real toolchains so the parsers meet what compilers really
# write. Each prints one line and does nothing else. Run from anywhere:
#
#     sh tests/fixtures/preview/programs.sh tests/fixtures/preview
#
# hello.exe     mingw-w64 (x64, console), no timestamp (--no-insert-timestamp)
# hello.dll     mingw-w64 DLL: two exports, a version resource ("Gorani
#               tests"), a manifest asking for asInvoker
# hello.elf     gcc, x86-64, position-independent, not stripped
# hello.macho   clang + ld64.lld: a universal Mach-O (x86_64, and arm64
#               signed ad hoc, as the linker does for Apple silicon), linked
#               against a stub of libSystem (no Apple SDK is needed)
#
# The HOSTILE program is not here: tests/lib/programs.mjs builds it when the
# tests run, so no file in this repository looks like malware to a scanner.
# Needs: x86_64-w64-mingw32-gcc and -windres, gcc, clang, ld64.lld, llvm-lipo.
set -eu
out=$(cd "${1:-.}" && pwd)
work=$(mktemp -d)
trap 'rm -rf "$work"' EXIT
cd "$work"
L=$(ls -d /usr/lib/llvm-*/bin 2>/dev/null | sort -V | tail -1)

cat > hello.c <<'C'
int puts(const char *);
int main(void) { puts("gorani hello"); return 0; }
C
cat > lib.c <<'C'
__declspec(dllexport) int gorani_count(int a) { return a + 1; }
__declspec(dllexport) int gorani_total(int a) { return a + 2; }
C
cat > app.manifest <<'X'
<?xml version="1.0" encoding="UTF-8" standalone="yes"?>
<assembly xmlns="urn:schemas-microsoft-com:asm.v1" manifestVersion="1.0">
<trustInfo xmlns="urn:schemas-microsoft-com:asm.v3"><security><requestedPrivileges>
<requestedExecutionLevel level="asInvoker" uiAccess="false"/>
</requestedPrivileges></security></trustInfo></assembly>
X
cat > ver.rc <<'R'
#include <winver.h>
1 VERSIONINFO
FILEVERSION 1,0,0,0
PRODUCTVERSION 1,0,0,0
BEGIN
  BLOCK "StringFileInfo"
  BEGIN
    BLOCK "040904B0"
    BEGIN
      VALUE "CompanyName", "Gorani tests"
      VALUE "FileDescription", "Counts water deer"
      VALUE "OriginalFilename", "hello.dll"
      VALUE "ProductName", "Gorani"
    END
  END
  BLOCK "VarFileInfo"
  BEGIN
    VALUE "Translation", 0x409, 1200
  END
END
2 24 "app.manifest"
R
x86_64-w64-mingw32-gcc -O2 -s -Wl,--no-insert-timestamp -o "$out/hello.exe" hello.c
x86_64-w64-mingw32-windres ver.rc -O coff -o ver.o
x86_64-w64-mingw32-gcc -O2 -s -shared -Wl,--no-insert-timestamp -o "$out/hello.dll" lib.c ver.o
gcc -O2 -o "$out/hello.elf" hello.c

cat > libSystem.tbd <<'T'
--- !tapi-tbd
tbd-version:     4
targets:         [ x86_64-macos, arm64-macos ]
install-name:    '/usr/lib/libSystem.B.dylib'
current-version: 1311
exports:
  - targets:         [ x86_64-macos, arm64-macos ]
    symbols:         [ _puts, dyld_stub_binder ]
...
T
for a in arm64 x86_64; do
	clang -target "$a-apple-macos13" -O2 -c hello.c -o "hello-$a.o"
	"$L/ld64.lld" -arch "$a" -platform_version macos 13.0 13.0 -o "hello-$a" "hello-$a.o" -L. -lSystem
done
"$L/llvm-lipo" -create hello-x86_64 hello-arm64 -output "$out/hello.macho"
echo "programs: hello.exe hello.dll hello.elf hello.macho → $out"
