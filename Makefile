BOFNAME := memreader
CC_x64 := x86_64-w64-mingw32-gcc

all:
        $(CC_x64) -o $(BOFNAME).o -c memreader.c -masm=intel
