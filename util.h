#include <Windows.h>
#include "aplib/lib/coff/aplib.h"
#include <stdio.h>
#include <string.h>

VOID FixImageIAT( PIMAGE_DOS_HEADER dos_header, PIMAGE_NT_HEADERS nt_header);
HANDLE GetImageActCtx(HMODULE module);
BOOL FixImageRelocations(PIMAGE_DOS_HEADER dos_header, PIMAGE_NT_HEADERS nt_header, ULONG_PTR delta);
int callback(unsigned int insize, unsigned int inpos,unsigned int outpos, void *cbparam);
int decompress(char *packed, char *data, unsigned depackedsizepacked, unsigned int inputSize);
uint32_t rotr32 (uint32_t n, unsigned int c);
int compress( char *input,  char *packed, unsigned int insize, unsigned int &outSize);
typedef unsigned __int64 QWORD;
