#pragma once
#include <Windows.h>
#include "aplib/lib/coff/aplib.h"
#include <cstdint>
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

static unsigned long get_word_le(const void *pData, int pos)   {
    const unsigned char *pdata = static_cast<const unsigned char *>(pData);
    return pdata[pos + 0] | (unsigned (pdata[pos + 1]) << 8);
}

static unsigned long get_dword_le(const void *pData, int pos)   {
    const unsigned char *pdata = static_cast<const unsigned char *>(pData);
    return pdata[pos + 0] | (unsigned (pdata[pos + 1]) << 8) | (unsigned (pdata[pos + 2]) << 16) | (unsigned (pdata[pos + 3]) << 24);
}

static unsigned long get_qword_le(const void *pData, int pos)   {
    const unsigned char *pdata = static_cast<const unsigned char *>(pData);
    return pdata[pos + 0] | (QWORD (pdata[pos + 1]) << 8) | (QWORD (pdata[pos + 2]) << 16) | (QWORD (pdata[pos + 3]) << 24) | (QWORD (pdata[pos + 4]) << 32) | (QWORD (pdata[pos + 5]) << 40) | (QWORD (pdata[pos + 6]) << 48) | (QWORD (pdata[pos + 7]) << 56);
}


typedef struct IMAGE_DELAY_IMPORT_DESCRIPTOR
{
    DWORD grAttrs;
    DWORD szName;
    DWORD phmod;
    DWORD pIAT;
    DWORD pINT;
    DWORD pBoundIAT;
    DWORD pUnloadIAT;
    DWORD dwTimeStamp;
} IMAGE_DELAY_IMPORT_DESCRIPTOR, *PIMAGE_DELAY_IMPORT_DESCRIPTOR;
