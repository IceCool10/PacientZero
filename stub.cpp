#include <stdio.h>
#include <stdint.h>
#include <string.h>
#include <iostream>
#include <stdio.h>
#include <Windows.h>
#include "Parser.h"
#include "util.h"
#include "aplib/lib/coff64/aplib.h"
#include <stdint.h>

#define DBG

#ifdef DBG
    #define dbgprintf printf
#else
    #define dbgprintf
#endif

typedef unsigned __int64 QWORD;
extern "C" int _chIt(void);
extern "C" void addIndexToTLSArray(DWORD newTLSIndex, PVOID tlsData);
char* decompressCode;
DWORD decompressCodeProt;

VOID DeobfuscateDllName(BYTE* dllName) {

    int dllNameLength = strlen((char*) dllName);
    char xorKey =   0x45;

    for (DWORD i = 0; i < dllNameLength; i++) {
        if (((char)dllName[i]) == xorKey)
            continue;
        dllName[i] ^= xorKey;
        rotr32(1, xorKey);
    }
}

VOID DeobfuscateDllFunction(BYTE* functionName) {

    int functionNameLength = strlen((char*) functionName);
    char xorKey =   0x45;

    for (DWORD i = 0; i < functionNameLength; i++) {
        if (((char)functionName[i]) == xorKey)
            continue;
        functionName[i] ^= xorKey;
        rotr32(1, xorKey);
    }
}

VOID DeobfuscateIAT( PIMAGE_DOS_HEADER dos_header, PIMAGE_NT_HEADERS nt_header)
{
    PIMAGE_THUNK_DATA thunk;
    PIMAGE_THUNK_DATA fixup;
    DWORD iat_rva;
    SIZE_T iat_size;
    HMODULE import_base;
    PIMAGE_IMPORT_DESCRIPTOR import_table =
        (PIMAGE_IMPORT_DESCRIPTOR)(nt_header->OptionalHeader.DataDirectory[IMAGE_DIRECTORY_ENTRY_IMPORT].VirtualAddress + 
            (UINT_PTR)dos_header);

    DWORD iat_loc =
        (nt_header->OptionalHeader.DataDirectory[IMAGE_DIRECTORY_ENTRY_IAT].VirtualAddress) ? 
        IMAGE_DIRECTORY_ENTRY_IAT : 
        IMAGE_DIRECTORY_ENTRY_IMPORT;

    iat_rva = nt_header->OptionalHeader.DataDirectory[iat_loc].VirtualAddress;
    iat_size = nt_header->OptionalHeader.DataDirectory[iat_loc].Size;

    LPVOID iat = (LPVOID)(iat_rva + (UINT_PTR)dos_header);
    DWORD op;
    VirtualProtect(iat, iat_size, PAGE_READWRITE, &op);
        while (import_table->Name) {
            //import_base = LoadLibraryA((LPCSTR)(import_table->Name + (UINT_PTR)dos_header));
            BYTE* dllName = (BYTE*)(import_table->Name + (UINT_PTR)dos_header);
            DeobfuscateDllName(dllName);


            fixup = (PIMAGE_THUNK_DATA)(import_table->FirstThunk + (UINT_PTR)dos_header);
            if (import_table->OriginalFirstThunk) {
                thunk = (PIMAGE_THUNK_DATA)(import_table->OriginalFirstThunk + (UINT_PTR)dos_header);
            } else {
                thunk = (PIMAGE_THUNK_DATA)(import_table->FirstThunk + (UINT_PTR)dos_header);
            }

            while (thunk->u1.Function) {
                PCHAR func_name;
                if (thunk->u1.Ordinal & IMAGE_ORDINAL_FLAG64) {
                    fixup->u1.Function = 
                        (UINT_PTR)GetProcAddress(import_base, (LPCSTR)(thunk->u1.Ordinal & 0xFFFF));

                } else {
                    func_name = 
                        (PCHAR)(((PIMAGE_IMPORT_BY_NAME)(thunk->u1.AddressOfData))->Name + (UINT_PTR)dos_header);
                    //fixup->u1.Function = (UINT_PTR)GetProcAddress(import_base, func_name);
                    DeobfuscateDllFunction((BYTE*)func_name);
                }
                fixup++;
                thunk++;
            }
            import_table++;
        }

    return;
}

/*
struct CTX {
    PEXCEPTION_POINTERS exPtr;
    DWORD thID;
};
DWORD WINAPI SetContext(LPVOID ctx) {

    CTX* context = (CTX*) ctx;
    HANDLE hThread = OpenThread((THREAD_GET_CONTEXT | THREAD_SET_CONTEXT | THREAD_SUSPEND_RESUME), false, context->thID);
    SuspendThread(hThread);
    BOOL tc = SetThreadContext(hThread, context->exPtr->ContextRecord);
    ResumeThread(hThread);
    return 0;
}
*/

LONG WINAPI ExceptionHandler(PEXCEPTION_POINTERS exPtr) {

    MEMORY_BASIC_INFORMATION memory;
    DWORD oldProt;
    if (exPtr->ExceptionRecord->ExceptionCode == EXCEPTION_ACCESS_VIOLATION) {

        dbgprintf("ACCESS VIOLATION RIP : %08X\n", exPtr->ContextRecord->Rip);

        
        if (!VirtualQuery((LPVOID)decompressCode, &memory, sizeof(MEMORY_BASIC_INFORMATION))) {
            dbgprintf("[-] Error VirtualQuery\n");
            return EXCEPTION_CONTINUE_SEARCH;
        }
        BOOL vp = VirtualProtect(memory.BaseAddress, memory.RegionSize, PAGE_EXECUTE_READWRITE, &oldProt);
        /*
        CTX context;
        context.exPtr = exPtr;
        DWORD tId;
        context.thID = GetCurrentThreadId();
        HANDLE hThread = CreateThread(NULL, 0, (LPTHREAD_START_ROUTINE)SetContext, &context, 0, &tId);
        WaitForSingleObject(hThread, INFINITE);
        */
        return EXCEPTION_CONTINUE_EXECUTION;
    }
    return EXCEPTION_CONTINUE_SEARCH;
}
                            
void CallTLSCallbacks(IMAGE_NT_HEADERS* nt, char* decompressedCode) {

    if ((nt->OptionalHeader.DataDirectory[IMAGE_DIRECTORY_ENTRY_TLS].VirtualAddress == 0) || (nt->OptionalHeader.DataDirectory[IMAGE_DIRECTORY_ENTRY_TLS].Size == 0)) {
        return;
    }
    DWORD tlsAddress = nt->OptionalHeader.DataDirectory[IMAGE_DIRECTORY_ENTRY_TLS].VirtualAddress;
    IMAGE_TLS_DIRECTORY* originalTLS = reinterpret_cast<IMAGE_TLS_DIRECTORY*>(decompressedCode + tlsAddress);

    PIMAGE_TLS_CALLBACK* ptls = (PIMAGE_TLS_CALLBACK*)originalTLS->AddressOfCallBacks;
    if (ptls) {
        while(*ptls) {
            (*ptls)((PVOID)decompressedCode, DLL_THREAD_ATTACH, 0);
            ptls++;
        }
    }
}


void SetTLSIndex(IMAGE_NT_HEADERS* nt, char* decompressedCode) {
    
    if ((nt->OptionalHeader.DataDirectory[IMAGE_DIRECTORY_ENTRY_TLS].VirtualAddress == 0) || (nt->OptionalHeader.DataDirectory[IMAGE_DIRECTORY_ENTRY_TLS].Size == 0)) {
        return;
    }
    DWORD tlsAddress = nt->OptionalHeader.DataDirectory[IMAGE_DIRECTORY_ENTRY_TLS].VirtualAddress;
    IMAGE_TLS_DIRECTORY* originalTLS = reinterpret_cast<IMAGE_TLS_DIRECTORY*>(decompressedCode + tlsAddress);

    DWORD newTLSIndex = TlsAlloc();
    if (newTLSIndex == TLS_OUT_OF_INDEXES) {
        return;
    }
    PVOID tlsData;

    *((DWORD*)originalTLS->AddressOfIndex) = newTLSIndex;
    addIndexToTLSArray(newTLSIndex, tlsData);
    DWORD tlsDataSize = originalTLS->EndAddressOfRawData - originalTLS->StartAddressOfRawData;
    memcpy(tlsData, (PVOID)originalTLS->StartAddressOfRawData,tlsDataSize);
    memset((PVOID) originalTLS->EndAddressOfRawData, 0, originalTLS->SizeOfZeroFill);
}

bool PacientZeroDecompress(HANDLE hFile, DWORD size, DWORD offset) {

    SetFilePointer(hFile, offset, NULL, FILE_BEGIN);
    char *compressedCode = (char*) malloc(size);
    if (!compressedCode) {
        dbgprintf("[-] Error malloc compressedCode\n");
        return false;
    }

    DWORD oldProt;
    MEMORY_BASIC_INFORMATION memory;

    DWORD bytesRead = 0;
    if (!ReadFile(hFile, compressedCode, size, &bytesRead, NULL)) {
        dbgprintf("[-] Error reading compressedCode\n");
        free(compressedCode);
        return false;
    }

	unsigned depackedsize = aPsafe_get_orig_size(compressedCode);
    decompressCodeProt = PAGE_EXECUTE_READWRITE;
    decompressCode = (char*) VirtualAlloc(NULL, depackedsize, MEM_COMMIT | MEM_RESERVE, decompressCodeProt);

    if (!VirtualQuery((LPVOID)decompressCode, &memory, sizeof(MEMORY_BASIC_INFORMATION))) {
        dbgprintf("[-] Error VirtualQuery\n");
        return false;
    }

    //AddVectoredExceptionHandler(1, ExceptionHandler  );
    if (decompress(compressedCode, decompressCode, depackedsize, size) != 0) {
        dbgprintf("[-] Error decompress code\n");
        free(compressedCode);
        return false;
    }

    dbgprintf("[*] Before DeobfuscateIAT\n");
    //DeobfuscateIAT((IMAGE_DOS_HEADER*)decompressCode, (IMAGE_NT_HEADERS*) (decompressCode + reinterpret_cast<IMAGE_DOS_HEADER*>(decompressCode)->e_lfanew));
    dbgprintf("[*] DeobfuscateIAT\n");


    IMAGE_NT_HEADERS* nt_header = (IMAGE_NT_HEADERS*) (decompressCode + reinterpret_cast<IMAGE_DOS_HEADER*>(decompressCode)->e_lfanew);

    dbgprintf("[*] Before FixImageIAT\n");

    FixImageIAT((IMAGE_DOS_HEADER*) decompressCode, nt_header);
    dbgprintf("[*] FixImageIAT\n");

    if (nt_header->OptionalHeader.DataDirectory[IMAGE_DIRECTORY_ENTRY_BASERELOC].VirtualAddress) {
        ptrdiff_t difference = (ptrdiff_t) ((BYTE*) decompressCode - (BYTE*) nt_header->OptionalHeader.ImageBase);
        if (difference) {
            dbgprintf("[*] Before FixImageReloc\n");

            FixImageRelocations((IMAGE_DOS_HEADER*) decompressCode, nt_header, difference);
            dbgprintf("[*] FixImageReloc\n");
        }
    }
    //VirtualProtect(memory.BaseAddress, memory.RegionSize, PAGE_NOACCESS, &oldProt);

    DWORD ThreadID;
    LPTHREAD_START_ROUTINE oep = (LPTHREAD_START_ROUTINE)(nt_header->OptionalHeader.AddressOfEntryPoint + (UINT_PTR)decompressCode);
    CallTLSCallbacks(nt_header, decompressCode);
    SetTLSIndex(nt_header, decompressCode);
    dbgprintf("oep :%16llX\n", oep);
    //HANDLE stubThread = CreateThread(NULL, 0, oep, NULL, 0, &ThreadID);
    ((void(*)())(oep))();


    return true;
}

void readSizeAndOffset(HANDLE hFile, DWORD& size, DWORD& offset) {

    DWORD bytesRead = 0;
    SetFilePointer(hFile, (LONG) - (2 * sizeof(DWORD)), NULL, FILE_END);
    if (!ReadFile(hFile, &size, sizeof(DWORD), &bytesRead, NULL)) {
        dbgprintf("[-] Error reading size\n");
        return;
    }
    dbgprintf("bytesRead : %04X\n", bytesRead);
    if (!ReadFile(hFile, &offset, sizeof(DWORD), &bytesRead, NULL)) {
        dbgprintf("[-] Error reading offset\n");
        return;
    }

}

int main() {


    char buffer[MAX_PATH];

    if (_chIt()) {
        dbgprintf("[-] Debugger detected\n");
        return 0;
    }

    if (!GetModuleFileNameA(NULL, buffer, MAX_PATH)) {
        dbgprintf("[-] Error getting info about this file\n");
        DWORD err = GetLastError();
        printf("[*] ERROR : %16llX\n", err);
        return -1;
    }

    dbgprintf("buffer : %s\n", buffer);

    HANDLE thisFile = CreateFileA(buffer, GENERIC_READ, 0, NULL, OPEN_EXISTING, FILE_ATTRIBUTE_NORMAL, NULL);
    if (thisFile == INVALID_HANDLE_VALUE) {
        dbgprintf("[-] Invalid File\n");
        DWORD err = GetLastError();
        printf("[*] ERROR : %16llX\n", err);
        return -1;
    }

    dbgprintf("[+] This file was opened successfully\n");

    DWORD size = 0;
    DWORD offset = 0;
    readSizeAndOffset(thisFile, size, offset);

    dbgprintf("size : %04X, offset : %04X\n", size, offset);
    if (size == 0 || offset == 0) {
        dbgprintf("[-] Error invalid size/offfset");
        return -1;
    }

    if (!PacientZeroDecompress(thisFile, size, offset)) {
        dbgprintf("[-] Error decompressing\n");
        return -1;
    }

    return 0;
    
}
