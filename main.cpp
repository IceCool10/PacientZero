#include <Windows.h>
#include <string.h>
#include <iostream>
#include <stdio.h>
#include "Parser.h"
#include "util.h"
#include <stdint.h>
#include "aplib/lib/coff/aplib.h"
using namespace std;

#ifndef CB_CALLCONV
# if defined(AP_DLL)
#  define CB_CALLCONV __stdcall
# elif defined(__GNUC__)
#  define CB_CALLCONV
# else
#  define CB_CALLCONV __cdecl
# endif
#endif

VOID obfuscateDllName(BYTE* dllName) {

    int dllNameLength = strlen((char*) dllName);
    char xorKey =   0x45;

    for (DWORD i = 0; i < dllNameLength; i++) {
        if (((char)dllName[i]) == xorKey)
            continue;
        dllName[i] ^= xorKey;
        rotr32(1, xorKey);
    }
}

VOID obfuscateDllFunction(BYTE* functionName) {

    int functionNameLength = strlen((char*) functionName);
    char xorKey =   0x45;

    for (DWORD i = 0; i < functionNameLength; i++) {
        if (((char)functionName[i]) == xorKey)
            continue;
        functionName[i] ^= xorKey;
        rotr32(1, xorKey);
    }
}

VOID ObfuscateIAT( PIMAGE_DOS_HEADER dos_header, PIMAGE_NT_HEADERS nt_header)
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
            obfuscateDllName(dllName);


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
                    obfuscateDllFunction((BYTE*)func_name);
                }
                fixup++;
                thunk++;
            }
            import_table++;
        }

    return;
}

VOID DropCompressedExe(BYTE* compressCode, Parser* parser, unsigned int compressCodeLength) {

    char stubName[] = "STUB";
    HRSRC stub = FindResource (NULL, stubName, RT_RCDATA);

    if (stub == NULL) {
        printf("[-] Error getting stub\n");
        return;
    }

    int size = SizeofResource(NULL, stub);
    if (!size) {
        printf("[-] Error SizeofResource\n");
        return;
    }

    HGLOBAL hStub = LoadResource(NULL, stub);

    if (!hStub) {
        printf("[-] Error LoadResource\n");
        return;
    }

    unsigned char *pStub = (unsigned char *) LockResource(hStub);

    HANDLE droppedExe = CreateFileA("compressedexe.exe", GENERIC_WRITE, 0, NULL, CREATE_ALWAYS, FILE_FLAG_WRITE_THROUGH, NULL);

    if (droppedExe == INVALID_HANDLE_VALUE) {
        printf("[-] Error handle\n");
        return;
    }

    DWORD bytesWritten = 0;
    if (!WriteFile(droppedExe, pStub, size, &bytesWritten, NULL)) {
        printf("[-] Error WriteFile\n");
        return;
    }

    // round size;
    int initialSize = size;
    char zero = 0x0;
    size = (size + 0x100) / 0x100 * 0x100;

    DWORD compressCodePos = SetFilePointer(droppedExe, size, 0, FILE_BEGIN);
    printf("[*] compressCodePos : %08X\n", compressCodePos);

    printf("[*] compressCodeLength  : %08X\n", compressCodeLength);
    printf("compressCode %s\n", compressCode);
    if (!WriteFile(droppedExe, (unsigned char*)compressCode, compressCodeLength, &bytesWritten, NULL)) {
        printf("[-] Error writting compressed code\n");
        DWORD err = GetLastError();
        printf("error : %X\n", err);
        return ;
    }

    if (!WriteFile(droppedExe, &compressCodeLength, sizeof(DWORD), &bytesWritten, NULL)) {
        printf("[-] Error writting compress code length\n");
        return ;
    }
    

    if (!WriteFile(droppedExe, &compressCodePos, sizeof(DWORD), &bytesWritten, NULL)) {
        printf("[-] Error writting code pos\n");
        return ;
    }

}

bool PackFile(Parser* parser, HANDLE hFile) {

    printf("PackFile\n");
    unsigned char* mappedFile;
    DWORD entryPoint = 0;
    WORD numberOfSections = 0;

    LPVOID baseAddress;
    HANDLE mapFile = CreateFileMappingA(hFile, 0, PAGE_EXECUTE_READWRITE | SEC_IMAGE , 0, 0, 0);
    if (mapFile == NULL) {
        printf("[-] Error creating file mapping\n");
        DWORD err = GetLastError();
        printf("error : %X\n", err);
        return false;
    }

    if (parser->getArchitecture() == 0) {
        entryPoint = parser->ntHeader32.OptionalHeader.AddressOfEntryPoint;
        numberOfSections = parser->ntHeader32.FileHeader.NumberOfSections;
        baseAddress = VirtualAlloc(NULL, parser->ntHeader32.OptionalHeader.SizeOfImage, MEM_COMMIT | MEM_RESERVE | MEM_TOP_DOWN , PAGE_EXECUTE_READWRITE);
        if (baseAddress == NULL) {
            printf("[-] Error virtual alloc\n");
            DWORD err = GetLastError();
            printf("Error : %X\n", err);
            return false;
        }
        mappedFile = (unsigned char*) MapViewOfFile(mapFile, FILE_MAP_ALL_ACCESS, 0, 0, 0);
    }
    else if (parser->getArchitecture() == 1) {
        printf("64 bit\n");
        entryPoint = parser->ntHeader64.OptionalHeader.AddressOfEntryPoint;
        numberOfSections = parser->ntHeader64.FileHeader.NumberOfSections;
        baseAddress = VirtualAlloc(NULL, parser->ntHeader64.OptionalHeader.SizeOfImage, MEM_RESERVE, PAGE_EXECUTE_READWRITE);
        if (!baseAddress) {
            printf("[-] Error virtual alloc\n");
            DWORD err = GetLastError();
            printf("Error : %X\n", err);
            return false;
        }       
        mappedFile = (unsigned char*) MapViewOfFile(mapFile, FILE_MAP_ALL_ACCESS, 0, 0, 0);
    }

    if (!mappedFile) {
        printf("[-] Error MapViewOfFile\n");
        DWORD err = GetLastError();
        printf("Error : %X\n", err);
        return false;
    }

    DWORD sectionId = 0;
    for (DWORD i = 0; i < numberOfSections; i++) {
        if ((entryPoint >= parser->sectionHeader[i].VirtualAddress) && (entryPoint < parser->sectionHeader[i].VirtualAddress + parser->sectionHeader[i].Misc.VirtualSize)) {
            sectionId = i;
            break;
        }
    }

    HANDLE actctx = NULL;
    UINT_PTR cookie = 0;
    BOOL changed_ctx = FALSE;
    if (parser->ntHeader64.OptionalHeader.DataDirectory[IMAGE_DIRECTORY_ENTRY_RESOURCE].VirtualAddress) {
        actctx = GetImageActCtx((HMODULE)mappedFile);
        if (actctx) 
            changed_ctx = ActivateActCtx(actctx, &cookie);
    }
    

    /*
     FixImageIAT((IMAGE_DOS_HEADER*)mappedFile, (IMAGE_NT_HEADERS*)(mappedFile + reinterpret_cast<IMAGE_DOS_HEADER*>(mappedFile)->e_lfanew));

    if (parser->ntHeader64.OptionalHeader.DataDirectory[IMAGE_DIRECTORY_ENTRY_BASERELOC].VirtualAddress) {
        ptrdiff_t difference = (ptrdiff_t) ((PBYTE)mappedFile - (PBYTE)(reinterpret_cast<IMAGE_NT_HEADERS*>(mappedFile + reinterpret_cast<IMAGE_DOS_HEADER*>(mappedFile)->e_lfanew)->OptionalHeader.ImageBase));
        if (difference) {
            FixImageRelocations((PIMAGE_DOS_HEADER)mappedFile, (IMAGE_NT_HEADERS*)(mappedFile + reinterpret_cast<IMAGE_DOS_HEADER*>(mappedFile)->e_lfanew), difference);
        }
    }
    */
     ObfuscateIAT((IMAGE_DOS_HEADER*)mappedFile, (IMAGE_NT_HEADERS*)(mappedFile + reinterpret_cast<IMAGE_DOS_HEADER*>(mappedFile)->e_lfanew));

    char* compressedCode = (char *) malloc(sizeof(char) * parser->ntHeader64.OptionalHeader.SizeOfImage);
    printf("SizeOfImage : %08X\n", parser->ntHeader64.OptionalHeader.SizeOfImage);
    unsigned int compressedCodeLength = 0;
    compress((char*) mappedFile, compressedCode, parser->ntHeader64.OptionalHeader.SizeOfImage, compressedCodeLength);

    DropCompressedExe((BYTE*)compressedCode, parser, compressedCodeLength);

    return true;
        
}

int main(int argc, char** argv) {

    if (argc < 2) {
        printf("Usage %s [FILENAME]\n", argv[0]);
        return -1;
    }

    
    HANDLE inputFile = CreateFileA(argv[1], GENERIC_READ | GENERIC_WRITE | GENERIC_EXECUTE, FILE_SHARE_READ | FILE_SHARE_WRITE, NULL, OPEN_EXISTING, FILE_ATTRIBUTE_NORMAL, NULL);
    if (inputFile == INVALID_HANDLE_VALUE) {
        printf("[-] Invalid File\n");
        return -1;
    }

    Parser peParser(inputFile);
    if (peParser.parsePE() == false ) {
        printf("[-] Error parsing file\n");
        return -1;
    }

    if (PackFile(&peParser, inputFile) == false) {
        printf("[-] Error packing file\n");
        return -1;
    }

    
    char* out;
    char* out2;
    char comp[] = "Nicoleta";
    //compress(comp, out, strlen(comp));

    return 0;
}
