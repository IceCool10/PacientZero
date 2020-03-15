#include <Windows.h>
#include <stdint.h>
#include "aplib/lib/coff/aplib.h"
#include <stdio.h>
#include <string.h>
#include "util.h"

//#define DBG

#ifdef DBG
    #define dbgprintf printf
#else
    #define dbgprintf
#endif

int callback(unsigned int insize, unsigned int inpos,
                         unsigned int outpos, void *cbparam)
{
	(void) cbparam;

	dbgprintf("\rcompressed %u -> %u bytes\n", inpos, outpos);

	return 1;
}
VOID FixImageIAT( PIMAGE_DOS_HEADER dos_header, PIMAGE_NT_HEADERS nt_header)
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
    dbgprintf("berofre virtual  protect\n");
    VirtualProtect(iat, iat_size, PAGE_READWRITE, &op);
    dbgprintf("After virtual protect\n");
        while (import_table->Name) {
            import_base = LoadLibraryA((LPCSTR)(import_table->Name + (UINT_PTR)dos_header));
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
                    fixup->u1.Function = (UINT_PTR)GetProcAddress(import_base, func_name);
                }
                fixup++;
                thunk++;
            }
            import_table++;
        }

    return;
}

HANDLE GetImageActCtx(HMODULE module)
{
    CHAR temp_path[MAX_PATH];
    CHAR temp_filename[MAX_PATH];
    for (int i = 1; i <= 3; i++) {
        HRSRC resource_info = FindResource(module, MAKEINTRESOURCE(i), RT_MANIFEST); 
        if (resource_info) {
            HGLOBAL resource = LoadResource(module, resource_info);
            DWORD resource_size = SizeofResource(module, resource_info);
            const PBYTE resource_data = (const PBYTE)LockResource(resource);
            if (resource_data && resource_size) {
                FILE *fp;
                errno_t err;
                DWORD ret_val = GetTempPath(MAX_PATH, temp_path);  

                if (0 == GetTempFileName(temp_path, "manifest.tmp", 0, temp_filename))  
                    return NULL;

                err = fopen_s(&fp, temp_filename, "w");

                if (errno) 
                    return NULL;

                fclose(fp);
                break;
            } else { 
                return NULL;
            }
        } 
    }

    ACTCTXA act = { sizeof(act) };
    act.lpSource = temp_filename;
    return CreateActCtx(&act);
}

BOOL FixImageRelocations(PIMAGE_DOS_HEADER dos_header, PIMAGE_NT_HEADERS nt_header, ULONG_PTR delta)
{
    ULONG_PTR size;
    PULONG_PTR intruction;
    PIMAGE_BASE_RELOCATION reloc_block =
        (PIMAGE_BASE_RELOCATION)(nt_header->OptionalHeader.DataDirectory[IMAGE_DIRECTORY_ENTRY_BASERELOC].VirtualAddress +
            (UINT_PTR)dos_header);

    while (reloc_block->VirtualAddress) {
        size = (reloc_block->SizeOfBlock - sizeof(reloc_block)) / sizeof(WORD);
        PWORD fixup = (PWORD)((ULONG_PTR)reloc_block + sizeof(reloc_block));
        for (int i = 0; i < size; i++, fixup++) {
            if (IMAGE_REL_BASED_DIR64 == (*fixup >> 12)) {
                intruction = (PULONG_PTR)(reloc_block->VirtualAddress + (ULONG_PTR)dos_header + (*fixup & 0xfff));
                *intruction += delta;
            } 
        }
        reloc_block = (PIMAGE_BASE_RELOCATION)(reloc_block->SizeOfBlock + (ULONG_PTR)reloc_block);
    }
    return TRUE;
}

int decompress(char *packed, char *data, unsigned depackedsize, unsigned int inputSize)
{
	unsigned int insize, outsize;

    insize = inputSize;

	/* decompress data */
	outsize = aPsafe_depack(packed, insize, data, depackedsize);


	/* check for decompression error */
	return 0;
}

uint32_t rotr32 (uint32_t n, unsigned int c) {   
    const unsigned int mask = (CHAR_BIT*sizeof(n) - 1);    
    c &= mask;   
    return (n>>c) | (n<<( (-c)&mask )); 
}

int compress( char *input,  char *packed, unsigned int insize, unsigned int &outsize) {
    
	char *workmem;

    //insize = strlen(input);

	/* allocate memory */
	if ((workmem = (char *) malloc(aP_workmem_size(insize))) == NULL) {
		dbgprintf("\nERR: not enough memory\n");
		return 1;
	}

	/* compress packed block */
	outsize = aPsafe_pack(input, packed, insize, workmem, callback, NULL);


	/* check for compression error */
	if (outsize == APLIB_ERROR) {
		dbgprintf("\nERR: an error occured while compressing\n");
		return 1;
	}

    /*
    dbgprintf("Compressed packed:\n");
    for (DWORD i = 0; i < outsize; i++) {
        dbgprintf("%c", packed[i]);
    }
    */

    //decompress(packed, dec, outsize);
	/* free memory */
	free(workmem);
	return 0;
}

