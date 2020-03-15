#include "Parser.h"
#include <stdio.h>

#define MZ_HEADER 0x5A4D

#ifdef DBG
    #define dbgprintf printf
#else
    #define dbgprintf
#endif

Parser::Parser(HANDLE inputFile) {
    this->inputFile = inputFile;
}

bool Parser::parsePE() {
    if (!this->readDosHeader()) {
        return false;
    }

    if (!this->readNtHeaders()) {
        dbgprintf("[-] Error reading NTHeaders\n");
        return false;
    }

    if (!this->readSectionHeader()) {
        dbgprintf("[-] Error reading SectionHeader\n");
        return false;
    }

    return true;
}

bool Parser::readDosHeader() {

    DWORD bytesRead = 0;
    if (!ReadFile(inputFile, &dosHeader, sizeof(IMAGE_DOS_HEADER), &bytesRead, NULL)) {
        dbgprintf("[-] Error reading dosHeader\n");
        return false;
    }

    if (get_word_le(&dosHeader, 0) != MZ_HEADER) {
        dbgprintf("[-] MZ header not found\n");
        return false;
    }

    dbgprintf("[*] dosHeader read successfully\n");
    dosHeader.e_lfanew = get_dword_le(&dosHeader.e_lfanew, 0);

    dbgprintf("[+] e_lfanew : %04X\n", dosHeader.e_lfanew);

    return true;

}

bool Parser::readNtHeaders() {
    
    DWORD bytesRead = 0;
    SetFilePointer(inputFile, dosHeader.e_lfanew, NULL, FILE_BEGIN);
    if (!ReadFile(inputFile, &ntHeader32, sizeof(DWORD) + sizeof(IMAGE_FILE_HEADER), &bytesRead, NULL)) {
        dbgprintf("[-] Error reading ntHeader32\n");
        return false;
    }
    
    if (get_word_le(&ntHeader32.FileHeader.Machine, 0) == IMAGE_FILE_MACHINE_I386) {
        // dbgprintf("[*] 32bit PE\n");
        if (!ReadFile(inputFile, &ntHeader32.OptionalHeader, sizeof(IMAGE_OPTIONAL_HEADER32), &bytesRead, NULL)) {
            dbgprintf("[-] Error reading OptionalHeader 32 bit\n");
            return false;
        }
        this->ntHeader = &ntHeader32;
        dbgprintf("ImageBase : %08X\n", get_dword_le(&ntHeader32.OptionalHeader.ImageBase, 0));
        return true;
    }
    else if (get_word_le(&ntHeader32.FileHeader.Machine, 0) == IMAGE_FILE_MACHINE_AMD64) {

        memcpy(&ntHeader64, &ntHeader32, sizeof(DWORD) + sizeof(IMAGE_FILE_HEADER));
        if (!ReadFile(inputFile, &ntHeader64.OptionalHeader, sizeof(IMAGE_OPTIONAL_HEADER64), &bytesRead, NULL)) {
            dbgprintf("[-] Error reading OptionalHeader 64 bit\n");
            return false;
        }
        this->ntHeader = &ntHeader64;
        dbgprintf("SizeOfCode : %08X\n", get_dword_le(&ntHeader64.OptionalHeader.SizeOfCode, 0));
        dbgprintf("NumberOfSections : %08X\n", get_word_le(&ntHeader64.FileHeader.NumberOfSections, 0));
        dbgprintf("ImageBase : %08X\n", get_qword_le(&ntHeader64.OptionalHeader.ImageBase, 0));
        return true;
    }
    return false;
}

int Parser::getArchitecture() {
    if (get_word_le(&ntHeader32.FileHeader.Machine, 0) == IMAGE_FILE_MACHINE_I386) {
        return 0;
    }
    else if (get_word_le(&ntHeader64.FileHeader.Machine, 0) == IMAGE_FILE_MACHINE_AMD64) {
        return 1;
    }
    return -1;
}

bool Parser::readSectionHeader() {

    int arch = this->getArchitecture();
    WORD numberOfSections = 0;
    if (arch == 0) {
        numberOfSections = get_word_le(&this->ntHeader32.FileHeader.NumberOfSections, 0);
        this->sectionHeader = (IMAGE_SECTION_HEADER*) malloc(numberOfSections * sizeof(IMAGE_SECTION_HEADER));
        if (!this->sectionHeader) {
            dbgprintf("[-] error allocating sectionHeader 32bit\n");
            return false;
        }
    }
    else if (arch == 1) {
        numberOfSections = get_word_le(&this->ntHeader64.FileHeader.NumberOfSections, 0);
        this->sectionHeader = (IMAGE_SECTION_HEADER*) malloc(numberOfSections * sizeof(IMAGE_SECTION_HEADER));
        if (!this->sectionHeader) {
            dbgprintf("[-] error allocating sectionHeader 64bit\n");
            return false;
        }
    }
    else {
        return false;
    }

    DWORD bytesRead;
    for (DWORD i = 0; i < numberOfSections; i++) {
        if (!ReadFile(this->inputFile, this->sectionHeader + i, sizeof(IMAGE_SECTION_HEADER), &bytesRead, NULL)) {
            DWORD err = GetLastError();
            dbgprintf("err : %04X\n", err);
            return false;
        }
    }

    return true;

}

Parser::~Parser() {
    if (this->sectionHeader) {
        free(this->sectionHeader);
    }
}
