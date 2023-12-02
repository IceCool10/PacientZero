#pragma once
#include <Windows.h>
#include "util.h"


class Parser {

    public:
        IMAGE_DOS_HEADER dosHeader;
        IMAGE_NT_HEADERS32 ntHeader32;
        IMAGE_NT_HEADERS64 ntHeader64;
        void *ntHeader;
        IMAGE_SECTION_HEADER *sectionHeader;
        HANDLE inputFile;

        Parser(HANDLE inputFile);
        bool parsePE();
        int  getArchitecture();
        ~Parser();

    private:
        bool readDosHeader();
        bool readNtHeaders();
        bool readSectionHeader();
};
