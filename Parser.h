#pragma once
#include <Windows.h>

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
