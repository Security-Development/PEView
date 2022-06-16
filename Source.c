#include <stdio.h>
#include <windows.h>
#include <tlhelp32.h>

HANDLE GetProcessHandle(DWORD pid) {
	HANDLE snap = CreateToolhelp32Snapshot(TH32CS_SNAPPROCESS, FALSE), result = NULL;
	PROCESSENTRY32 pe32;
	pe32.dwSize = sizeof(pe32);

	if( !Process32First(snap, &pe32) ) 
		return NULL;
		
	do{
		if( pid == pe32.th32ProcessID) {
			result = OpenProcess(PROCESS_ALL_ACCESS, FALSE, pid);
			break;
		}
	}while( Process32Next(snap, &pe32));
	
	return result;	
} 

void GetDosHeader(DWORD pid) {
	HANDLE snap = CreateToolhelp32Snapshot(TH32CS_SNAPMODULE, pid);
	MODULEENTRY32 me32;
	
	IMAGE_DOS_HEADER DOS = {0,};
	// DOS SUB 구조체는 없음 
	IMAGE_NT_HEADERS NT = {0,};
	
	me32.dwSize = sizeof(me32);
	PVOID ImageBase;
	
	if( !Module32First(snap, &me32) )
		return;
	
	ImageBase = me32.modBaseAddr;
	
	CloseHandle(snap);
	
	ReadProcessMemory( GetProcessHandle(pid), ImageBase, &DOS, sizeof(DOS), NULL);
	ReadProcessMemory(GetProcessHandle(pid), ImageBase + DOS.e_lfanew, &NT, sizeof(NT), NULL );
	
	printf("===========================================\n");
	printf("[+] DOS Signature Byte : 0x%x\n", DOS.e_magic);
	printf("[+] NT Signature Byte : 0x%x\n", NT.Signature);
	printf("[+] DOS Signature Char : %s\n", &DOS.e_magic);
	printf("[+] NT Signature Char : %s\n", &NT.Signature);
	printf("===========================================\n");
	printf("[+] DOS Header Offset : 0x00\n");
	printf("[+] DOS Stub Offset : 0x40\n");
	printf("[+] NT Header Offset : 0x%x\n", DOS.e_lfanew);
	printf("===========================================\n");
	printf("[+] DOS Header Address : 0x%x\n", ImageBase);
	printf("[+] DOS Header e_cblp : 0x%x\n", DOS.e_cblp);
	printf("[+] DOS Header e_cp : 0x%x\n", DOS.e_cp);
	printf("[+] DOS Header e_cparhdr : 0x%x\n", DOS.e_cparhdr);
	printf("[+] DOS Header e_crlc : 0x%x\n", DOS.e_crlc);
	printf("[+] DOS Header e_cs : 0x%x\n", DOS.e_cs);
	printf("[+] DOS Header e_csum : 0x%x\n", DOS.e_csum);
	printf("[+] DOS Header e_ip : 0x%x\n", DOS.e_ip);
	printf("[+] DOS Header e_lfanew : 0x%x\n", DOS.e_lfanew);
	printf("[+] DOS Header e_e_lfarlc : 0x%x\n", DOS.e_lfarlc);
	printf("[+] DOS Header e_magic : 0x%x\n", DOS.e_magic);
	printf("[+] DOS Header e_maxalloc : 0x%x\n", DOS.e_maxalloc);
	printf("[+] DOS Header e_minalloc : 0x%x\n", DOS.e_minalloc);
	printf("[+] DOS Header e_oemid : 0x%x\n", DOS.e_oemid);
	printf("[+] DOS Header e_oeminfo : 0x%x\n", DOS.e_oeminfo);
	printf("[+] DOS Header e_ovno : 0x%x\n", DOS.e_ovno);
	printf("[+] DOS Header e_res : 0x%x\n", DOS.e_res);
	printf("[+] DOS Header e_res2 : 0x%x\n", DOS.e_res2);
	printf("[+] DOS Header e_sp : 0x%x\n", DOS.e_sp);
	printf("[+] DOS Header e_ss : 0x%x\n", DOS.e_ss);
	printf("===========================================\n");
	printf("[+] DOS Stub Address : 0x%x\n", ImageBase + 0x40); // 0x40 == 64byte
	printf("===========================================\n");
	printf("[+] NT Header Address : 0x%x\n", ImageBase + DOS.e_lfanew);
	printf("[+] NT Header Address : 0x%x\n", NT.Signature);
	printf("===========================================\n");
	
}	

int main(){
	DWORD input;
	printf("[+] INPUT Process ID : ");
	scanf("%ld", &input);
	
	GetDosHeader(input);
	
	return 0;
}
