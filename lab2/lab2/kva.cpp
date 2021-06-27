/******************************************************************************
Module:  InjLib.cpp
Notices: Copyright (c) 2008 Jeffrey Richter & Christophe Nasarre
******************************************************************************/

#define _CRT_SECURE_NO_WARNINGS
#include <iostream>
#include <vector>
#include "..\CommonFiles\CmnHdr.h"     /* See Appendix A. */
#include <windowsx.h>
#include <stdio.h>
#include <tchar.h>
#include <malloc.h>        // For alloca
#include <TlHelp32.h>
//#include "Resource.h"
#include <StrSafe.h>
//#include<Windows.h>
#include<tlhelp32.h>
#include<time.h>
#include<signal.h>

///////////////////////////////////////////////////////////////////////////////
CRITICAL_SECTION critical2;
CRITICAL_SECTION critical3;

volatile sig_atomic_t stop;
HANDLE hrecieverTread_real;
HANDLE ejector;
DWORD ejector_ThreadID;
BOOL WINAPI EjectLibW(DWORD dwProcessId, PCWSTR pszLibFile);
void inthand(int signum)
{
	EnterCriticalSection(&critical2);
	stop = 1;
	LeaveCriticalSection(&critical2);
}

#ifdef UNICODE
#define InjectLib InjectLibW
#define EjectLib  EjectLibW
#else
#define InjectLib InjectLibA
#define EjectLib  EjectLibA
#endif   // !UNICODE

struct Command_line_args
{
	char name_of_process[512] = "\0";
	DWORD pid = 0;
	char func_name[512] = "\0";
	char what_to_hide[512] = "\0";
	//char choose = 0;

};
struct Command_line_args Arguments;
struct Command_line_args Arguments_copy;
struct Command_line_args Arguments_copy2;


CRITICAL_SECTION critial;
DWORD dwThreadID;
HANDLE hThreadServer;
static char* GetTime()
{
	time_t rawtime;
	struct tm* timeinfo;

	time(&rawtime);
	timeinfo = localtime(&rawtime);
	//printf("Current local time and date: %s", asctime(timeinfo));

	return asctime(timeinfo);
}
void checker()
{ 
	//EnterCriticalSection(&critical2); 
	while (1)
	{     
		if (stop == 1)
		{
			//printf("Ya zdec\n");
			DWORD code = 0;
			EnterCriticalSection(&critical3);

			GetExitCodeThread(hrecieverTread_real, &code);
			if (TerminateThread(hrecieverTread_real, code))
			{
				//printf("Ya zdec2");

			}
			//while (1);
			TCHAR szLibFile[MAX_PATH];
			GetModuleFileName(NULL, szLibFile, _countof(szLibFile));
			PTSTR pFilename = _tcsrchr(szLibFile, TEXT('\\')) + 1;
			_tcscpy_s(pFilename, _countof(szLibFile) - (pFilename - szLibFile), TEXT("dl.dll"));


			//EnterCriticalSection(&critial);
			EjectLib(Arguments_copy2.pid, szLibFile);
			printf("\nDLL Injection/Ejection successful.");
			ExitProcess(0);
			//LeaveCriticalSection(&critial);



			LeaveCriticalSection(&critical3);

		}
	}
	//LeaveCriticalSection(&critical2);
}


int SendArgsThread()
{
	HANDLE hPipe;
	DWORD dwWritten;

	int k = strlen(Arguments_copy.func_name);
	PSECURITY_DESCRIPTOR psd = NULL;
	BYTE  sd[SECURITY_DESCRIPTOR_MIN_LENGTH];
	psd = (PSECURITY_DESCRIPTOR)sd;
	InitializeSecurityDescriptor(psd, SECURITY_DESCRIPTOR_REVISION);
	SetSecurityDescriptorDacl(psd, TRUE, (PACL)NULL, FALSE);
	SECURITY_ATTRIBUTES sa = { sizeof(sa), psd, FALSE };


	while (1)
	{
		Sleep(500);
		//EnterCriticalSection(&critial);
		hPipe = CreateFile(TEXT("\\\\.\\pipe\\arguments"), GENERIC_READ | GENERIC_WRITE, 0, &sa/*NULL*/, OPEN_EXISTING, 0, NULL);
		if (hPipe != INVALID_HANDLE_VALUE)
		{

			if (k/*strlen(Arguments_copy.func_name)*/)
			{
				if (WriteFile(hPipe, Arguments_copy.func_name, strlen(Arguments_copy.func_name) + 1, &dwWritten, NULL))
				{
					break;
				}
			}
			else
			{

				if (WriteFile(hPipe, Arguments_copy.what_to_hide, strlen(Arguments_copy.what_to_hide) + 1, &dwWritten, NULL))

				{
					break;
				}

			}



			CloseHandle(hPipe);
		}


	}
	return (0);
}








///////////////////////////////////////////////////////////////////////////////
void receive()
{
	InitializeCriticalSection(&critical2);
	InitializeCriticalSection(&critical3);

	EnterCriticalSection(&critical2);
	stop = 0;
	LeaveCriticalSection(&critical2);
	HANDLE  hrecieverTread_psevdo = GetCurrentThread();
	EnterCriticalSection(&critical3);
	DuplicateHandle(GetCurrentProcess(),       /* source handle process*/
		hrecieverTread_psevdo,            /* handle to duplicate*/
		GetCurrentProcess(),       /* target process handle*/
		&hrecieverTread_real,               /* duplicate handle*/
		(DWORD)0,                  /* requested access*/
		FALSE,                     /* handle inheritance*/
		DUPLICATE_SAME_ACCESS);   /* optional actions*/
	LeaveCriticalSection(&critical3);

	ejector = chBEGINTHREADEX(NULL, 0, checker, NULL,
		0, &ejector_ThreadID);



	HANDLE hPipe;
	char buffer[1024] = "\0";
	char timed_buffer[2048] = "\0";
	DWORD dwRead;
	PSECURITY_DESCRIPTOR psd = NULL;
	BYTE  sd[SECURITY_DESCRIPTOR_MIN_LENGTH];
	psd = (PSECURITY_DESCRIPTOR)sd;
	InitializeSecurityDescriptor(psd, SECURITY_DESCRIPTOR_REVISION);
	SetSecurityDescriptorDacl(psd, TRUE, (PACL)NULL, FALSE);
	SECURITY_ATTRIBUTES sa = { sizeof(sa), psd, FALSE };

	hPipe = CreateNamedPipe(TEXT("\\\\.\\pipe\\lab2"),
		PIPE_ACCESS_DUPLEX,
		PIPE_TYPE_BYTE | PIPE_READMODE_BYTE | PIPE_WAIT,   // FILE_FLAG_FIRST_PIPE_INSTANCE is not needed but forces CreateNamedPipe(..) to fail if the pipe already exists...
		1,
		1024 * 16,
		1024 * 16,
		NMPWAIT_USE_DEFAULT_WAIT,
		&sa);
	printf("\nNew instanse arrived. Press CTRL-C to stop receiving messages and eject dll:\n\n");



	while (hPipe != INVALID_HANDLE_VALUE)
	{


		if (ConnectNamedPipe(hPipe, NULL) != FALSE)   // wait for someone to connect to the pipe
		{

			while (ReadFile(hPipe, buffer, sizeof(buffer) - 1, &dwRead, NULL) != FALSE)
			{

				/* add terminating zero */
				buffer[dwRead] = '\0';
				sprintf(timed_buffer, "%s", GetTime());
				timed_buffer[strlen(timed_buffer) - 1] = '\0';
				strcat(timed_buffer, " ");
				strcat(timed_buffer, buffer);
				//sprintf(timed_buffer, "%s " "%s\n", GetTime(),buffer);
				/* do something with data in buffer */
				printf("%s\n\n", timed_buffer);

			}
		}


		DisconnectNamedPipe(hPipe);
	}



}




///////////////////////////////////////////////////////////////////////////////


BOOL WINAPI InjectLibW(DWORD dwProcessId, PCWSTR pszLibFile) {

	BOOL bOk = FALSE; // Assume that the function fails
	HANDLE hProcess = NULL, hThread = NULL;
	PWSTR pszLibFileRemote = NULL;

	__try {
		// Get a handle for the target process.
		hProcess = OpenProcess(
			PROCESS_QUERY_INFORMATION |   // Required by Alpha
			PROCESS_CREATE_THREAD |   // For CreateRemoteThread
			PROCESS_VM_OPERATION |   // For VirtualAllocEx/VirtualFreeEx
			PROCESS_VM_WRITE,             // For WriteProcessMemory
			FALSE, dwProcessId);
		if (hProcess == NULL) __leave;

		// Calculate the number of bytes needed for the DLL's pathname
		int cch = 1 + lstrlenW(pszLibFile);
		int cb = cch * sizeof(wchar_t);

		// Allocate space in the remote process for the pathname
		pszLibFileRemote = (PWSTR)
			VirtualAllocEx(hProcess, NULL, cb, MEM_COMMIT, PAGE_READWRITE);
		if (pszLibFileRemote == NULL) __leave;

		// Copy the DLL's pathname to the remote process' address space
		if (!WriteProcessMemory(hProcess, pszLibFileRemote,
			(PVOID)pszLibFile, cb, NULL)) __leave;

		// Get the real address of LoadLibraryW in Kernel32.dll
		PTHREAD_START_ROUTINE pfnThreadRtn = (PTHREAD_START_ROUTINE)
			GetProcAddress(GetModuleHandle(TEXT("Kernel32")), "LoadLibraryW");
		if (pfnThreadRtn == NULL) __leave;

		// Create a remote thread that calls LoadLibraryW(DLLPathname)
		hThread = CreateRemoteThread(hProcess, NULL, 0,
			pfnThreadRtn, pszLibFileRemote, 0, NULL);
		if (hThread == NULL) __leave;


		WaitForSingleObject(hThreadServer, INFINITE);
		DeleteCriticalSection(&critial);
		// Wait for the remote thread to terminate
		WaitForSingleObject(hThread, INFINITE);

		bOk = TRUE; // Everything executed successfully
	}
	__finally { // Now, we can clean everything up

	   // Free the remote memory that contained the DLL's pathname
		if (pszLibFileRemote != NULL)
			VirtualFreeEx(hProcess, pszLibFileRemote, 0, MEM_RELEASE);

		if (hThread != NULL)
			CloseHandle(hThread);

		if (hProcess != NULL)
			CloseHandle(hProcess);
	}

	return(bOk);
}


///////////////////////////////////////////////////////////////////////////////


BOOL WINAPI InjectLibA(DWORD dwProcessId, PCSTR pszLibFile) {

	// Allocate a (stack) buffer for the Unicode version of the pathname
	SIZE_T cchSize = lstrlenA(pszLibFile) + 1;
	PWSTR pszLibFileW = (PWSTR)
		_alloca(cchSize * sizeof(wchar_t));

	// Convert the ANSI pathname to its Unicode equivalent
	StringCchPrintfW(pszLibFileW, cchSize, L"%S", pszLibFile);

	// Call the Unicode version of the function to actually do the work.
	return(InjectLibW(dwProcessId, pszLibFileW));
}


///////////////////////////////////////////////////////////////////////////////


BOOL WINAPI EjectLibW(DWORD dwProcessId, PCWSTR pszLibFile) {

	BOOL bOk = FALSE; // Assume that the function fails
	HANDLE hthSnapshot = NULL;
	HANDLE hProcess = NULL, hThread = NULL;

	__try {
		// Grab a new snapshot of the process
		hthSnapshot = CreateToolhelp32Snapshot(TH32CS_SNAPMODULE, dwProcessId);
		if (hthSnapshot == INVALID_HANDLE_VALUE) __leave;

		// Get the HMODULE of the desired library
		MODULEENTRY32W me = { sizeof(me) };
		BOOL bFound = FALSE;
		BOOL bMoreMods = Module32FirstW(hthSnapshot, &me);
		for (; bMoreMods; bMoreMods = Module32NextW(hthSnapshot, &me)) {
			bFound = (_wcsicmp(me.szModule, pszLibFile) == 0) ||
				(_wcsicmp(me.szExePath, pszLibFile) == 0);
			if (bFound) break;
		}
		if (!bFound) __leave;

		// Get a handle for the target process.
		hProcess = OpenProcess(
			PROCESS_QUERY_INFORMATION |
			PROCESS_CREATE_THREAD |
			PROCESS_VM_OPERATION,  // For CreateRemoteThread
			FALSE, dwProcessId);
		if (hProcess == NULL) __leave;

		// Get the real address of FreeLibrary in Kernel32.dll
		PTHREAD_START_ROUTINE pfnThreadRtn = (PTHREAD_START_ROUTINE)
			GetProcAddress(GetModuleHandle(TEXT("Kernel32")), "FreeLibrary");
		if (pfnThreadRtn == NULL) __leave;

		// Create a remote thread that calls FreeLibrary()
		hThread = CreateRemoteThread(hProcess, NULL, 0,
			pfnThreadRtn, me.modBaseAddr, 0, NULL);
		if (hThread == NULL) __leave;

		// Wait for the remote thread to terminate
		WaitForSingleObject(hThread, INFINITE);

		bOk = TRUE; // Everything executed successfully
	}
	__finally { // Now we can clean everything up

		if (hthSnapshot != NULL)
			CloseHandle(hthSnapshot);

		if (hThread != NULL)
			CloseHandle(hThread);

		if (hProcess != NULL)
			CloseHandle(hProcess);
	}

	return(bOk);
}


///////////////////////////////////////////////////////////////////////////////


BOOL WINAPI EjectLibA(DWORD dwProcessId, PCSTR pszLibFile) {

	// Allocate a (stack) buffer for the Unicode version of the pathname
	SIZE_T cchSize = lstrlenA(pszLibFile) + 1;
	PWSTR pszLibFileW = (PWSTR)
		_alloca(cchSize * sizeof(wchar_t));

	// Convert the ANSI pathname to its Unicode equivalent
	StringCchPrintfW(pszLibFileW, cchSize, L"%S", pszLibFile);

	// Call the Unicode version of the function to actually do the work.
	return(EjectLibW(dwProcessId, pszLibFileW));
}


///////////////////////////////////////////////////////////////////////////////





///////////////////////////////////////////////////////////////////////////////


void Dlg_OnCommand()
{

	EnterCriticalSection(&critial);
	DWORD dwProcessId = Arguments.pid;//GetDlgItemInt(hWnd, IDC_PROCESSID, NULL, FALSE);
	LeaveCriticalSection(&critial);

	//if (dwProcessId == 0) {
	//	// A process ID of 0 causes everything to take place in the 
	//	// local process; this makes things easier for debugging.
	//	dwProcessId = GetCurrentProcessId();
	//}

	TCHAR szLibFile[MAX_PATH];
	GetModuleFileName(NULL, szLibFile, _countof(szLibFile));
	PTSTR pFilename = _tcsrchr(szLibFile, TEXT('\\')) + 1;
	_tcscpy_s(pFilename, _countof(szLibFile) - (pFilename - szLibFile),
		TEXT("dl.dll"));
	if (InjectLib(dwProcessId, szLibFile))
	{
		//send_arguments(Arguments);
		receive();
		//chVERIFY(EjectLib(dwProcessId, szLibFile));
		EjectLib(dwProcessId, szLibFile);
		//chMB("DLL Injection/Ejection successful.");
		printf("DLL Injection/Ejection successful.");
	}
	else {
		//chMB("DLL Injection/Ejection failed.");
		printf("DLL Injection/Ejection failed.");
	}

}


///////////////////////////////////////////////////////////////////////////////
void parse_args(int amount_of_arguments, char** arguments)
{
	if (amount_of_arguments == 5)
	{
		for (int i = 1; i < amount_of_arguments; i++)
		{
			if (!(strcmp(arguments[i], "-pid")))
			{
				i = i + 1;
				EnterCriticalSection(&critial);
				Arguments.pid = atoi(arguments[i]);
				LeaveCriticalSection(&critial);
			}
			if (!(strcmp(arguments[i], "-func")))
			{
				i++;
				EnterCriticalSection(&critial);
				sprintf(Arguments.func_name, "%s", arguments[i]);
				LeaveCriticalSection(&critial);

			}
			if (!(strcmp(arguments[i], "-hide")))
			{
				i++;
				EnterCriticalSection(&critial);
				sprintf(Arguments.what_to_hide, "%s", arguments[i]);
				LeaveCriticalSection(&critial);

			}
			if (!(strcmp(arguments[i], "-name")))//name of .exe
			{
				i++;
				//if (!(strcmp(arguments[i], ".exe")))
				//{
				EnterCriticalSection(&critial);

				sprintf(Arguments.name_of_process, "%s", arguments[i]);
				LeaveCriticalSection(&critial);

				//}
			}

		}


	}
	else
	{
		fprintf(stderr, "Invalid arguments");
	}

}
int get_pid_by_name(const char* name_of_process)
{


	std::vector<DWORD> pids;
	std::string targetProcessName1(name_of_process);

	int wchars_num = MultiByteToWideChar(CP_UTF8, 0, targetProcessName1.c_str(), -1, NULL, 0);
	wchar_t* wstr = new wchar_t[wchars_num];
	MultiByteToWideChar(CP_UTF8, 0, targetProcessName1.c_str(), -1, wstr, wchars_num);
	// do whatever with wstr
	std::wstring targetProcessName = wstr;


	HANDLE snap = CreateToolhelp32Snapshot(TH32CS_SNAPPROCESS, 0); //all processes

	PROCESSENTRY32 entry; //current process
	entry.dwSize = sizeof entry;

	if (!Process32First(snap, &entry)) { //start with the first in snapshot
		return 0;
	}

	do {
		if (std::wstring(entry.szExeFile) == targetProcessName) {
			pids.emplace_back(entry.th32ProcessID); //name matches; add to list
		}
	} while (Process32Next(snap, &entry)); //keep going until end of snapshot

	/*for (int i(0); i < pids.size(); ++i) {
		std::cout << pids[i] << std::endl;
	}*/

	return pids[0];

}


///////////////////////////////////////////////////////////////////////////////


int  main(int argc, char** argv)
{
	signal(SIGINT, inthand);

	InitializeCriticalSection(&critial);
	//struct Command_line_args Arguments;

	parse_args(argc, argv);


	EnterCriticalSection(&critial);
	if (Arguments.pid == 0 && strlen(Arguments.name_of_process) != 0)
	{

		Arguments.pid = get_pid_by_name(Arguments.name_of_process);

	}

	if (strlen(Arguments.func_name) != 0)
	{
		//Arguments.choose = 'f';
		strcat(Arguments.func_name, " f");// sign of function
	}
	if (strlen(Arguments.what_to_hide) != 0)
	{
		//Arguments.choose = 'h';
		strcat(Arguments.what_to_hide, " h");
	}
	Arguments_copy = Arguments;
	Arguments_copy2 = Arguments;
	LeaveCriticalSection(&critial);



	hThreadServer = chBEGINTHREADEX(NULL, 0, SendArgsThread, NULL,
		0, &dwThreadID);
	auto k = GetLastError();



	Dlg_OnCommand();//исправить параметр 

	return(0);
}


//////////////////////////////// End of File //////////////////////////////////
