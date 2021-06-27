//////////////////////////////////////////////////////////////////////////////
//
//  Detours Test Program (simple.cpp of simple.dll)
//
//  Microsoft Research Detours Package
//
//  Copyright (c) Microsoft Corporation.  All rights reserved.
//
//  This DLL will detour the Windows SleepEx API so that TimedSleep function
//  gets called instead.  TimedSleepEx records the before and after times, and
//  calls the real SleepEx API through the TrueSleepEx function pointer.
//
#define _CRT_SECURE_NO_WARNINGS
#include <stdio.h>
#include <windows.h>
#include "../Detours-master/include/detours.h"
#include<string.h>
#include<wchar.h>
#include <comdef.h>  // you will need this

static struct cmd_arguments
{
	BOOL func_or_hide = 0;//0 - func and 1 is for hide
	char str_arg[256] = "\0";
};
static cmd_arguments ARGS;
static int k = 0;
static char a[256];
bool check(char* s, char* p)
{
	char* rs = 0, * rp = 0;
	while (1)
		if (*p == '*')
			rs = s, rp = ++p;
		else if (!*s)
			return !*p;
		else if (*s == *p || *p == '?')
			++s, ++p;
		else if (rs)
			s = ++rs, p = rp;
		else
			return false;
}
void recieve_arguments()
{
	HANDLE hPipe;
	char buffer[1024];
	DWORD dwRead;
	PSECURITY_DESCRIPTOR psd = NULL;
	BYTE  sd[SECURITY_DESCRIPTOR_MIN_LENGTH];
	psd = (PSECURITY_DESCRIPTOR)sd;
	InitializeSecurityDescriptor(psd, SECURITY_DESCRIPTOR_REVISION);
	SetSecurityDescriptorDacl(psd, TRUE, (PACL)NULL, FALSE);
	SECURITY_ATTRIBUTES sa = { sizeof(sa), psd, FALSE };

	hPipe = CreateNamedPipe(TEXT("\\\\.\\pipe\\arguments"), PIPE_ACCESS_DUPLEX, PIPE_TYPE_BYTE | PIPE_READMODE_BYTE | PIPE_WAIT, 1, 1024 * 16, 1024 * 16, NMPWAIT_USE_DEFAULT_WAIT, &sa);
	while (hPipe != INVALID_HANDLE_VALUE)
	{

		if (ConnectNamedPipe(hPipe, NULL) != FALSE)   // wait for someone to connect to the pipe
		{
			while (ReadFile(hPipe, buffer, sizeof(buffer) - 1, &dwRead, NULL) != FALSE)
			{
				/* add terminating zero */
				buffer[dwRead] = '\0';

				/* do something with data in buffer */
				//printf("%s\n", buffer);
				if (strlen(buffer))
				{
					OutputDebugString("Here i am\n");
					OutputDebugString(buffer);
					char* forstr;

					forstr = strtok(buffer, " ");//строку на несколько подстрок
					while (forstr)
					{
						if (strlen(ARGS.str_arg) == 0)
						{
							sprintf(ARGS.str_arg, "%s", forstr);
						}
						if (!strcmp(forstr, "f"))
						{
							ARGS.func_or_hide = 0;//function
						}
						if (!strcmp(forstr, "h"))
						{
							ARGS.func_or_hide = 1;//hiding
						}
						forstr = strtok(NULL, " ");
					}
					//OutputDebugString("Here i am TWICE \n");
					//OutputDebugString(a);

					return;
				}
			}
		}

		DisconnectNamedPipe(hPipe);
	}

	return;
}







void send(const char* string)
{
	HANDLE hPipe = NULL;
	DWORD dwWritten;

	if (!strcmp(ARGS.str_arg, string) && ARGS.func_or_hide == 0)
	{


		hPipe = CreateFileA(TEXT("\\\\.\\pipe\\lab2"), GENERIC_READ | GENERIC_WRITE, 0, NULL, OPEN_EXISTING, 0, NULL);
		if (hPipe != INVALID_HANDLE_VALUE)
		{
			WriteFile(hPipe,
				string,
				strlen(string) + 1,   // = length of string + terminating '\0' !!!
				&dwWritten,
				NULL);

			CloseHandle(hPipe);
		}

	}
	if (ARGS.func_or_hide == 1 && (strstr(string, "blocked")))
	{
		hPipe = CreateFileA(TEXT("\\\\.\\pipe\\lab2"), GENERIC_READ | GENERIC_WRITE, 0, NULL, OPEN_EXISTING, 0, NULL);
		if (hPipe != INVALID_HANDLE_VALUE)
		{
			WriteFile(hPipe,
				string,
				strlen(string) + 1,   // = length of string + terminating '\0' !!!
				&dwWritten,
				NULL);

			CloseHandle(hPipe);
		}

	}

}


BOOL(__stdcall* Real_CloseHandle)(HANDLE a0) = CloseHandle;
HANDLE(__stdcall* Real_CreateFileW)(LPCWSTR a0, DWORD a1, DWORD a2, LPSECURITY_ATTRIBUTES a3, DWORD a4, DWORD a5, HANDLE a6) = CreateFileW;
BOOL(__stdcall* Real_WriteFile)(HANDLE a0, LPCVOID a1, DWORD a2, LPDWORD a3, LPOVERLAPPED a4) = WriteFile;
BOOL(__stdcall* Real_FlushFileBuffers)(HANDLE a0) = FlushFileBuffers;
BOOL(__stdcall* Real_WaitNamedPipeW)(LPCWSTR a0, DWORD a1) = WaitNamedPipeW;
BOOL(__stdcall* Real_SetNamedPipeHandleState)(HANDLE a0, LPDWORD a1, LPDWORD a2, LPDWORD a3) = SetNamedPipeHandleState;
DWORD(__stdcall* Real_GetCurrentProcessId)(void) = GetCurrentProcessId;
void(__stdcall* Real_GetSystemTimeAsFileTime)(LPFILETIME a0) = GetSystemTimeAsFileTime;
DWORD(__stdcall* Real_GetModuleFileNameW)(HMODULE a0, LPWSTR a1, DWORD a2) = GetModuleFileNameW;
#undef GetEnvironmentStrings
LPSTR(__stdcall* Real_GetEnvironmentStrings)(void) = GetEnvironmentStrings;
DWORD(WINAPI* Real_SleepEx)(DWORD dwMilliseconds, BOOL bAlertable) = SleepEx;
BOOL(__stdcall* Real_AppendMenuA)(HMENU a0, UINT a1, UINT_PTR a2, LPCSTR a3) = AppendMenuA;
BOOL(__stdcall* Real_AppendMenuW)(HMENU a0, UINT a1, UINT_PTR a2, LPCWSTR a3) = AppendMenuW;
//HANDLE(__stdcall * Real_CreateFileA)(LPCSTR a0, DWORD a1, DWORD a2, LPSECURITY_ATTRIBUTES a3, DWORD a4, DWORD a5, HANDLE a6) = CreateFileA;
BOOL(__stdcall* Real_CloseWindow)(HWND a0) = CloseWindow;
HANDLE(__stdcall* Real_FindFirstFileA)(LPCSTR a0, LPWIN32_FIND_DATAA a1) = FindFirstFileA;
HANDLE(__stdcall* Real_FindFirstFileExA)(LPCSTR a0, FINDEX_INFO_LEVELS a1, LPVOID a2, FINDEX_SEARCH_OPS a3, LPVOID a4, DWORD a5) = FindFirstFileExA;
HANDLE(__stdcall* Real_FindFirstFileExW)(LPCWSTR a0, FINDEX_INFO_LEVELS a1, LPVOID a2, FINDEX_SEARCH_OPS a3, LPVOID a4, DWORD a5) = FindFirstFileExW;
HANDLE(__stdcall* Real_FindFirstFileW)(LPCWSTR a0, LPWIN32_FIND_DATAW a1) = FindFirstFileW;
BOOL(__stdcall* Real_FindNextFileA)(HANDLE a0, LPWIN32_FIND_DATAA a1) = FindNextFileA;
BOOL(__stdcall* Real_FindNextFileW)(HANDLE a0, LPWIN32_FIND_DATAW a1) = FindNextFileW;


DWORD WINAPI Mine_SleepEx(DWORD dwMilliseconds, BOOL bAlertable)
{

	send("SleepEx");
	DWORD ret = Real_SleepEx(dwMilliseconds, bAlertable);


	return ret;
}
BOOL __stdcall Mine_CloseHandle(HANDLE a0)
{

	send("CloseHandle");

	BOOL rv = 0;
	rv = Real_CloseHandle(a0);

	return rv;
}

HANDLE __stdcall Mine_CreateFileW(LPCWSTR a0,
	DWORD a1,
	DWORD a2,
	LPSECURITY_ATTRIBUTES a3,
	DWORD a4,
	DWORD a5,
	HANDLE a6)
{
	if (ARGS.func_or_hide == 1)
	{
		return INVALID_HANDLE_VALUE;
	}
	//while (1);
	send("CreateFileW");
	//return 0;


	HANDLE rv = 0;

	rv = Real_CreateFileW(a0, a1, a2, a3, a4, a5, a6);

	return rv;
}
BOOL __stdcall Mine_WriteFile(HANDLE a0,
	LPCVOID a1,
	DWORD a2,
	LPDWORD a3,
	LPOVERLAPPED a4)
{
	send("WriteFile");

	BOOL rv = 0;

	rv = Real_WriteFile(a0, a1, a2, a3, a4);

	return rv;
}

BOOL __stdcall Mine_FlushFileBuffers(HANDLE a0)
{
	send("FlushFileBuffers");

	BOOL rv = 0;

	rv = Real_FlushFileBuffers(a0);

	return rv;
}
BOOL __stdcall Mine_WaitNamedPipeW(LPCWSTR a0,
	DWORD a1)
{

	send("WaitNamedPipeW");
	BOOL rv = 0;

	rv = Real_WaitNamedPipeW(a0, a1);

	return rv;
}
BOOL __stdcall Mine_SetNamedPipeHandleState(HANDLE a0,
	LPDWORD a1,
	LPDWORD a2,
	LPDWORD a3)
{

	send("SetNamedPipeHandleState");

	BOOL rv = 0;

	rv = Real_SetNamedPipeHandleState(a0, a1, a2, a3);

	return rv;
}
DWORD __stdcall Mine_GetCurrentProcessId(void)
{
	send("GetCurrentProcessId");
	DWORD rv = 0;

	rv = Real_GetCurrentProcessId();

	return rv;
}
void __stdcall Mine_GetSystemTimeAsFileTime(LPFILETIME a0)
{
	send("GetSystemTimeAsFileTime");

	Real_GetSystemTimeAsFileTime(a0);
}
DWORD __stdcall Mine_GetModuleFileNameW(HMODULE a0,
	LPWSTR a1,
	DWORD a2)
{
	send("GetModuleFileNameW");
	DWORD rv = 0;

	rv = Real_GetModuleFileNameW(a0, a1, a2);

	return rv;
}
LPSTR __stdcall Mine_GetEnvironmentStrings(void)
{
	send("GetEnvironmentStrings");
	LPSTR rv = 0;

	rv = Real_GetEnvironmentStrings();

	return rv;
}
BOOL __stdcall Mine_AppendMenuA(HMENU a0, UINT a1, UINT_PTR a2, LPCSTR a3)
{

	send("AppendMenuA");
	BOOL rv = 0;

	rv = Real_AppendMenuA(a0, a1, a2, a3);

	return rv;
}

BOOL __stdcall Mine_AppendMenuW(HMENU a0, UINT a1, UINT_PTR a2, LPCWSTR a3)
{
	send("AppendMenuW");

	BOOL rv = 0;

	rv = Real_AppendMenuW(a0, a1, a2, a3);

	return rv;
}
//HANDLE __stdcall Mine_CreateFileA(LPCSTR a0, DWORD a1, DWORD a2, LPSECURITY_ATTRIBUTES a3, DWORD a4, DWORD a5, HANDLE a6)
//{
//	/*if (ARGS.func_or_hide == 1)
//	{
//		return INVALID_HANDLE_VALUE;
//	}*/
//	send("CreateFileA");
//	HANDLE rv = 0;
//
//	rv = Real_CreateFileA(a0, a1, a2, a3, a4, a5, a6);
//
//	return rv;
//}
BOOL __stdcall Mine_CloseWindow(HWND a0)
{
	send("CloseWindow");
	BOOL rv = 0;

	rv = Real_CloseWindow(a0);

	return rv;
}
HANDLE __stdcall Mine_FindFirstFileA(LPCSTR a0, LPWIN32_FIND_DATAA a1)
{
	send("FindFirstFileA");
	HANDLE rv = 0;

	rv = Real_FindFirstFileA(a0, a1);


	return rv;
}
HANDLE __stdcall Mine_FindFirstFileExA(LPCSTR a0, FINDEX_INFO_LEVELS a1, LPVOID a2, FINDEX_SEARCH_OPS a3, LPVOID a4, DWORD a5)
{
	send("FindFirstFileExA");
	HANDLE rv = 0;

	rv = Real_FindFirstFileExA(a0, a1, a2, a3, a4, a5);

	return rv;
}
HANDLE __stdcall Mine_FindFirstFileExW(LPCWSTR a0, FINDEX_INFO_LEVELS a1, LPVOID a2, FINDEX_SEARCH_OPS a3, LPVOID a4, DWORD a5)
{
	//while (1);
	if (ARGS.func_or_hide == 1)
	{


		const wchar_t* k = wcsrchr(a0, L'\\');
		k++;
		_bstr_t b(k);
		char* c = b;
		if (strcmp(c, "*") && ARGS.func_or_hide == 1 && check(ARGS.str_arg, c))
		{
			//send("FindFirstFileExW blocked");
			send("blocked");
			return INVALID_HANDLE_VALUE;
		}
		else
		{
			send("FindFirstFileExW");
			HANDLE rv = 0;
			rv = Real_FindFirstFileExW(a0, a1, a2, a3, a4, a5);
			return rv;
		}
	}  
	else     
	{
		send("FindFirstFileExW");
		HANDLE rv = 0;
		rv = Real_FindFirstFileExW(a0, a1, a2, a3, a4, a5); 
		return rv;
	}


}
HANDLE __stdcall Mine_FindFirstFileW(LPCWSTR a0, LPWIN32_FIND_DATAW a1)
{
	send("FindFirstFileW");
	HANDLE rv = 0;

	rv = Real_FindFirstFileW(a0, a1);
	return rv;
}
BOOL __stdcall Mine_FindNextFileA(HANDLE a0, LPWIN32_FIND_DATAA a1)
{
	send("FindNextFileA");
	BOOL rv = 0;

	rv = Real_FindNextFileA(a0, a1);

	return rv;
}
BOOL __stdcall Mine_FindNextFileW(HANDLE a0, LPWIN32_FIND_DATAW a1)
{
	if (ARGS.func_or_hide == 1 && a0 == INVALID_HANDLE_VALUE)
	{
		//send("FindNextFileW blocked");
		send("blocked");
		return 0;
	}
	else
	{
		send("FindNextFileW");
		BOOL rv = 0;

		rv = Real_FindNextFileW(a0, a1);

		return rv;
	}

}




VOID DetAttach(PVOID* ppvReal, PVOID pvMine, const char* psz)
{
	PVOID pvReal = NULL;
	if (ppvReal == NULL) {
		ppvReal = &pvReal;
	}

	LONG l = DetourAttach(ppvReal, pvMine);

}

VOID DetDetach(PVOID* ppvReal, PVOID pvMine, const char* psz)
{
	LONG l = DetourDetach(ppvReal, pvMine);

}

#define ATTACH(x)       DetAttach(&(PVOID&)Real_##x,Mine_##x,#x)
#define DETACH(x)       DetDetach(&(PVOID&)Real_##x,Mine_##x,#x)

LONG AttachDetours(VOID)
{
	recieve_arguments();
	DetourTransactionBegin();
	DetourUpdateThread(GetCurrentThread());

	// For this many APIs, we'll ignore one or two can't be detoured.
	DetourSetIgnoreTooSmall(TRUE);
	ATTACH(CloseHandle);
	ATTACH(CreateFileW);
	ATTACH(WriteFile);
	ATTACH(FlushFileBuffers);
	ATTACH(WaitNamedPipeW);
	ATTACH(SetNamedPipeHandleState);
	ATTACH(GetCurrentProcessId);
	ATTACH(GetSystemTimeAsFileTime);
	ATTACH(GetModuleFileNameW);
	ATTACH(GetEnvironmentStrings);
	ATTACH(SleepEx);
	ATTACH(AppendMenuA);
	ATTACH(AppendMenuW);
	//ATTACH(CreateFileA);
	ATTACH(CloseWindow);
	ATTACH(FindFirstFileA);
	ATTACH(FindFirstFileExA);
	ATTACH(FindFirstFileExW);
	ATTACH(FindFirstFileW);
	ATTACH(FindNextFileA);
	ATTACH(FindNextFileW);

	PVOID* ppbFailedPointer = NULL;
	LONG error = DetourTransactionCommitEx(&ppbFailedPointer);
	if (error != 0) {
		printf("\ndl.dll: Attach transaction failed to commit. Error %d (%p/%p)",
			error, ppbFailedPointer, *ppbFailedPointer);
		return error;
	}
	return 1;
}
LONG DetachDetours(VOID)
{
	DetourTransactionBegin();
	DetourUpdateThread(GetCurrentThread());

	// For this many APIs, we'll ignore one or two can't be detoured.
	DetourSetIgnoreTooSmall(TRUE);
	DETACH(CloseHandle);
	DETACH(CreateFileW);
	DETACH(WriteFile);
	DETACH(FlushFileBuffers);
	DETACH(WaitNamedPipeW);
	DETACH(SetNamedPipeHandleState);
	DETACH(GetCurrentProcessId);
	DETACH(GetSystemTimeAsFileTime);
	DETACH(GetModuleFileNameW);
	DETACH(GetEnvironmentStrings);
	DETACH(SleepEx);
	DETACH(AppendMenuA);
	DETACH(AppendMenuW);
	//DETACH(CreateFileA);
	DETACH(CloseWindow);
	DETACH(FindFirstFileA);
	DETACH(FindFirstFileExA);
	DETACH(FindFirstFileExW);
	DETACH(FindFirstFileW);
	DETACH(FindNextFileA);
	DETACH(FindNextFileW);

	if (DetourTransactionCommit() != 0) {
		PVOID* ppbFailedPointer = NULL;
		LONG error = DetourTransactionCommitEx(&ppbFailedPointer);

		printf("dl.dll: Detach transaction failed to commit. Error %d (%p/%p)",
			error, ppbFailedPointer, *ppbFailedPointer);
		return error;
	}
	return 1;
}







































BOOL APIENTRY DllMain(HINSTANCE hModule, DWORD dwReason, PVOID lpReserved)
{
	(void)hModule;
	(void)lpReserved;
	BOOL ret;

	if (DetourIsHelperProcess()) {
		return TRUE;
	}

	switch (dwReason)
	{
	case DLL_PROCESS_ATTACH:

		DetourRestoreAfterWith();
		OutputDebugStringA("dl" DETOURS_STRINGIFY(DETOURS_BITS) ".dll:"
			" DllMain DLL_PROCESS_ATTACH\n");
		//while (1);
			//recieve_arguments();
		k = 1;
		sprintf(a, "%s", "Privet\n");
		return AttachDetours();//ProcessAttach(hModule);
		//break;
	case DLL_PROCESS_DETACH:
		ret = DetachDetours();//ProcessDetach(hModule);
		OutputDebugStringA("dl" DETOURS_STRINGIFY(DETOURS_BITS) ".dll:"
			" DllMain DLL_PROCESS_DETACH\n");
		return ret;

	}

	return TRUE;
}
//
///////////////////////////////////////////////////////////////// End of File.