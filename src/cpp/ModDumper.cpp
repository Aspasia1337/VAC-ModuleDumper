#include <iostream>
#include <Windows.h>
#include <TlHelp32.h>
#include <string>

const wchar_t* modName = L"steamservice.dll";
const uint32_t offset = 0x5906A;

DWORD getPid() {
	HANDLE procSnap = CreateToolhelp32Snapshot(TH32CS_SNAPPROCESS,0);

	if (procSnap == INVALID_HANDLE_VALUE) {
		CloseHandle(procSnap);
		return -1;
	}

	PROCESSENTRY32 proc;
	proc.dwSize = sizeof(PROCESSENTRY32);

	if (Process32First(procSnap, &proc)) {
		do {
			//std::wcout << proc.szExeFile << " - " << proc.th32ProcessID << std::endl;
			if(!wcscmp(L"steam.exe",proc.szExeFile)){
				CloseHandle(procSnap);
				return proc.th32ProcessID;
			}
		} while (Process32Next(procSnap, &proc));
	}
	CloseHandle(procSnap);
	return -1;
}

BYTE *getModuleAddress(DWORD pid) {
	HANDLE modSnap = CreateToolhelp32Snapshot(TH32CS_SNAPMODULE, pid);

	if (modSnap == INVALID_HANDLE_VALUE) {
		CloseHandle(modSnap);
		return nullptr;
	}

	MODULEENTRY32 mod;
	mod.dwSize = sizeof(MODULEENTRY32);
	
	if (Module32First(modSnap, &mod)) {
		do {
			if (std::wstring(mod.szExePath).find(modName, sizeof(modName)) != std::string::npos) {
			std::wcout << "[Module Base Address] - " << mod.szExePath << " - " << std::hex << mod.modBaseAddr << std::endl;
			CloseHandle(modSnap);
			return mod.modBaseAddr;
			}
		} while (Module32Next(modSnap, &mod));
	}
	CloseHandle(modSnap);
	return nullptr;
}

int patchMemory(DWORD pid, BYTE *baseAddress) {
	HANDLE pHandle = OpenProcess(PROCESS_ALL_ACCESS, 1, pid);
	if (pHandle == INVALID_HANDLE_VALUE) {
		CloseHandle(pHandle);
		return -1;
	}

	// test eax, eax
	const BYTE array[] = { 0x90,0x90,0x85,0xC0 };

	DWORD oldProtect; 
	SIZE_T numWritten;

	BYTE* patchAddress = baseAddress + offset;

	if (VirtualProtectEx(pHandle, baseAddress + offset, 4, PAGE_EXECUTE_READWRITE, &oldProtect) == 0) {
		std::cout << "Error on virtualprotect\n";
		CloseHandle(pHandle);
		return -1;
	}
	
	if (WriteProcessMemory(pHandle, baseAddress + offset, array, 4, &numWritten) == 0) {
		std::cout << "Error on virtualprotect\n";
		CloseHandle(pHandle);
		return -1;
	}

	std::cout << "[Patch Memory] - Bytes Written to the address - 0x" << std::hex << (uintptr_t)patchAddress << std::endl;
	std::cout << "[Patch Memory] - Num Bytes Written = " << numWritten << std::endl;
	
	CloseHandle(pHandle);
	return 0;
}


int main() {

	DWORD pid = getPid();
	BYTE* moduleBaseAddress = getModuleAddress(pid);

	patchMemory(pid, moduleBaseAddress);
	
	getchar();
	return 0;
}