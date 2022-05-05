#include <iostream>
#include <string>
#include <Windows.h>
#include <tlhelp32.h>

void scanFullMemory(DWORD procId)
{
	HANDLE targetProcess = OpenProcess(PROCESS_QUERY_INFORMATION, true, procId);
	HANDLE moduleSnapshot = CreateToolhelp32Snapshot(TH32CS_SNAPMODULE, procId);

	LPCVOID addr = NULL;
	MEMORY_BASIC_INFORMATION memInfo;

	while (VirtualQueryEx(targetProcess, addr, &memInfo, sizeof(memInfo)))
	{
		if (memInfo.State == MEM_COMMIT && memInfo.Protect != PAGE_NOACCESS)
		{
			std::cout << " [MEM_COMMIT && !PAGE_NOACCESS] Address: " << addr << std::endl;
			for (LPCVOID i = addr; i < (char*)addr + memInfo.RegionSize; i = (char*)i + 1) // increment by 1 Byte
			{
				std::cout << "    |- " << i << "\r"; // moving the cursor back to the start
			}
		}
		else
		{
			//std::cout << " Address: " << addr << '\r'; // reset line by moving the cursor to the start of the line
			std::cout << " Address: " << addr << std::endl;
		}
		// cast to char* so bytes will be added
		addr = (char*)addr + memInfo.RegionSize;
	}

	CloseHandle(targetProcess);
}

void scanMemoryModules(DWORD procId)
{
	MODULEENTRY32 me32;
	me32.dwSize = sizeof(MODULEENTRY32);

	HANDLE targetProcess = OpenProcess(PROCESS_VM_READ, true, procId);
	HANDLE moduleSnapshot = CreateToolhelp32Snapshot(TH32CS_SNAPMODULE, procId);

	if (Module32First(moduleSnapshot, &me32))
	{
		while (Module32Next(moduleSnapshot, &me32))
		{
			if (me32.th32ProcessID == procId)
			{
				std::cout << "Module size: " << me32.modBaseSize << std::endl;
				std::wcout << "Module name: " << me32.szModule << std::endl;
			}
		}
	}
	CloseHandle(targetProcess);
}