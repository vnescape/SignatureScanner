#include <iostream>
#include <string>
#include <Windows.h>
#include <tlhelp32.h>

void getProcessNameOrId(DWORD& outProcId, std::wstring& outProcName)
{
	PROCESSENTRY32 entry;

	HANDLE hSnapshot = CreateToolhelp32Snapshot(TH32CS_SNAPPROCESS, NULL);

	entry.dwSize = sizeof(PROCESSENTRY32);
	if (Process32First(hSnapshot, &entry))
	{
		while (Process32NextW(hSnapshot, &entry))
		{
			if (entry.th32ProcessID == outProcId || wcscmp(entry.szExeFile, outProcName.c_str()) == 0)
			{
				outProcName = entry.szExeFile;
				outProcId = entry.th32ProcessID;
			}
		}
	}
	return;
}

int parseCommandLineArguments(DWORD& outProcId, std::wstring& outProcName, std::wstring& outSignature)
{
	int argcW;
	LPWSTR* argvW;
	std::wstring procNameOrId;
	DWORD procId;

	// get commannd line arguments as wide chars 
	argvW = CommandLineToArgvW(GetCommandLineW(), &argcW);
	procNameOrId = argvW[1];
	outSignature = argvW[2];

	// if process name is used instead of providing process id
	if (procNameOrId.find(L".exe") != std::string::npos)
	{
		getProcessNameOrId(outProcId, procNameOrId); // empty procId
		outProcName = procNameOrId;

	}
	else
	{
		procId = std::stoi(procNameOrId);
		getProcessNameOrId(procId, outProcName); // empty procName
		outProcId = procId;
	}

	if (outProcId == -1)
	{
		std::cout << "[-] Could not find running application: ";
		std::wcout << outProcName.c_str() << std::endl;
		return 0;
	}
	return 1;
}


int main(int argc, char** argv)
{
	DWORD procId = -1;
	std::wstring procName;
	std::wstring signature;
	SYSTEM_INFO sysInfo = { 0 };

	// check for arguments
	if (argc < 3) {
		std::cout << "Usage: .\\ExternalSignatureScanner.exe <processID / processName> <signature>" << std::endl;
		return 1;
	}

	std::cout << "[ ] Scan for process id or process name..." << std::endl;



	if (parseCommandLineArguments(procId, procName, signature))
	{
		std::cout << "[+] Found process" << std::endl;
		std::cout << "    |- procId: " << procId << std::endl;
		std::cout << "    |- procName: ";
		std::wcout << procName.c_str() << std::endl;
	}
	else
	{
		std::cout << "[-] Could not parse command line arguments" << std::endl;
		return 1;
	}

	// get system info
	GetSystemInfo(&sysInfo);
	//std::cout << sysInfo.dwNumberOfProcessors << std::endl;

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
				void* processMemory = calloc(1, me32.modBaseSize);
				SIZE_T bytesRead;
				
				if (processMemory != 0)
				{
					// reads process memory starting with the MZ header
					ReadProcessMemory(targetProcess, (LPCVOID)me32.modBaseAddr, processMemory, me32.modBaseSize, &bytesRead);
				}
				free(processMemory);
			}
		}
	}
	CloseHandle(targetProcess);
	return 0;
}