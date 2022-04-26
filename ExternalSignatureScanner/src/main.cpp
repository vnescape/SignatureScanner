#include <iostream>
#include <string>
#include <Windows.h>
#include <tlhelp32.h>

std::wstring getProcessNameById(DWORD& procId)
{
	// if no process with procId was found
	std::wstring procName = NULL;

	HANDLE hSnapshot = CreateToolhelp32Snapshot(TH32CS_SNAPPROCESS, NULL);
	PROCESSENTRY32 entry;
	entry.dwSize = sizeof(PROCESSENTRY32);
	if (Process32First(hSnapshot, &entry))
	{
		while (Process32NextW(hSnapshot, &entry))
		{
			if (entry.th32ProcessID == procId)
			{
				procName = entry.szExeFile;
			}
		}
	}
	return procName;
}

DWORD getProcessIdByProcessName(std::wstring proccesName)
{
	DWORD procId = -1;

	HANDLE hSnapshot = CreateToolhelp32Snapshot(TH32CS_SNAPPROCESS, NULL);
	PROCESSENTRY32 entry;
	entry.dwSize = sizeof(PROCESSENTRY32);
	if (Process32First(hSnapshot, &entry))
	{
		while (Process32NextW(hSnapshot, &entry))
		{
			if (wcscmp(entry.szExeFile, proccesName.c_str()))
			{
				procId = entry.th32ProcessID;
			}
		}
	}
	return procId;
}

int parseCommandLineArguments(DWORD& outProcId, std::wstring& outSignature)
{
	int argcW;
	LPWSTR* argvW;
	std::wstring procName;

	// get commannd line arguments as wide chars 
	argvW = CommandLineToArgvW(GetCommandLineW(), &argcW);
	procName = argvW[1];
	outSignature = argvW[2];

	// if process name is used instead of providing process id
	if (procName.find(L".exe") != std::string::npos)
	{
		outProcId = getProcessIdByProcessName(procName);
		if (outProcId == -1)
		{
			std::cout << "Could not find running application: " << procName.c_str() << std::endl;
			return 0;
		}
	}
	else
	{
		outProcId = std::stoi(procName);
	}
	return 1;
}


int main(int argc, char **argv)
{
	SYSTEM_INFO lpSystemInfo;

	// check for arguments
	if (argc < 3) {
		std::cout << "Usage: .\\ExternalSignatureScanner.exe <processID / processName> <signature>" << std::endl;
		return 1;
	}

	std::cout << "[>] Scan for process id or process name..." << std::endl;

	DWORD procId;
	std::wstring signature;
	if (!parseCommandLineArguments(procId, signature))
	{
		std::cout << "Could not parse command line arguments" << std::endl;
	}



	std::cout << "[*] Found process" << std::endl;
	std::cout << "    |- procId: " << procId << std::endl;
	std::cout << "    |- procName: " << getProcessNameById(procId).c_str() << std::endl;
	

	// retrieve system informations
	GetSystemInfo(&lpSystemInfo);
	std::cout << lpSystemInfo.dwNumberOfProcessors << std::endl;

	return 0;
}