#include <iostream>
#include <string>
#include <Windows.h>
#include <tlhelp32.h>

void getProcessNameOrId(DWORD& outProcId, std::wstring outProcName)
{
	// if no process with procId was found
	std::wstring procName = L"";

	HANDLE hSnapshot = CreateToolhelp32Snapshot(TH32CS_SNAPPROCESS, NULL);
	PROCESSENTRY32 entry;
	entry.dwSize = sizeof(PROCESSENTRY32);
	if (Process32First(hSnapshot, &entry))
	{
		while (Process32NextW(hSnapshot, &entry))
		{
			if (entry.th32ProcessID == outProcId || wcscmp(entry.szExeFile, outProcName.c_str()))
			{
				outProcName = entry.szExeFile;
				outProcId = entry.th32ProcessID;
			}
		}
	}
	return;
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
			if (wcscmp(entry.szExeFile, proccesName.c_str()) == TRUE) // TODO: comparison does not work
			{
				procId = entry.th32ProcessID;
			}
		}
	}
	return procId;
}

int parseCommandLineArguments(DWORD& outProcId, std::wstring& outProcName, std::wstring& outSignature)
{
	int argcW;
	LPWSTR* argvW;
	std::wstring procNameOrId;

	// get commannd line arguments as wide chars 
	argvW = CommandLineToArgvW(GetCommandLineW(), &argcW);
	procNameOrId = argvW[1];
	outSignature = argvW[2];

	// if process name is used instead of providing process id
	if (procNameOrId.find(L".exe") != std::string::npos)
	{
		getProcessNameOrId(outProcId, procNameOrId); // empty procId

	}
	else
	{
		DWORD procId = std::stoi(procNameOrId);
		getProcessNameOrId(procId, outProcName); // empty procName
	}
	if (outProcId == -1)
	{
		std::cout << "[-] Could not find running application: " << procNameOrId.c_str() << std::endl;
		return 0;
	}
	return 1;
}


int main(int argc, char** argv)
{
	SYSTEM_INFO lpSystemInfo;

	// check for arguments
	if (argc < 3) {
		std::cout << "Usage: .\\ExternalSignatureScanner.exe <processID / processName> <signature>" << std::endl;
		return 1;
	}

	std::cout << "[ ] Scan for process id or process name..." << std::endl;

	DWORD procId = -1;
	std::wstring procName;
	std::wstring signature;

	if (!parseCommandLineArguments(procId, procName, signature))
	{
		std::cout << "[-] Could not parse command line arguments" << std::endl;
	}
	else
	{
		std::cout << "[+] Found process" << std::endl;
		std::cout << "    |- procId: " << procId << std::endl;
		std::cout << "    |- procName: " << procName.c_str() << std::endl;
	}

	return 0;
}