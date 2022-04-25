#include <iostream>
#include <string>
#include <Windows.h>
#include <tlhelp32.h>

int getProcessIdByName(std::wstring proccesName)
{
	int procId = -1;

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

void parseCommandLineArguments(int& procId, std::wstring& signature)
{
	int argcW;
	LPWSTR* argvW;
	std::wstring procName;

	// get commannd line arguments as wide chars 
	argvW = CommandLineToArgvW(GetCommandLineW(), &argcW);
	procName = argvW[1];
	signature = argvW[2];

	// if process name is used instead of providing process id
	if (procName.find(L".exe") != std::string::npos)
	{
		procId = getProcessIdByName(procName);
	}
	else
	{
		procId = std::stoi(procName); 
	}

}


int main(int argc, char **argv)
{
	SYSTEM_INFO lpSystemInfo;

	// check for arguments
	if (argc < 3) {
		std::cout << "Usage: .\\ExternalSignatureScanner.exe <processID / processName> <signature>" << std::endl;
		return 1;
	}
	int procId;
	std::wstring signature;
	parseCommandLineArguments(procId, signature);

	// retrieve system informations
	GetSystemInfo(&lpSystemInfo);
	std::cout << lpSystemInfo.dwNumberOfProcessors << std::endl;

	return 0;
}