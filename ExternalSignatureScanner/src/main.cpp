#include <iostream>
#include <string>
#include <Windows.h>

int getProcessIdByName(std::wstring proccesName)
{
	// TODO
	return 0;
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