#include <iostream>
#include <Windows.h>

int getProcessIdByName(std::string proccesName)
{
	// TODO
	return 0;
}

void parseCommandLineArguments(int& procId, std::string& signature)
{
	int argcW;
	LPWSTR* argvW;
	std::string procName;

	// get commannd line arguments as wide chars 
	argvW = CommandLineToArgvW(GetCommandLineW(), &argcW);
	procName = *argvW[1];
	signature = *argvW[2];

	// if process name is used instead of providing process id
	if (procName.find(".exe") != std::string::npos)
	{
		procId = getProcessIdByName(procName);
	}
	else
	{
		procId = std::stio(procName); 
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
	std::string signature;
	parseCommandLineArguments(procId, signature);

	// retrieve system informations
	GetSystemInfo(&lpSystemInfo);
	std::cout << lpSystemInfo.dwNumberOfProcessors << std::endl;

	return 0;
}