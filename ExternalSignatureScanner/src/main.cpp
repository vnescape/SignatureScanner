
#include <iostream>
#include <Windows.h>



int main(int argc, char **argv)
{
	SYSTEM_INFO lpSystemInfo;
	int argcW;
	LPWSTR* argvW;

	// check for arguments
	if (argc < 3) {
		std::cout << "Usage: .\\ExternalSignatureScanner.exe <processID / processName> <signature>" << std::endl;
		return 1;
	}

	// get commannd line arguments as wide chars 
	argvW = CommandLineToArgvW(GetCommandLineW(), &argcW);

	// retrieve system informations
	GetSystemInfo(&lpSystemInfo);
	std::cout << lpSystemInfo.dwNumberOfProcessors << std::endl;

	return 0;
}