
#include <iostream>
#include <Windows.h>

void printUsage()
{
	std::cout << "Usage:"

}

int main(int argc, char **argv)
{
	if (argc < 3) {
		std::cout << "Usage: .\\ExternalSignatureScanner.exe <processID / processName> <signature>" << std::endl;
		return 1;
	}

	SYSTEM_INFO lpSystemInfo;

	// retrieve system informations
	GetSystemInfo(&lpSystemInfo);
	std::cout << lpSystemInfo.dwNumberOfProcessors << std::endl;

	return 0;
}