
#include <iostream>
#include <Windows.h>

int main() {

	SYSTEM_INFO lpSystemInfo;

	// retrieve system informations
	GetSystemInfo(&lpSystemInfo);
	std::cout << lpSystemInfo.dwNumberOfProcessors << std::endl;
	return 0;
}