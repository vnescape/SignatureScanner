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

static void getProcessNameOrId(DWORD& outProcId, std::wstring& outProcName)
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

static int parseCommandLineArguments(DWORD& outProcId, std::wstring& outProcName, std::wstring& outSignature)
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

	//convert signature into byte array
	const wchar_t* byteArray = signature.c_str();
	int byteArrayLength = signature.length();


	// get system info
	GetSystemInfo(&sysInfo);
	std::cout << "Scan from " << sysInfo.lpMinimumApplicationAddress
		<< " to " << sysInfo.lpMaximumApplicationAddress << std::endl;

	MODULEENTRY32 me32;
	me32.dwSize = sizeof(MODULEENTRY32);

	scanFullMemory(procId);
	return 0;
}