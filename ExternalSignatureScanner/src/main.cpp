#include <iostream>
#include <string>
#include <Windows.h>
#include <tlhelp32.h>

#include "Scanner.h"

/*
Fills outProcId or outProcName depanding on with is empty.
If they are both empty the function won't do 
*/
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


/*
Figures out if procId or procName is givin by the user and fills in the parameters by reference.
*/
static int parseCommandLineArguments(DWORD& outProcId, std::wstring& outProcName, std::wstring& inSignature, wchar_t* outSignature)
{
	int argcW;
	LPWSTR* argvW;
	std::wstring procNameOrId;
	DWORD procId;

	// get commannd line arguments as wide chars 
	argvW = CommandLineToArgvW(GetCommandLineW(), &argcW);
	procNameOrId = argvW[1];
	inSignature = argvW[2];

	// convert wstring to c string
	const wchar_t* sig = inSignature.c_str();
	unsigned long long sigSize = inSignature.size();
	
	// reserve memory for outSignature
	outSignature = new wchar_t[sigSize];

	// found hexadecimal signature and treat signature as raw bytes
	if (inSignature.find(L"0x"))
	{
		for (int i = 0; i < sigSize; i++)
		{
			outSignature[i] = sig[i];
		}
	}

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

	wchar_t* sig = NULL;

	if (parseCommandLineArguments(procId, procName, signature, sig))
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
	size_t byteArrayLength = signature.length();


	// get system info
	GetSystemInfo(&sysInfo);
	std::cout << "Scan from " << sysInfo.lpMinimumApplicationAddress
		<< " to " << sysInfo.lpMaximumApplicationAddress << std::endl;


	scanMemoryModules(procId);
	return 0;
}