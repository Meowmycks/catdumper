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
void XOR_EncryptDecrypt(LPVOID data, size_t dataSize, const char* key, size_t keySize);
constexpr unsigned int numRNG();
std::string stringRNG(int length);
void SelfDelete();

#endif
