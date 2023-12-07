#pragma once

#ifndef catxor
#define catxor

#include <iostream>
#include <fstream>
#include <vector>
#include <string>

void XOR_EncryptDecrypt(std::vector<char>& data, const char* key, size_t keySize);
std::string readKeyFromFile(const std::string& keyFilePath);

#endif
