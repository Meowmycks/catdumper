#include <iostream>
#include <fstream>
#include <vector>
#include <string>

using namespace std;

void XOR_EncryptDecrypt(vector<char>& data, const char* key, size_t keySize) {
    for (size_t i = 0; i < data.size(); ++i) {
        data[i] ^= key[i % keySize];
    }
}

string readKeyFromFile(const string& keyFilePath) {
    ifstream keyFile(keyFilePath);
    if (!keyFile) {
        cerr << "Error: Unable to open key file." << endl;
        exit(1);
    }

    string key;
    getline(keyFile, key);
    keyFile.close();
    return key;
}

int main() {
    const char* encryptedFilePath = "dump.dmp";
    const string keyFilePath = "key.txt";

    const char* xorKey = readKeyFromFile(keyFilePath).c_str();
    size_t xorKeySize = strlen(xorKey);

    ifstream file(encryptedFilePath, ios::binary);
    if (!file) {
        cerr << "Error: Unable to open file for reading." << endl;
        return 1;
    }

    vector<char> fileData((istreambuf_iterator<char>(file)), istreambuf_iterator<char>());
    file.close();

    // Decrypt the data
    XOR_EncryptDecrypt(fileData, xorKey, xorKeySize);

    // Write decrypted data back to file
    ofstream outFile(encryptedFilePath, ios::binary | ios::trunc);
    if (!outFile) {
        cerr << "Error: Unable to open file for writing." << endl;
        return 1;
    }

    outFile.write(fileData.data(), fileData.size());
    outFile.close();

    cout << "File decrypted successfully." << endl;
    return 0;
}
