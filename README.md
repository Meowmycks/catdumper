# catdumper

## Disclaimer

Don't be evil with this. I created this tool to learn. I'm not responsible if the Feds knock on your door.

## Overview

`catdumper.exe` takes a snapshot of the LSASS process, creates a MiniDump of it, RC4 encrypts it with a randomly-generated string, and Base64 encodes it, all in-memory.

While still in-memory, the encrypted MiniDump and its key are exfiltrated over an HTTPS connection to a Python Flask server, `exfil.py` you run on your machine.

The Flask server decodes and decrypts the data locally before dropping it to the disk. After that, you can open it in Mimikatz like normal.

Compile as a VS2022 project and run as Administrator. You can figure out that part :)

## Features

- Uses polymorphism with compiletime RNG to always generate a unique file signature.
- Unhooks NtReadVirtualMemory to defeat EDR userland hooking.
- Also tricks heuristics by performing multiple benign Windows API functions.
- Encrypting and encoding MiniDump in-memory means AV/EDRs *shouldn't* flag it.
- Strings that might raise flags are obfuscated (e.g "lsass.exe").
- Packet size and time between requests is randomized.

## Demo

![catdumper_demo](https://github.com/Meowmycks/catdumper/assets/45502375/2f6b5c33-de3b-4243-afdb-4ea84b017efb)

