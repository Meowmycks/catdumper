# catdumper

## Disclaimer

*Insert "eDuCaTiOnAl PuRpOsEs OnLy" disclaimer here. I created this to learn. I'm not responsible for your dumbass if the Feds knock on your door.*

## Overview

**catdumper** takes a snapshot of the LSASS process, then creates a MiniDump of it and XOR encrypts it in-memory with a randomly-generated string.
The encrypted MiniDump and its key are dropped to the current directory.

**catxor** then decrypts the MiniDump. Then you can open it in Mimikatz like normal.

Compile each as their own VS2022 project, then run with `NT AUTHORITY\SYSTEM` privileges. You can figure out that part :)

## Features

- Uses polymorphism with compiletime RNG to always generate a unique file signature.
- Tricks heuristics by performing multiple benign Windows API functions.
- XOR encrypting the MiniDump in-memory means AV/EDRs *shouldn't* flag it once it hits the disk.
- File deletes itself after running to try and prevent remnants from remaining on disk.
- Strings that might raise flags are obfuscated (e.g "lsass.exe").

## Demo

![catdumper_demo](https://github.com/Meowmycks/catdumper/assets/45502375/5a6419db-e7e4-451d-b14c-66d7f78806c9)
