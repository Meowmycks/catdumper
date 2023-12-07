# catdumper
Windows LSASS Credential Dumper

*Developed for educational and ethical testing purposes only. I'm not responsible for your dumbass if the Feds knock on your door.*

## Overview

**catdumper** creates a MiniDump of the LSASS process and XOR encrypts it in-memory with a randomly-generated string. The encrypted MiniDump and its key are dropped to the current directory. **catxor** then decrypts the MiniDump. Then you can open it in Mimikatz like normal.

Run with NT AUTHORITY\SYSTEM privileges. You can figure out that part :)

## Features

- Uses polymorphism with compiletime RNG to always generate a unique file signature.
- XOR encrypting the MiniDump in-memory means Defender *shouldn't* flag it once it hits the disk.
- File deletes itself after running to try and prevent remnants from remaining on disk.

## Demo

![catdumper_demo](https://github.com/Meowmycks/catdumper/assets/45502375/5a6419db-e7e4-451d-b14c-66d7f78806c9)
