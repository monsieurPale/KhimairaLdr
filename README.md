# KhimairaLdr

![img](./images/khimairaLdr.png)

## Execution Flow (using `java-rmi.exe`)

1. Drop `java-rmi.exe` and compiled `jli.dll` in `AppData\Local`
2. Run `java-rmi.exe` to sideload the `.dll`
3. `jli.dll` fetches `.bin` shellcode from web server
4. `jli.dll` roots persistence using selected method
5. `jli.dll` executes shellcode

## Evasion Features

- `wininet.dll` cache-cleaning, avoids leaving artefacts on disk
- `Nt*` and `Win32` APIs via CRC32 API-hashing (no imports)
- `ntdll.dll` unhook using indirect-syscalls 
- Only stacked strings in binary
- `CRT` library removal
-  RC4 shellcode decryption using `SystemFunction032`
- Local shellcode injection using `Nt*` APIs
- Threadless shellcode execution via `jmp rcx`
- `LoadLibrary, GetModuleHandle` and `GetProcAddress` removal

## Persistence Features

- Switch `#define _LNK_` flag to customize
- Persistence via registrey key `HKCU\Software\Microsoft\Windows\CurrentVersion\Run -> Updater -> AppData\Local\java-rmi.exe`
- Persistence via startup folder `shell:startup -> BGInfo.lnk -> AppData\Local\java-rmi.exe`

## Usage

- Use `MiniShellHCKey.exe <your.bin> rc4 hck.bin` to encrypt custom `.bin` (harcoded encryption key)
- If required, change persistence (default: regkey)
- If required, change staging URL using stack strings
- Compile the `.dll` using `.sln` file and rename to `jli.dll`
