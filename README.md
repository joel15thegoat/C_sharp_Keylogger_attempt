 # Keylogger

A C# keylogger I made for fun. It hooks into the Windows keyboard, logs keystrokes with modifier‑combo detection, encrypts everything using **AES‑256‑GCM**, and can be controlled remotely over TCP. It also includes optional steganography (PNG LSB) and AWS S3 upload

## Features

- Low‑level global keyboard hook (Windows only)
- Modifier key tracking (`Ctrl`, `Alt`, `Shift`, `Cmd`) and combo logging
- Keystroke buffer with periodic encrypted flushing
- AES‑256‑GCM encryption of log files
- DPAPI‑protected key storage (Windows)
- Remote control via TCP (start/stop/status/shutdown)
- Steganography: embed the encrypted log inside PNG images (LSB)
- AWS S3 upload support
- Self‑destruct temp plaintext files after encryption

## Building

### Prerequisites

- **Windows** – the keyboard hook uses Win32 API
- **.NET 6.0+** (8.0 recommended)  
  Download: [https://dotnet.microsoft.com/download](https://dotnet.microsoft.com/download)
- (Optional) AWS credentials if you want to test the S3 uploader

### Steps

 - **1. Clone the repo**
```bash
 git clone https://github.com/joel15thegoat/C_sharp_Keylogger_attempt/
```

 - **2. Create the project if you haven't yet**
``` bash
dotnet new console -n SecureKeylogger
cd SecureKeylogger
 ```

 - **3. Add NuGet packages**
``` bash
dotnet add package AWSSDK.S3
dotnet add package System.Drawing.Common
``` 
 - **4. Replace Program.cs with the source code from this repo**

 - **5. Build**
``` bash
dotnet build
``` 
 - **6. Run**
``` bash
dotnet run
```


## small warning

**Before you build or run this,pls change these hard coded values in the source code at will**

| What | Where to find it | Why you must change it |
|------|------------------|------------------------|
| **Auth Token** | `_authToken = "MySecretToken123"` | Change it to a strong random string (e.g., `openssl rand -base64 32`). |
| **Bind IP** | `IPAddress.Any` (which is `0.0.0.0`) | Change to `IPAddress.Loopback` (`127.0.0.1`) unless you specifically need remote access over a network. |
| **Encryption Password** | `"MyStrongPassword123!"` | chande to watever password u want but i suggest u use enviromental variabels instead.

> **Network Security**: The remote control traffic is sent in plaintext. i suggest u Don't run this on public Wi-Fi or untrusted networks without a VPN/SSH tunnel.

## Legal Warning

**Use this tool only on systems you own or on which you have explicit permission to monitor.**
- i don't take responsibility for anything you do with this
- this is code that i did for my eae application so i wouldn't trust this blindly if i were you
## licence 
this is published under the mit licence 
[licence](https://mit-license.org/)
## have fun
