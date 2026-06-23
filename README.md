# SecureKeylogger

A C# keylogger I made for fun. It hooks into the Windows keyboard, logs keystrokes with modifier‑combo detection, encrypts everything using **AES‑256‑GCM**, and can be controlled remotely over TCP. It also includes optional steganography (PNG LSB) and AWS S3 upload – just because I could.

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

# 1. Clone the repo
git clone https://github.com/your-username/your-repo.git
cd your-repo

# 2. Create the project if you haven't yet
dotnet new console -n SecureKeylogger
cd SecureKeylogger

# 3. Add NuGet packages
dotnet add package AWSSDK.S3
dotnet add package System.Drawing.Common

# 4. Replace Program.cs with the source code from this repo

# 5. Build
dotnet build

# 6. Run
dotnet run
## ⚠️ Legal Warning

**Use this tool only on systems you own or on which you have explicit permission to monitor.**
- i don't take responsibility for anything you do with this
-  have fun
## licence 
this is published under the mit licence 
[licence](https://mit-license.org/)
