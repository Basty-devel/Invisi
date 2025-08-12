# Thorn-Apple: Advanced Payload Generator

![Thorn-Apple Logo](thorn_apple.png)

Thorn-Apple is a military-grade encrypted payload generator with advanced evasion capabilities, designed for penetration testers and red team operators. It creates polymorphic reverse shells with multiple evasion techniques and modular payload capabilities.

## Key Features

- **Encrypted Payloads**: AES-256-GCM and ChaCha20-Poly1305 encryption
- **Cross-Platform**: Generate payloads for Windows, Linux, and macOS
- **Polymorphic Code**: Unique shellcode per generation
- **Advanced Evasion**:
  - SSL/TLS tunneling
  - Domain fronting
  - Anti-debug techniques
  - Randomized sleep patterns
- **Modular Payload System**:
  - File dropper
  - Cryptocurrency miner
  - Ransomware module
  - Multiple persistence mechanisms
- **Integrated Listener**: Built-in reverse shell handler with SSL support

## Installation

1. Clone the repository:
   ```bash
   git clone https://github.com/yourrepo/thorn-apple.git
   cd thorn-apple
Install dependencies:

bash
pip install -r requirements.txt
Run the application:

bash
python thorn-apple.py
Usage Guide
Basic Payload Generation
Configure connection settings (LHOST/LPORT)

Select architecture (x86/x64) and target OS

Choose payload format (Python Loader/EXE/Shellcode)

Configure encryption method

Enable evasion techniques as needed

Click "Generate Advanced Payload"

Advanced Modules
File Dropper: Embed and execute additional binaries

Domain Fronting: Evade network restrictions using CDN domains

Cryptominer: Monero CPU miner with stealth options

Ransomware: File encryption module with exclusion lists

Listener Controls
Set listener port (default: 4444)

Enable SSL/TLS for encrypted communications

Start listener and wait for connections

Execute commands through the integrated terminal

Configuration Options
Section	Options
Connection	LHOST, LPORT, SSL/TLS, Sleep Time
Payload Settings	Architecture, Platform, Format, Encryption Method
Advanced Evasion	Code Obfuscation, Anti-Debug, Sandbox Evasion
Persistence	Registry, Startup Folder, Scheduled Tasks, System Services
File Dropper	File selection, Target filename, Execution options
Domain Fronting	Front domain, Real domain
Cryptominer	Mining pool, Wallet address, CPU usage, Stealth options
Ransomware	Ransom note, Target extensions, Folder exclusions
Build Standalone Executables
To compile payloads to EXE format:

bash```
pyinstaller --onefile --noconsole payload.py```

## Security Considerations

## Use only on authorized systems with proper permissions

## SSL certificates are self-signed for demonstration purposes

## Ransomware module is for research purposes only

## Disable real attack modules during testing

Screenshot
https://screenshot.png

## Disclaimer
This tool is for educational and authorized penetration testing purposes only. The developers assume no liability for misuse of this software.

## License
Thorn-Apple is released under the Security Testing License - use only for legitimate security assessment activities.

### Implementation Notes

1. **Dependencies**:
   - PyCryptodome for military-grade encryption
   - PyQt5 for the professional GUI interface
   - pefile for future EXE manipulation features
   - (Optional) PyInstaller for compiling payloads

2. **Key Features**:
   - AES-256-GCM and ChaCha20-Poly1305 encryption
   - Polymorphic shellcode generation
   - Integrated SSL listener with domain fronting
   - Modular payload system (miner/ransomware/dropper)
   - Cross-platform payload generation
   - Professional dark-mode UI with status monitoring

3. **Security**:
   - Self-signed certificate included for SSL operations
   - Clear disclaimer about authorized usage
   - Warning labels for real attack modules

This package provides a complete, professional-grade payload generation framework with comprehensive documentation. The implementation follows security best practices while delivering advanced offensive capabilities in a user-friendly interface.
