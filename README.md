# Thorn-Apple: Advanced Secure Payload Generator

Thorn-Apple is a professional-grade payload generation framework designed for security professionals, penetration testers, and red team operators. This sophisticated tool combines military-grade encryption with polymorphic code generation to create evasive payloads that bypass modern security controls.

**Key Features:**
Military-Grade Encryption: AES-256-GCM and ChaCha20-Poly1305 authenticated encryption

Polymorphic Engine: Unique shellcode generation with junk code insertion

Cross-Platform Support: Windows, macOS, and Linux payload generation

Advanced Modules: Persistence, surveillance, and data operation capabilities

**Multiple Output Formats:**

Standalone executables (PE format)

Python loader scripts

Raw shellcode binaries

**Evasion Techniques:**

Randomized sleep timers

Anti-analysis measures

Architecture-specific polymorphism

Installation
Prerequisites
Python 3.8+

Supported platforms: Windows, Linux, macOS

**Installation Steps**

## Clone the repository
bash```
git clone https://github.com/your-username/thorn-apple.git
cd thorn-apple```

## Install dependencies
bash```
pip install -r requirements.txt```

## Run the application
bash```
python thorn-apple.py```

## Usage
Basic Operation
Configure connection settings (LHOST/LPORT)

Select encryption algorithm and target architecture

Choose payload format (EXE, Python Loader, or Shellcode)

Enable advanced modules as needed

Generate and save payload

Command Line Options
bash```
python thorn-apple.py [options]```

Options:
  --lhost LHOST       Listener IP address
  --lport LPORT       Listener port
  --format FORMAT     Output format (exe, py, bin)
  --encryption ENC    Encryption method (aes, chacha)
  --output FILE       Output file name
  --sleep SECONDS     Pre-execution sleep time
  
## Advanced Modules
**Persistence Mechanisms**

Registry Run Key (Windows)

Startup Folder

Scheduled Task/Cron Job

System Service/Daemon

**Surveillance Capabilities**

Microphone Capture

Webcam Capture

Keylogger

Screen Capture

**Data Operations**

File Exfiltration

Drive Content Search

Process Injection

Credential Harvesting

## Disclaimer
Thorn-Apple is designed for authorized security testing and educational purposes only. The developers assume no liability and are not responsible for any misuse or damage caused by this software. Always obtain proper authorization before testing systems you do not own.

## License
Thorn-Apple is released under the GNU General Public License v3.0. See LICENSE for full details.

# Thorn-Apple: Where cutting-edge cryptography meets offensive security operations.
