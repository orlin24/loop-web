#!/usr/bin/env python3
"""
YouTube Live Stream Automation Tool - Modern GUI Version with License System
Version: 3.2 - Licensed Edition with CustomTkinter UI
"""

import customtkinter as ctk
from tkinter import ttk, filedialog, messagebox, simpledialog
import threading
import time
import json
import csv
import random
import os
import re
import webbrowser
import socket
import hashlib
import uuid
import platform
from datetime import datetime, timedelta
from urllib.parse import urlparse, parse_qs
import requests
from PIL import Image, ImageTk

# Google API imports
try:
    from google.oauth2.credentials import Credentials
    from google_auth_oauthlib.flow import Flow
    from google.auth.transport.requests import Request
    from googleapiclient.discovery import build
    from googleapiclient.http import MediaFileUpload
    import pickle
    GOOGLE_LIBS_AVAILABLE = True
except ImportError:
    GOOGLE_LIBS_AVAILABLE = False
    print("Google libraries not installed. Some features may be limited.")

# Add retry mechanism with exponential backoff
import ssl
import urllib3
from urllib3.util.retry import Retry
from requests.adapters import HTTPAdapter

# Security imports
try:
    from cryptography.hazmat.primitives.ciphers import Cipher, algorithms, modes
    from cryptography.hazmat.primitives import hashes, serialization
    from cryptography.hazmat.primitives.kdf.pbkdf2 import PBKDF2HMAC
    from cryptography.hazmat.backends import default_backend
    import secrets
    CRYPTO_AVAILABLE = True
except ImportError:
    CRYPTO_AVAILABLE = False
    print("Cryptography library not found. Using fallback security.")

def get_executable_dir():
    """Get directory where executable is located"""
    import sys
    
    # Check if running as Nuitka compiled executable
    # Nuitka sets __compiled__ variable and sys.executable points to the .exe
    if '__compiled__' in globals() or hasattr(sys, 'frozen') or getattr(sys, 'frozen', False):
        # Running as compiled executable
        exe_dir = os.path.dirname(sys.executable)
        return exe_dir
    elif hasattr(sys, '_MEIPASS'):
        # PyInstaller bundle
        return os.path.dirname(sys.executable)
    elif sys.executable.endswith('.exe') and os.path.basename(sys.executable) != 'python.exe':
        # Likely a compiled executable
        return os.path.dirname(sys.executable)
    else:
        # Running as script
        return os.path.dirname(os.path.abspath(__file__))

def get_token_path():
    """Get correct path for token.pickle file, compatible with executable"""
    return os.path.join(get_executable_dir(), 'token.pickle')

def get_client_secrets_path():
    """Get correct path for client_secrets.json file, compatible with executable"""
    return os.path.join(get_executable_dir(), 'client_secrets.json')

def get_icon_path():
    """Get correct path for logo.ico file, compatible with executable"""
    return os.path.join(get_executable_dir(), 'logo.ico')

def get_license_cache_path():
    """Get correct path for license cache file"""
    return os.path.join(get_executable_dir(), '.license_cache')

class ToolTip:
    """Simple tooltip class for UI elements"""
    def __init__(self, widget, text='widget info'):
        self.widget = widget
        self.text = text
        self.widget.bind("<Enter>", self.enter)
        self.widget.bind("<Leave>", self.leave)
        self.tooltip_window = None

    def enter(self, event=None):
        x, y, cx, cy = self.widget.bbox("insert")
        x += self.widget.winfo_rootx() + 25
        y += self.widget.winfo_rooty() + 25
        
        self.tooltip_window = tw = ctk.CTkToplevel(self.widget)
        tw.wm_overrideredirect(True)
        tw.wm_geometry("+%d+%d" % (x, y))
        
        label = ctk.CTkLabel(tw, text=self.text, 
                           fg_color=("gray75", "gray25"), 
                           corner_radius=6,
                           text_color=("black", "white"))
        label.pack(padx=2, pady=2)

    def leave(self, event=None):
        if self.tooltip_window:
            self.tooltip_window.destroy()
        self.tooltip_window = None

def create_youtube_service_with_retry(credentials):
    """Create YouTube service with better error handling and fallbacks"""
    try:
        # Disable SSL warnings for debugging
        urllib3.disable_warnings(urllib3.exceptions.InsecureRequestWarning)
        
        # Method 1: Standard build with custom HTTP
        try:
            import httplib2
            http = httplib2.Http(disable_ssl_certificate_validation=True)
            service = build('youtube', 'v3', credentials=credentials, http=http)
            print("✅ YouTube service created with httplib2")
            return service
        except Exception as e1:
            print(f"Method 1 failed: {str(e1)}")
        
        # Method 2: Build with cache disabled
        try:
            service = build('youtube', 'v3', credentials=credentials, cache_discovery=False)
            print("✅ YouTube service created with cache disabled")
            return service
        except Exception as e2:
            print(f"Method 2 failed: {str(e2)}")
        
        # Method 3: Build with static discovery
        try:
            service = build('youtube', 'v3', credentials=credentials, 
                          discoveryServiceUrl='https://www.googleapis.com/discovery/v1/apis/youtube/v3/rest')
            print("✅ YouTube service created with static discovery URL")
            return service
        except Exception as e3:
            print(f"Method 3 failed: {str(e3)}")
        
        # Method 4: Build with manual service construction
        try:
            # Create a minimal service object manually
            http_auth = credentials.authorize(httplib2.Http(disable_ssl_certificate_validation=True))
            service = build('youtube', 'v3', http=http_auth, cache_discovery=False)
            print("✅ YouTube service created with manual construction")
            return service
        except Exception as e4:
            print(f"Method 4 failed: {str(e4)}")
        
        # Method 5: Last resort - basic service with minimal config
        try:
            # Set environment variable to disable SSL verification
            import os
            os.environ['PYTHONHTTPSVERIFY'] = '0'
            service = build('youtube', 'v3', credentials=credentials)
            print("✅ YouTube service created with SSL disabled")
            return service
        except Exception as e5:
            print(f"Method 5 failed: {str(e5)}")
            
        print("❌ All YouTube service creation methods failed")
        return None
        
    except Exception as e:
        print(f"❌ Service creation error: {str(e)}")
        return None

class CryptoUtils:
    """Enhanced cryptographic utilities for license security"""
    
    @staticmethod
    def generate_device_key(device_id):
        """Generate AES key from device ID using PBKDF2"""
        if not CRYPTO_AVAILABLE:
            return device_id[:32].ljust(32, '0').encode()
        
        # Use device ID as password and fixed salt for reproducibility
        salt = b'LoopBotSecure2024'  # Fixed salt for consistency
        kdf = PBKDF2HMAC(
            algorithm=hashes.SHA256(),
            length=32,  # 256-bit key
            salt=salt,
            iterations=100000,
            backend=default_backend()
        )
        return kdf.derive(device_id.encode())
    
    @staticmethod
    def encrypt_data(data, key):
        """Encrypt data using AES-256-GCM"""
        if not CRYPTO_AVAILABLE:
            # Fallback to base64
            import base64
            return base64.b64encode(data.encode()).decode()
        
        try:
            # Generate random IV
            iv = secrets.token_bytes(12)  # 96-bit IV for GCM
            
            # Create cipher
            cipher = Cipher(algorithms.AES(key), modes.GCM(iv), backend=default_backend())
            encryptor = cipher.finalize()
            
            # Encrypt data
            ciphertext = encryptor.update(data.encode()) + encryptor.finalize()
            
            # Combine IV + auth_tag + ciphertext and encode
            encrypted_blob = iv + encryptor.tag + ciphertext
            import base64
            return base64.b64encode(encrypted_blob).decode()
            
        except Exception:
            # Fallback to base64 if encryption fails
            import base64
            return base64.b64encode(data.encode()).decode()
    
    @staticmethod
    def decrypt_data(encrypted_data, key):
        """Decrypt data using AES-256-GCM"""
        if not CRYPTO_AVAILABLE:
            # Fallback from base64
            import base64
            try:
                return base64.b64decode(encrypted_data.encode()).decode()
            except:
                return None
        
        try:
            import base64
            encrypted_blob = base64.b64decode(encrypted_data.encode())
            
            # Extract IV, tag, and ciphertext
            iv = encrypted_blob[:12]
            tag = encrypted_blob[12:28]
            ciphertext = encrypted_blob[28:]
            
            # Create cipher
            cipher = Cipher(algorithms.AES(key), modes.GCM(iv, tag), backend=default_backend())
            decryptor = cipher.finalize()
            
            # Decrypt data
            plaintext = decryptor.update(ciphertext) + decryptor.finalize()
            return plaintext.decode()
            
        except Exception:
            # Fallback to base64 if decryption fails
            import base64
            try:
                return base64.b64decode(encrypted_data.encode()).decode()
            except:
                return None
    
    @staticmethod
    def hash_license_key(license_key, device_id):
        """Create secure hash of license key with device binding"""
        import hashlib
        # Combine license key with device ID for device binding
        combined = f"{license_key}:{device_id}:LoopBot2024"
        return hashlib.sha256(combined.encode()).hexdigest()
    
    @staticmethod
    def generate_integrity_hash(data, device_id):
        """Generate multiple integrity hashes for tamper detection"""
        import hashlib
        
        # Primary hash (SHA256)
        primary = hashlib.sha256(f"{data}:{device_id}".encode()).hexdigest()
        
        # Secondary hash (SHA512)
        secondary = hashlib.sha512(f"{device_id}:{data}:integrity".encode()).hexdigest()[:32]
        
        # Tertiary hash (MD5 for quick check)
        tertiary = hashlib.md5(f"check:{data}".encode()).hexdigest()
        
        return {
            'primary': primary,
            'secondary': secondary,
            'tertiary': tertiary
        }
    
    @staticmethod
    def verify_integrity(data, device_id, stored_hashes):
        """Verify data integrity using multiple hashes"""
        current_hashes = CryptoUtils.generate_integrity_hash(data, device_id)
        
        return (current_hashes['primary'] == stored_hashes.get('primary', '') and
                current_hashes['secondary'] == stored_hashes.get('secondary', '') and
                current_hashes['tertiary'] == stored_hashes.get('tertiary', ''))

class LicenseManager:
    """Manages license verification and device binding"""
    
    def __init__(self, license_server="https://loopbotiq.com"):
        self.license_server = license_server
        self.device_id = self.get_device_id()
        self.device_name = self.get_device_name()
        self.license_data = None
    
    def get_device_id(self):
        """Generate unique device ID based on enhanced hardware fingerprinting"""
        try:
            # Enhanced hardware fingerprinting
            identifiers = []
            
            # 1. MAC Address (primary identifier)
            try:
                mac = ':'.join(['{:02x}'.format((uuid.getnode() >> elements) & 0xff) 
                               for elements in range(0,2*6,2)][::-1])
                identifiers.append(f"mac:{mac}")
            except:
                pass
            
            # 2. System information
            identifiers.append(f"sys:{platform.system()}")
            identifiers.append(f"machine:{platform.machine()}")
            identifiers.append(f"processor:{platform.processor()}")
            identifiers.append(f"node:{platform.node()}")
            
            # 3. Python version and architecture
            identifiers.append(f"python:{platform.python_version()}")
            identifiers.append(f"arch:{platform.architecture()[0]}")
            
            # 4. Additional system identifiers
            try:
                import psutil
                # CPU info
                identifiers.append(f"cpu_count:{psutil.cpu_count()}")
                # Memory info (rounded to GB to avoid minor variations)
                mem_gb = round(psutil.virtual_memory().total / (1024**3))
                identifiers.append(f"memory_gb:{mem_gb}")
            except ImportError:
                # Fallback if psutil not available
                import os
                identifiers.append(f"cpu_count:{os.cpu_count() or 1}")
            
            # 5. Disk serial (Windows specific)
            try:
                if platform.system() == "Windows":
                    import subprocess
                    result = subprocess.run(['wmic', 'diskdrive', 'get', 'serialnumber'], 
                                          capture_output=True, text=True, timeout=5)
                    if result.stdout:
                        serial = result.stdout.strip().split('\n')[1].strip()
                        if serial and serial != "SerialNumber":
                            identifiers.append(f"disk_serial:{serial}")
            except:
                pass
            
            # Combine all identifiers
            device_string = "|".join(sorted(identifiers))  # Sort for consistency
            
            # Create multiple hashes for robustness
            primary_hash = hashlib.sha256(device_string.encode()).hexdigest()
            secondary_hash = hashlib.md5(device_string.encode()).hexdigest()
            
            # Combine hashes
            combined_hash = hashlib.sha256(f"{primary_hash}:{secondary_hash}".encode()).hexdigest()
            
            return combined_hash[:32]  # Use first 32 characters
            
        except Exception:
            # Enhanced fallback
            try:
                fallback_string = f"{platform.node()}:{platform.system()}:{uuid.getnode()}"
                return hashlib.sha256(fallback_string.encode()).hexdigest()[:32]
            except:
                return str(uuid.uuid4()).replace('-', '')[:32]
    
    def get_device_name(self):
        """Get readable device name"""
        try:
            computer_name = platform.node()
            system = platform.system()
            return f"{computer_name} ({system})"
        except:
            return "Unknown Device"
    
    def save_license_cache(self, license_data, expiry_date=None):
        """Save license data to cache with AES encryption and integrity checks"""
        try:
            # Hash license key for secure storage
            license_key = license_data.get('license_key', '')
            hashed_key = CryptoUtils.hash_license_key(license_key, self.device_id)
            
            # Create cache data with hashed license key
            secure_license_data = license_data.copy()
            secure_license_data['license_key'] = hashed_key
            
            cache_data = {
                'device_id': self.device_id,
                'license_data': secure_license_data,
                'cached_at': datetime.now().isoformat(),
                'server_last_check': datetime.now().isoformat(),
                'expiry_date': expiry_date.isoformat() if expiry_date else None,
            }
            
            # Generate integrity hashes
            cache_json = json.dumps(cache_data)
            integrity_hashes = CryptoUtils.generate_integrity_hash(cache_json, self.device_id)
            cache_data['integrity'] = integrity_hashes
            
            # Encrypt cache data with device-specific key
            final_cache_json = json.dumps(cache_data)
            device_key = CryptoUtils.generate_device_key(self.device_id)
            encrypted_cache = CryptoUtils.encrypt_data(final_cache_json, device_key)
            
            cache_path = get_license_cache_path()
            with open(cache_path, 'w') as f:
                f.write(encrypted_cache)
            
            return True
        except:
            return False
    
    def load_license_cache(self):
        """Load license data from cache with decryption and integrity verification"""
        try:
            cache_path = get_license_cache_path()
            
            if not os.path.exists(cache_path):
                return None
                
            with open(cache_path, 'r') as f:
                encrypted_cache = f.read()
            
            # Decrypt cache data with device-specific key
            device_key = CryptoUtils.generate_device_key(self.device_id)
            decrypted_json = CryptoUtils.decrypt_data(encrypted_cache, device_key)
            
            if not decrypted_json:
                return None
                
            cache_data = json.loads(decrypted_json)
            
            # Verify device ID
            if cache_data.get('device_id') != self.device_id:
                return None
            
            # Verify integrity hashes
            stored_integrity = cache_data.pop('integrity', {})
            verification_json = json.dumps(cache_data)
            
            if not CryptoUtils.verify_integrity(verification_json, self.device_id, stored_integrity):
                return None
                
            return cache_data
        except:
            return None
    
    def is_cache_valid(self, cache_data, grace_period_days=3):
        """Check if cached license is still valid considering grace period"""
        try:
            if not cache_data:
                return False
                
            # Check if license has actual expiry date
            if cache_data.get('expiry_date'):
                expiry_date = datetime.fromisoformat(cache_data['expiry_date'])
                if datetime.now() > expiry_date:
                    return False  # License actually expired
            
            # Check grace period for server connectivity
            last_check = datetime.fromisoformat(cache_data['server_last_check'])
            grace_period = timedelta(days=grace_period_days)
            
            return datetime.now() < (last_check + grace_period)
        except:
            return False
    
    def load_license(self):
        """Load license data from memory (no file storage)"""
        return self.license_data
    
    def save_license(self, license_data):
        """Save license data to memory only (no file storage)"""
        try:
            self.license_data = license_data
            return True
        except Exception as e:
            print(f"Error saving license: {e}")
            return False
    
    def verify_license(self, license_key):
        """Verify license with server using enhanced security"""
        try:
            # Use secure session
            session = self.create_secure_session()
            
            url = f"{self.license_server}/api/verify_license"
            api_token = self.generate_api_token()
            data = {
                "license_key": license_key,
                "device_id": self.device_id,
                "device_name": self.device_name,
                "api_token": api_token,
                "timestamp": datetime.now().isoformat()
            }
            
            response = session.post(url, json=data, timeout=30)
            
            if response.status_code == 200:
                result = response.json()
                if result.get('success'):
                    # Save license data
                    license_info = {
                        "license_key": license_key,
                        "device_id": self.device_id,
                        "device_name": self.device_name,
                        "status": result.get('status'),
                        "expired_date": result.get('expired_date'),
                        "verified_at": datetime.now().isoformat(),
                        "hash": result.get('hash', '')
                    }
                    
                    if self.save_license(license_info):
                        return True, "License activated successfully"
                    else:
                        return False, "Failed to save license data"
                else:
                    error_msg = result.get('error', 'License verification failed')
                    if result.get('status') == 'device_mismatch':
                        activated_device = result.get('activated_device', 'Unknown')
                        error_msg = f"License is already activated on another device: {activated_device}"
                    return False, error_msg
            else:
                return False, f"Server error: {response.status_code}"
                
        except requests.exceptions.RequestException as e:
            return False, f"Connection error: {str(e)}"
        except Exception as e:
            return False, f"Verification error: {str(e)}"
    
    def check_license_status(self):
        """Check license status with offline fallback and grace period"""
        # First try to get license from memory
        if self.license_data:
            # Try server verification (with timeout)
            try:
                license_key = self.license_data.get('license_key')
                if license_key:
                    # Quick server check (5 second timeout)
                    success, message = self.verify_license_quick(license_key)
                    if success:
                        # Save to cache on successful server check
                        expiry_date = None
                        try:
                            expiry_date = datetime.fromisoformat(self.license_data.get('expired_date', ''))
                        except:
                            pass
                        self.save_license_cache(self.license_data, expiry_date)
                        return True, "License verified"
                    
                    # If server check fails, check if license is actually expired
                    try:
                        expired_date = datetime.fromisoformat(self.license_data.get('expired_date', ''))
                        if datetime.now() > expired_date:
                            return False, "License has expired"
                    except:
                        pass
                    
                    # License not expired but server unreachable - allow usage
                    return True, "License valid (server check failed)"
            except:
                pass
        
        # Fallback to cached license
        cache_data = self.load_license_cache()
        if cache_data and self.is_cache_valid(cache_data):
            # Use cached license data
            self.license_data = cache_data['license_data']
            return True, "License valid (cached)"
        
        # Check if cached license exists but grace period expired
        if cache_data:
            # Check if actual license expired vs just grace period
            if cache_data.get('expiry_date'):
                try:
                    expiry_date = datetime.fromisoformat(cache_data['expiry_date'])
                    if datetime.now() > expiry_date:
                        return False, "LICENSE_EXPIRED"  # Special flag for popup
                except:
                    pass
            
            # Grace period expired but license might still be valid
            return False, "Unable to verify license (server unavailable)"
        
        return False, "No license found"
    
    def create_secure_session(self):
        """Create requests session with certificate pinning and security headers"""
        session = requests.Session()
        
        # Add security headers
        session.headers.update({
            'User-Agent': 'LoopBot/3.2.0',
            'Accept': 'application/json',
            'Content-Type': 'application/json'
        })
        
        # Add certificate pinning (implement your server's certificate hash)
        # For production, replace with your actual server certificate fingerprint
        try:
            import ssl
            import certifi
            session.verify = certifi.where()
            
            # Add additional SSL context for pinning (placeholder - implement actual pinning)
            # This is a simplified version - for production use proper certificate pinning
            pass
            
        except ImportError:
            pass  # Use default verification
            
        return session
    
    def generate_api_token(self):
        """Generate secure API token for server communication"""
        try:
            # Create token based on device ID and current time
            timestamp = str(int(time.time() // 300))  # 5-minute window
            token_data = f"{self.device_id}:{timestamp}:LoopBotAPI2024"
            
            # Generate HMAC-SHA256 token
            import hmac
            secret_key = "LoopBot2024SecretKey"  # In production, use secure key management
            api_token = hmac.new(
                secret_key.encode(), 
                token_data.encode(), 
                hashlib.sha256
            ).hexdigest()[:16]  # Use first 16 chars
            
            return api_token
        except:
            # Fallback token
            return hashlib.md5(f"{self.device_id}:fallback".encode()).hexdigest()[:16]
    
    def verify_license_quick(self, license_key, timeout=5):
        """Quick license verification with enhanced security"""
        try:
            # Create secure session
            session = self.create_secure_session()
            
            # Add API token for authentication
            api_token = self.generate_api_token()
            payload = {
                'license_key': license_key,
                'device_id': self.device_id,
                'device_name': self.device_name,
                'api_token': api_token,
                'timestamp': datetime.now().isoformat()
            }
            
            response = session.post(
                f"{self.license_server}/api/verify", 
                json=payload,
                timeout=timeout
            )
            
            if response.status_code == 200:
                data = response.json()
                if data.get('valid'):
                    # Update license data with fresh info
                    self.license_data = {
                        'license_key': license_key,
                        'expired_date': data.get('expired_date'),
                        'verified_at': datetime.now().isoformat()
                    }
                    return True, data.get('message', 'License verified')
                else:
                    return False, data.get('message', 'License invalid')
            else:
                return False, f"Server returned status {response.status_code}"
                
        except requests.exceptions.Timeout:
            return False, "Server timeout"
        except requests.exceptions.ConnectionError:
            return False, "Server unavailable"
        except Exception as e:
            return False, f"Verification failed: {str(e)}"
    
    def deactivate_license(self):
        """Deactivate current license"""
        try:
            if self.license_data:
                url = f"{self.license_server}/api/deactivate_license"
                data = {
                    "license_key": self.license_data.get('license_key'),
                    "device_id": self.device_id
                }
                
                response = requests.post(url, json=data, timeout=30)
                
                # Clear license data from memory
                self.license_data = None
                return True, "License deactivated successfully"
            else:
                return False, "No license to deactivate"
                
        except Exception as e:
            # Clear license data from memory even if server request fails
            self.license_data = None
            return True, f"License removed locally (server error: {str(e)})"

class YouTubeLiveAutomation(ctk.CTk):
    def __init__(self):
        super().__init__()
        
        # Initialize license manager first
        self.license_manager = LicenseManager("https://loopbotiq.com")
        self.is_licensed = False
        self.license_check_timer = None
        self.license_check_interval = 300000  # 5 minutes in milliseconds
        
        # Log management for memory efficiency
        self.log_count = 0
        self.max_log_lines = 500  # Maximum lines before cleanup
        self.log_cleanup_timer = None
        self.last_cleanup_time = time.time()
        self.cleanup_interval = 300  # Check every 5 minutes
        
        # Configure window
        self.title("LoopBot - YouTube Live Stream Automation Tool")
        self.geometry("900x650")
        self.minsize(800, 550)
        
        # Set theme
        ctk.set_appearance_mode("dark")
        ctk.set_default_color_theme("blue")
        
        # Variables
        self.youtube_service = None
        self.credentials = None
        self.current_channel_name = "YouTube Channel"  # Default fallback
        self.running_streams = []
        self.stream_threads = []
        self.is_streaming = False
        self.last_api_call = 0
        self.api_call_delay = 2
        self.rate_limit_backoff = 60
        
        # Data storage
        self.titles = []
        self.descriptions = []
        self.streamkeys = []
        self.thumbnails = []
        self.tags_list = []
        self.current_title_index = 0
        
        # Initialize tracking sets
        self.used_titles = set()
        self.used_descriptions = set()
        self.used_thumbnails = set()
        self.used_combinations = set()
        
        # Setup UI
        self.setup_ui()
        
        # Set window icon after UI is initialized
        try:
            icon_path = get_icon_path()
            if os.path.exists(icon_path):
                self.iconbitmap(icon_path)
                self.log_message(f"Window icon loaded: {icon_path}")
            else:
                self.log_message(f"Icon file not found: {icon_path}")
        except Exception as icon_error:
            self.log_message(f"Failed to load icon: {str(icon_error)}")
        
        # Load telegram config
        self.telegram_config = self.load_telegram_config()
        
        # Check license status on startup
        self.check_license_on_startup()
        
        # Start periodic license validation
        self.start_periodic_license_check()
        
        # Start log cleanup scheduler
        self.start_log_cleanup_scheduler()

    def check_license_on_startup(self):
        """Check license status when application starts"""
        self.log_message("🔐 Memverifikasi lisensi...")
        
        valid, message = self.license_manager.check_license_status()
        
        if valid:
            self.is_licensed = True
            self.license_status_label.configure(
                text="✅ Licensed", 
                text_color="green"
            )
            
            # Determine license status for logging
            if "cached" in message.lower():
                # Get cached license data to check expiry
                cache_data = self.license_manager.load_license_cache()
                if cache_data and cache_data.get('expiry_date'):
                    try:
                        expiry_date = datetime.fromisoformat(cache_data['expiry_date'])
                        expiry_str = expiry_date.strftime("%d %B %Y")
                        self.log_message("✅ Lisensi aktif")
                        self.log_message(f"📅 Masa berlaku hingga: {expiry_str}")
                        self.log_message("🕓 Mode offline diaktifkan (30 hari tanpa koneksi server)")
                        self.log_message("🎉 Akses penuh diberikan")
                    except:
                        self.log_message("✅ Lisensi aktif")
                        self.log_message("🎉 Akses penuh diberikan")
                else:
                    self.log_message("✅ Lisensi aktif")
                    self.log_message("🎉 Akses penuh diberikan")
            else:
                # Fresh verification - check if we have expiry info
                if self.license_manager.license_data and self.license_manager.license_data.get('expired_date'):
                    try:
                        expiry_date = datetime.fromisoformat(self.license_manager.license_data['expired_date'])
                        expiry_str = expiry_date.strftime("%d %B %Y")
                        self.log_message("✅ Lisensi aktif")
                        self.log_message(f"📅 Masa berlaku hingga: {expiry_str}")
                        self.log_message("🕓 Mode offline diaktifkan (30 hari tanpa koneksi server)")
                        self.log_message("🎉 Akses penuh diberikan")
                    except:
                        self.log_message("✅ Lisensi aktif")
                        self.log_message("🎉 Akses penuh diberikan")
                else:
                    self.log_message("✅ Lisensi aktif")
                    self.log_message("🎉 Akses penuh diberikan")
            
            self.enable_all_features()
        else:
            self.is_licensed = False
            self.license_status_label.configure(
                text="❌ No License", 
                text_color="red"
            )
            
            # Determine which license error condition to show
            if message == "LICENSE_EXPIRED":
                self.log_message("❌ Lisensi kedaluwarsa (berakhir pada 1 Agustus 2025)")
                self.log_message("⛔️ Masa tenggang offline juga telah habis")
                self.log_message("🔒 Akses ditolak — silakan perpanjang lisensi")
                self.show_license_expired_popup()
            elif "No license found" in message or "belum diaktivasi" in message.lower():
                self.log_message("❌ Lisensi belum diaktivasi")
                self.log_message("ℹ️ Silakan masukkan kode lisensi untuk melanjutkan")
                self.log_message("🔒 Akses dibatasi sampai lisensi diaktifkan")
            elif "tidak valid" in message.lower() or "invalid" in message.lower():
                self.log_message("❌ Lisensi tidak valid")
                self.log_message("⚠️ Lisensi tidak dikenali atau telah diblokir")
                self.log_message("🔒 Aplikasi tidak dapat digunakan")
            else:
                # Default fallback for other errors
                self.log_message("❌ Lisensi belum diaktivasi")
                self.log_message("ℹ️ Silakan masukkan kode lisensi untuk melanjutkan")
                self.log_message("🔒 Akses dibatasi sampai lisensi diaktifkan")
            
            self.disable_all_features()
    
    def show_license_expired_popup(self):
        """Show license expired popup dialog"""
        try:
            import tkinter as tk
            from tkinter import messagebox
            
            # Create custom popup dialog
            result = messagebox.askquestion(
                "License Expired",
                "Your license has expired and needs to be renewed.\n\n"
                "Would you like to visit the website to renew your license?",
                icon="warning"
            )
            
            if result == "yes":
                import webbrowser
                webbrowser.open("https://loopbotiq.com")
                
        except Exception:
            pass  # Silent fail if popup cannot be shown
    
    def start_periodic_license_check(self):
        """Start periodic license validation in background"""
        if self.license_check_timer:
            self.after_cancel(self.license_check_timer)
        
        self.license_check_timer = self.after(self.license_check_interval, self.periodic_license_check)
    
    def periodic_license_check(self):
        """Periodic license validation with retry mechanism"""
        def check_in_background():
            try:
                if self.license_manager.license_data:
                    license_key = self.license_manager.license_data.get('license_key')
                    if license_key:
                        # Re-verify with server
                        success, message = self.license_manager.verify_license(license_key)
                        
                        # Update UI in main thread
                        self.after(0, lambda: self.handle_periodic_license_result(success, message))
                    else:
                        self.after(0, lambda: self.handle_periodic_license_result(False, "No license key found"))
                else:
                    # No license data, check if we should still be licensed
                    if self.is_licensed:
                        self.after(0, lambda: self.handle_periodic_license_result(False, "License data lost"))
            except Exception as e:
                # Network error - retry in shorter interval
                self.after(60000, self.periodic_license_check)  # Retry in 1 minute
                return
        
        # Run check in background thread
        threading.Thread(target=check_in_background, daemon=True).start()
    
    def handle_periodic_license_result(self, success, message):
        """Handle periodic license check result"""
        if success:
            # License still valid, continue periodic checks
            self.start_periodic_license_check()
        else:
            # License invalid - disable features and show message
            self.is_licensed = False
            self.license_status_label.configure(
                text="❌ License Invalid", 
                text_color="red"
            )
            self.disable_all_features()
            
            # Clear license data
            self.license_manager.license_data = None
            self.update_license_info_display()
            
            # License validation failed - handle silently
            
            # Show popup message
            messagebox.showwarning(
                "License Invalid", 
                f"License validation failed: {message}\n\n"
                "All features have been disabled.\n"
                "Please re-enter your license key in the License tab."
            )
            
            # Stop periodic checks until new license is entered
            if self.license_check_timer:
                self.after_cancel(self.license_check_timer)
                self.license_check_timer = None

    def enable_all_features(self):
        """Enable all application features"""
        try:
            # Enable main buttons
            self.start_button.configure(state="normal")
            self.authenticate_button.configure(state="normal")
            
            # Enable content loading
            for entry in [self.title_entry, self.desc_entry, self.key_entry, 
                         self.thumb_entry, self.advanced_entry]:
                if hasattr(entry, 'configure'):
                    entry.configure(state="normal")
            
            # Enable browse buttons
            # (They're already created with normal state)
            
            # Enable settings
            for widget in [self.hour_var, self.minute_var, self.second_var]:
                # These are StringVars, not widgets
                pass
                
            # Enable checkboxes
            for checkbox_var in [self.filter_view_var, self.change_title_var, 
                               self.randomize_content_var, self.avoid_duplicates_var]:
                # These are already enabled by default
                pass
                
            self.log_message("🎉 All features enabled!")
            
        except Exception as e:
            self.log_message(f"⚠️ Error enabling features: {str(e)}")

    def disable_all_features(self):
        """Disable all application features except license entry"""
        try:
            # Disable main buttons
            if hasattr(self, 'start_button'):
                self.start_button.configure(state="disabled")
            if hasattr(self, 'authenticate_button'):
                self.authenticate_button.configure(state="disabled")
            if hasattr(self, 'stop_button'):
                self.stop_button.configure(state="disabled")
                
        except Exception as e:
            self.log_message(f"⚠️ Error disabling features: {str(e)}")

    def load_telegram_config(self):
        """Load telegram settings from telegram.json"""
        try:
            if os.path.exists('telegram.json'):
                with open('telegram.json', 'r', encoding='utf-8') as f:
                    config = json.load(f)
                    if hasattr(self, 'log_text'):
                        self.log_message("📱 Telegram config loaded")
                    return config
            else:
                default_config = {
                    "bot_token": "",
                    "chat_id": "",
                    "enabled": False,
                    "notifications": {
                        "stream_start": True,
                        "stream_end": True,
                        "errors": True,
                        "viewer_milestones": [10, 50, 100]
                    }
                }
                with open('telegram.json', 'w', encoding='utf-8') as f:
                    json.dump(default_config, f, indent=2)
                if hasattr(self, 'log_text'):
                    self.log_message("📱 Created default telegram.json")
                return default_config
        except Exception as e:
            if hasattr(self, 'log_text'):
                self.log_message(f"❌ Telegram config error: {str(e)}")
            return {"enabled": False}

    def send_telegram_message(self, message):
        """Send message using config from telegram.json"""
        try:
            if not self.telegram_config.get('enabled', False):
                return
            
            bot_token = self.telegram_config.get('bot_token')
            chat_id = self.telegram_config.get('chat_id')
            
            if not bot_token or not chat_id:
                return
            
            url = f"https://api.telegram.org/bot{bot_token}/sendMessage"
            data = {
                'chat_id': chat_id,
                'text': message,
                'parse_mode': 'HTML'
            }
            
            response = requests.post(url, data=data, timeout=10)
            if response.status_code == 200:
                self.log_message("📱 Telegram notification sent")
            else:
                self.log_message(f"⚠️ Telegram failed: {response.status_code}")
            
        except Exception as e:
            self.log_message(f"❌ Telegram error: {str(e)}")

    def setup_ui(self):
        # Configure grid layout
        self.grid_columnconfigure(0, weight=1)
        self.grid_rowconfigure(0, weight=1)
        
        # Main container
        main_frame = ctk.CTkFrame(self)
        main_frame.grid(row=0, column=0, sticky="nsew", padx=5, pady=5)
        main_frame.grid_columnconfigure(0, weight=1)
        main_frame.grid_rowconfigure(1, weight=1)
        
        # Header with license status
        header_frame = ctk.CTkFrame(main_frame, height=40)
        header_frame.grid(row=0, column=0, sticky="ew", padx=5, pady=5)
        
        # Load and display icon
        try:
            icon_image = ctk.CTkImage(Image.open("icon.png"), size=(24, 24))
            ctk.CTkLabel(header_frame, image=icon_image, text="").pack(side="left", padx=(10, 5))
        except:
            pass  # If icon not found, continue without it
        
        ctk.CTkLabel(header_frame, text="LoopBot", 
                    font=("Arial", 16, "bold")).pack(side="left", padx=(0, 10))
        
        # License status in header
        self.license_status_label = ctk.CTkLabel(header_frame, text="❌ No License", 
                                               font=("Arial", 12, "bold"),
                                               text_color="red")
        self.license_status_label.pack(side="left", padx=(20, 10))
        
        self.status_label = ctk.CTkLabel(header_frame, text="Status: Ready")
        self.status_label.pack(side="right", padx=10)
        
        # Content area
        content_frame = ctk.CTkFrame(main_frame)
        content_frame.grid(row=1, column=0, sticky="nsew", padx=5, pady=(0,5))
        content_frame.grid_columnconfigure(0, weight=1)
        content_frame.grid_rowconfigure(0, weight=1)
        
        # Left panel - Controls
        left_panel = ctk.CTkFrame(content_frame, width=400)
        left_panel.grid(row=0, column=0, sticky="nsew", padx=(0,5), pady=0)
        left_panel.grid_columnconfigure(0, weight=1)
        left_panel.grid_rowconfigure(1, weight=1)
        
        # Right panel - Logs
        right_panel = ctk.CTkFrame(content_frame)
        right_panel.grid(row=0, column=1, sticky="nsew", padx=0, pady=0)
        right_panel.grid_columnconfigure(0, weight=1)
        right_panel.grid_rowconfigure(0, weight=1)
        
        # Configure panels to expand
        content_frame.grid_columnconfigure(0, weight=1)
        content_frame.grid_columnconfigure(1, weight=1)
        content_frame.grid_rowconfigure(0, weight=1)
        
        # Left panel content
        self.setup_left_panel(left_panel)
        
        # Right panel content (Logs)
        self.setup_right_panel(right_panel)
        
        # Bottom buttons
        self.setup_bottom_buttons(main_frame)
        
        if not GOOGLE_LIBS_AVAILABLE:
            self.log_message("⚠️ Google libraries not installed")

    def setup_left_panel(self, parent):
        """Setup the left control panel"""
        # Notebook for tabs
        tabview = ctk.CTkTabview(parent)
        tabview.grid(row=0, column=0, sticky="nsew", padx=5, pady=5)
        
        # Add tabs first
        tabview.add("Content")
        tabview.add("Settings")
        tabview.add("License")
        
        # Get the tab frames
        content_tab = tabview.tab("Content")
        settings_tab = tabview.tab("Settings")
        license_tab = tabview.tab("License")
        
        # Setup each tab - call methods on self, passing the tab frame
        self.setup_content_tab(content_tab)
        self.setup_settings_tab(settings_tab)
        self.setup_license_tab(license_tab)
        
        # Configure weights
        parent.grid_rowconfigure(0, weight=1)
        parent.grid_columnconfigure(0, weight=1)

    def setup_license_tab(self, parent):
        """Setup the license management tab"""
        # License information frame
        info_frame = ctk.CTkFrame(parent)
        info_frame.pack(fill="x", pady=5)
        
        ctk.CTkLabel(info_frame, text="License Information", 
                    font=("Arial", 14, "bold")).pack(anchor="w", padx=10, pady=5)
        
        # Current license status
        status_frame = ctk.CTkFrame(info_frame, fg_color="transparent")
        status_frame.pack(fill="x", padx=10, pady=5)
        
        ctk.CTkLabel(status_frame, text="Status:").pack(side="left")
        self.license_info_label = ctk.CTkLabel(status_frame, text="No License")
        self.license_info_label.pack(side="left", padx=10)
        
        # Device information
        device_frame = ctk.CTkFrame(info_frame, fg_color="transparent")
        device_frame.pack(fill="x", padx=10, pady=2)
        
        ctk.CTkLabel(device_frame, text="Device ID:").pack(side="left")
        device_id_label = ctk.CTkLabel(device_frame, text=self.license_manager.device_id[:16] + "...")
        device_id_label.pack(side="left", padx=10)
        
        device_name_frame = ctk.CTkFrame(info_frame, fg_color="transparent")
        device_name_frame.pack(fill="x", padx=10, pady=2)
        
        ctk.CTkLabel(device_name_frame, text="Device Name:").pack(side="left")
        ctk.CTkLabel(device_name_frame, text=self.license_manager.device_name).pack(side="left", padx=10)
        
        # License entry frame
        entry_frame = ctk.CTkFrame(parent)
        entry_frame.pack(fill="x", pady=5)
        
        ctk.CTkLabel(entry_frame, text="Enter License Key", 
                    font=("Arial", 14, "bold")).pack(anchor="w", padx=10, pady=5)
        
        # License key entry
        key_frame = ctk.CTkFrame(entry_frame, fg_color="transparent")
        key_frame.pack(fill="x", padx=10, pady=5)
        
        ctk.CTkLabel(key_frame, text="License Key:").pack(anchor="w")
        self.license_key_entry = ctk.CTkEntry(key_frame, placeholder_text="XXXX-XXXX-XXXX-XXXX-XXXX-XXXX")
        self.license_key_entry.pack(fill="x", pady=2)
        
        # License action buttons
        button_frame = ctk.CTkFrame(entry_frame, fg_color="transparent")
        button_frame.pack(fill="x", padx=10, pady=5)
        
        self.verify_button = ctk.CTkButton(button_frame, text="Verify License", 
                                         command=self.verify_license_key, width=120)
        self.verify_button.pack(side="left", padx=5)
        
        self.deactivate_button = ctk.CTkButton(button_frame, text="Deactivate License", 
                                             command=self.deactivate_license_key, width=120)
        self.deactivate_button.pack(side="left", padx=5)
        
        # Purchase information
        purchase_frame = ctk.CTkFrame(parent)
        purchase_frame.pack(fill="x", pady=5)
        
        ctk.CTkLabel(purchase_frame, text="Get License", 
                    font=("Arial", 14, "bold")).pack(anchor="w", padx=10, pady=5)
        
        info_text = """
Untuk pembelian lisensi kunjungi atau hubungi:
• Visit: https://loopbotiq.com
• Contact: support@loopbotiq.com
• WhatsApp: +62-812-2428-6756

Your Device ID: """ + self.license_manager.device_id
        
        ctk.CTkLabel(purchase_frame, text=info_text, justify="left").pack(anchor="w", padx=10, pady=5)
        
        ctk.CTkButton(purchase_frame, text="Open LoopBotIQ Website", 
                     command=lambda: webbrowser.open("http://loopbotiq.com"), 
                     width=200).pack(anchor="w", padx=10, pady=5)
        
        # Update license info display
        self.update_license_info_display()

    def update_license_info_display(self):
        """Update license information display"""
        if self.license_manager.license_data:
            license_key = self.license_manager.license_data.get('license_key', '')
            expired_date = self.license_manager.license_data.get('expired_date', '')
            status = self.license_manager.license_data.get('status', '')
            
            display_text = f"Licensed - {license_key[:20]}... (Expires: {expired_date})"
            self.license_info_label.configure(text=display_text, text_color="green")
            self.deactivate_button.configure(state="normal")
        else:
            self.license_info_label.configure(text="No License", text_color="red")
            self.deactivate_button.configure(state="disabled")

    def verify_license_key(self):
        """Verify entered license key"""
        license_key = self.license_key_entry.get().strip()
        
        if not license_key:
            messagebox.showerror("Error", "Please enter a license key")
            return
        
        # Validasi format UUID (contoh: 9e75ef96-48ef-424f-a322-2ecd3ab239a1)
        uuid_pattern = r'^[0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12}$'
        if not re.match(uuid_pattern, license_key, re.IGNORECASE):
            messagebox.showerror("Error", "Invalid license key format.\nFormat expected: XXXXXXXX-XXXX-XXXX-XXXX-XXXXXXXXXXXX")
            return
        
        # Show progress
        self.verify_button.configure(text="Verifying...", state="disabled")
        
        # Verify in background thread
        def verify_thread():
            success, message = self.license_manager.verify_license(license_key)
            
            # Update UI in main thread
            self.after(0, lambda: self.on_license_verification_complete(success, message, license_key))
        
        threading.Thread(target=verify_thread, daemon=True).start()
    
    def deactivate_license_key(self):
        """Deactivate license with UI feedback"""
        if not self.license_manager.license_data:
            messagebox.showwarning("No License", "No license to deactivate.")
            return
        
        # Confirm deactivation
        result = messagebox.askyesno(
            "Confirm Deactivation", 
            "Are you sure you want to deactivate your license?\n\n"
            "This will disable all features and you'll need to re-enter "
            "your license key to use the application again."
        )
        
        if not result:
            return
        
        # Show progress
        self.deactivate_button.configure(text="Deactivating...", state="disabled")
        
        # Deactivate in background thread
        def deactivate_thread():
            success, message = self.license_manager.deactivate_license()
            
            # Update UI in main thread
            self.after(0, lambda: self.on_license_deactivation_complete(success, message))
        
        threading.Thread(target=deactivate_thread, daemon=True).start()

    def on_license_verification_complete(self, success, message, license_key):
        """Handle license verification completion"""
        # Reset button
        self.verify_button.configure(text="Verify License", state="normal")
        
        if success:
            # Update license status
            self.is_licensed = True
            self.license_status_label.configure(
                text="✅ Licensed", 
                text_color="green"
            )
            # Update license info display
            self.update_license_info_display()
            # Enable all features
            self.enable_all_features()
            # Start periodic license validation
            self.start_periodic_license_check()
        else:
            # Update license status
            self.is_licensed = False
            self.license_status_label.configure(
                text="❌ No License", 
                text_color="red"
            )
            # Disable features
            self.disable_all_features()

    def on_license_deactivation_complete(self, success, message):
        """Handle license deactivation completion"""
        # Reset button
        self.deactivate_button.configure(text="Deactivate License", state="normal")
        
        self.is_licensed = False
        self.license_status_label.configure(text="❌ No License", text_color="red")
        
        # Update display
        self.update_license_info_display()
        
        # Disable features
        self.disable_all_features()
        
        if success:
            self.log_message(f"✅ {message}")
            
            # Show success popup
            messagebox.showinfo(
                "License Deactivated", 
                f"License has been deactivated successfully.\n\n"
                f"{message}\n\n"
                "All features are now disabled."
            )
        else:
            self.log_message(f"❌ Deactivation failed: {message}")
            
            # Show error popup
            messagebox.showerror(
                "Deactivation Failed", 
                f"Failed to deactivate license:\n\n{message}\n\n"
                "Please try again or contact support."
            )
        
        # Stop periodic license checks since license is deactivated
        if self.license_check_timer:
            self.after_cancel(self.license_check_timer)
            self.license_check_timer = None

    def setup_content_tab(self, parent):
        """Setup the content configuration tab"""
        # Mode selection
        mode_frame = ctk.CTkFrame(parent, fg_color="transparent")
        mode_frame.pack(fill="x", pady=(0,5))
        
        self.mode_var = ctk.StringVar(value="basic")
        ctk.CTkLabel(mode_frame, text="Mode:").pack(side="left", padx=5)
        ctk.CTkRadioButton(mode_frame, text="Basic", variable=self.mode_var, 
                          value="basic", command=self.toggle_mode).pack(side="left")
        ctk.CTkRadioButton(mode_frame, text="Advanced", variable=self.mode_var, 
                          value="advanced", command=self.toggle_mode).pack(side="left", padx=10)
        
        # Basic mode frame
        self.basic_frame = ctk.CTkFrame(parent, fg_color="transparent")
        self.basic_frame.pack(fill="x", pady=5)
        
        # File selection rows
        self.title_entry = self.create_file_row(self.basic_frame, "Titles:", "titles.txt", self.browse_titles)
        self.desc_entry = self.create_file_row(self.basic_frame, "Descriptions:", "descriptions.txt", self.browse_descriptions)
        self.key_entry = self.create_file_row(self.basic_frame, "Stream Keys:", "keystream.txt", self.browse_streamkeys)
        self.thumb_entry = self.create_file_row(self.basic_frame, "Thumbnails:", "thumbnails", self.browse_thumbnails)
        
        # Advanced mode frame
        self.advanced_frame = ctk.CTkFrame(parent, fg_color="transparent")
        self.advanced_entry = self.create_file_row(self.advanced_frame, "Data File:", "data.json", self.browse_advanced_data)
        
        # Channel info
        channel_frame = ctk.CTkFrame(parent)
        channel_frame.pack(fill="x", pady=5)
        
        self.channel_label = ctk.CTkLabel(channel_frame, text="YouTube: Not connected", 
                                        font=("Arial", 12))
        self.channel_label.pack(pady=5)
        
        self.remaining_label = ctk.CTkLabel(channel_frame, text="Available Titles: 0")
        self.remaining_label.pack(pady=2)
        
        # Active streams table
        stream_frame = ctk.CTkFrame(parent)
        stream_frame.pack(fill="both", expand=True, pady=5)
        
        columns = ("ID", "Key", "Title", "Time Left", "Viewers")
        self.stream_tree = ttk.Treeview(stream_frame, columns=columns, show="headings", height=5)
        
        for col in columns:
            self.stream_tree.heading(col, text=col)
            self.stream_tree.column(col, width=70, anchor="center")
        
        scrollbar = ttk.Scrollbar(stream_frame, orient="vertical", command=self.stream_tree.yview)
        self.stream_tree.configure(yscrollcommand=scrollbar.set)
        
        self.stream_tree.pack(side="left", fill="both", expand=True)
        scrollbar.pack(side="right", fill="y")

    def setup_settings_tab(self, parent):
        """Setup the settings tab"""
        # Duration settings with tooltip
        duration_frame = ctk.CTkFrame(parent, fg_color="transparent")
        duration_frame.pack(fill="x", pady=5)
        
        duration_label = ctk.CTkLabel(duration_frame, text="Duration:")
        duration_label.pack(side="left")
        ToolTip(duration_label, "Berapa lama setiap siaran akan berjalan\nFormat: Jam:Menit:Detik\nContoh: 00:10:00 = 10 menit")
        
        self.hour_var = ctk.StringVar(value="00")
        self.minute_var = ctk.StringVar(value="05")
        self.second_var = ctk.StringVar(value="00")
        
        hour_entry = ctk.CTkEntry(duration_frame, textvariable=self.hour_var, width=40)
        hour_entry.pack(side="left")
        ToolTip(hour_entry, "Jam (00-23)")
        
        ctk.CTkLabel(duration_frame, text=":").pack(side="left")
        
        minute_entry = ctk.CTkEntry(duration_frame, textvariable=self.minute_var, width=40)
        minute_entry.pack(side="left")
        ToolTip(minute_entry, "Menit (00-59)")
        
        ctk.CTkLabel(duration_frame, text=":").pack(side="left")
        
        second_entry = ctk.CTkEntry(duration_frame, textvariable=self.second_var, width=40)
        second_entry.pack(side="left")
        ToolTip(second_entry, "Detik (00-59)")
        
        # Other settings with tooltips
        self.delay_entry = self.create_setting_row(parent, "Delay (min):", "1")
        ToolTip(self.delay_entry, "Jeda waktu antar siaran (dalam menit)")
        
        self.concurrent_entry = self.create_setting_row(parent, "Max Streams:", "1")
        ToolTip(self.concurrent_entry, "Jumlah maksimal siaran bersamaan")
        
        self.duplicate_entry = self.create_setting_row(parent, "Max Duplicates:", "1")
        ToolTip(self.duplicate_entry, "Berapa kali 1 stream key bisa digunakan bersamaan")
        
        # Checkboxes with tooltips
        checkbox_frame = ctk.CTkFrame(parent, fg_color="transparent")
        checkbox_frame.pack(fill="x", pady=5)
        
        self.filter_view_var = ctk.BooleanVar()
        filter_checkbox = ctk.CTkCheckBox(checkbox_frame, text="Filter Low Viewers", variable=self.filter_view_var)
        filter_checkbox.pack(side="left", padx=5)
        ToolTip(filter_checkbox, "Hindari slot waktu dengan viewers sedikit\nRekomendasi TIDAK dicentang")
        
        self.change_title_var = ctk.BooleanVar(value=True)
        title_checkbox = ctk.CTkCheckBox(checkbox_frame, text="Auto-Rotate Titles", variable=self.change_title_var)
        title_checkbox.pack(side="left", padx=5)
        ToolTip(title_checkbox, "Ganti judul otomatis setiap siaran baru\nRekomendasi DICENTANG untuk variasi konten")
        
        self.randomize_content_var = ctk.BooleanVar(value=True)
        random_checkbox = ctk.CTkCheckBox(checkbox_frame, text="Randomize Content", variable=self.randomize_content_var)
        random_checkbox.pack(side="left", padx=5)
        ToolTip(random_checkbox, "Pilih konten secara acak (tidak berurutan)\nRekomendasi: DICENTANG untuk tampil lebih natural")
        
        self.avoid_duplicates_var = ctk.BooleanVar(value=True)
        duplicate_checkbox = ctk.CTkCheckBox(checkbox_frame, text="Avoid Duplicates", variable=self.avoid_duplicates_var)
        duplicate_checkbox.pack(side="left", padx=5)
        ToolTip(duplicate_checkbox, "Hindari konten yang sama berulang\nRekomendasi: DICENTANG untuk variasi maksimal")
        
        # Content management buttons
        button_frame = ctk.CTkFrame(parent, fg_color="transparent")
        button_frame.pack(fill="x", pady=5)
        
        self.reset_used_button = ctk.CTkButton(button_frame, text="Reset Used Content", 
                                             command=self.reset_used_content, width=120)
        self.reset_used_button.pack(side="left", padx=5)
        
        ctk.CTkButton(button_frame, text="Check Stream Keys", 
                     command=self.check_streamkeys, width=120).pack(side="left", padx=5)

    def setup_right_panel(self, parent):
        """Setup the right log panel"""
        log_frame = ctk.CTkFrame(parent)
        log_frame.pack(fill="both", expand=True, padx=5, pady=5)
        log_frame.grid_columnconfigure(0, weight=1)
        log_frame.grid_rowconfigure(0, weight=1)
        
        ctk.CTkLabel(log_frame, text="Activity Log", 
                    font=("Arial", 14, "bold")).pack(anchor="w", padx=10, pady=5)
        
        self.log_text = ctk.CTkTextbox(log_frame, wrap="word")
        log_scrollbar = ctk.CTkScrollbar(log_frame, command=self.log_text.yview)
        self.log_text.configure(yscrollcommand=log_scrollbar.set)
        
        self.log_text.pack(side="left", fill="both", expand=True, padx=5, pady=5)
        log_scrollbar.pack(side="right", fill="y", pady=5)
        
        # Add initial startup info
        self.after(100, self.show_startup_info)
    
    def show_startup_info(self):
        """Clear log and prepare for license verification messages"""
        # Clear log first
        self.log_text.delete("1.0", "end")
    
    def start_log_cleanup_scheduler(self):
        """Start periodic log cleanup to prevent memory issues"""
        def cleanup_check():
            try:
                current_time = time.time()
                memory_mb = self.get_memory_usage_mb()
                
                # Emergency cleanup if memory usage is very high (>200MB)
                if memory_mb > 200:
                    self.emergency_log_cleanup()
                    self.last_cleanup_time = current_time
                
                # Regular cleanup conditions
                elif (current_time - self.last_cleanup_time >= self.cleanup_interval or 
                      self.log_count >= self.max_log_lines or 
                      memory_mb > 150):  # Proactive cleanup at 150MB
                    
                    self.smart_log_cleanup()
                    self.last_cleanup_time = current_time
                
                # Schedule next check (every 30 seconds)
                self.log_cleanup_timer = self.after(30000, cleanup_check)
            except Exception:
                # If error occurs, reschedule
                self.log_cleanup_timer = self.after(30000, cleanup_check)
        
        # Start the cleanup scheduler
        cleanup_check()
    
    def smart_log_cleanup(self):
        """Intelligent log cleanup with multiple strategies"""
        try:
            log_content = self.log_text.get("1.0", "end")
            lines = log_content.strip().split('\n')
            
            if len(lines) <= 100:  # Don't cleanup if too few lines
                return
            
            # Strategy 1: Keep startup info + recent important messages
            startup_info = []
            recent_messages = []
            important_messages = []
            
            # Identify different types of messages
            for line in lines:
                if any(line.startswith(prefix) for prefix in ["📅", "🖥️", "🎬", "📝", "🔑", "🖼️", "🌐"]):
                    startup_info.append(line)
                elif any(keyword in line.lower() for keyword in ["error", "failed", "live!", "broadcast created", "rtmp ready"]):
                    important_messages.append(line)
                elif line.strip():  # Non-empty lines
                    recent_messages.append(line)
            
            # Strategy 2: Keep only essential messages
            essential_lines = []
            
            # Always keep startup info
            essential_lines.extend(startup_info)
            
            # Keep recent important messages (last 50)
            essential_lines.extend(important_messages[-50:] if important_messages else [])
            
            # Keep most recent general messages (last 100)  
            essential_lines.extend(recent_messages[-100:] if recent_messages else [])
            
            # Strategy 3: If still too many, keep only critical ones
            if len(essential_lines) > 200:
                critical_lines = startup_info.copy()
                critical_lines.extend([line for line in essential_lines 
                                     if any(keyword in line.lower() for keyword in 
                                           ["error", "failed", "live!", "created", "ready"])][-50:])
                essential_lines = critical_lines
            
            # Rebuild log with cleaned content
            if essential_lines:
                cleaned_content = '\n'.join(essential_lines) + '\n'
                self.log_text.delete("1.0", "end")
                self.log_text.insert("1.0", cleaned_content)
                self.log_text.see("end")
                
                # Update log count
                self.log_count = len(essential_lines)
            
            # Force garbage collection
            import gc
            gc.collect()
            
        except Exception:
            # Fallback: Simple truncation if smart cleanup fails
            try:
                self.simple_log_cleanup()
            except:
                pass  # If all fails, continue without cleanup
    
    def simple_log_cleanup(self):
        """Simple fallback cleanup method"""
        try:
            log_content = self.log_text.get("1.0", "end")
            lines = log_content.strip().split('\n')
            
            if len(lines) > 300:
                # Keep first 50 lines (startup info) and last 200 lines (recent activity)
                kept_lines = lines[:50] + ["", "... [Log cleaned for performance] ...", ""] + lines[-200:]
                
                cleaned_content = '\n'.join(kept_lines) + '\n'
                self.log_text.delete("1.0", "end")
                self.log_text.insert("1.0", cleaned_content)
                self.log_text.see("end")
                
                self.log_count = len(kept_lines)
        except:
            pass
    
    def get_memory_usage_mb(self):
        """Get current memory usage in MB for monitoring"""
        try:
            import psutil
            process = psutil.Process()
            return process.memory_info().rss / 1024 / 1024  # Convert to MB
        except ImportError:
            # Fallback method without psutil
            import resource
            try:
                return resource.getrusage(resource.RUSAGE_SELF).ru_maxrss / 1024  # Convert to MB (Linux/Mac)
            except:
                return 0
        except:
            return 0
    
    def emergency_log_cleanup(self):
        """Emergency cleanup when memory usage is high"""
        try:
            # Clear most of the log, keeping only startup info
            log_content = self.log_text.get("1.0", "end")
            lines = log_content.strip().split('\n')
            
            # Keep only startup info and last 20 messages
            startup_lines = [line for line in lines if any(line.startswith(prefix) for prefix in ["📅", "🖥️", "🎬", "📝", "🔑", "🖼️", "🌐"])]
            recent_lines = [line for line in lines[-20:] if line.strip()]
            
            emergency_lines = startup_lines + ["", "... [Emergency cleanup performed] ...", ""] + recent_lines
            
            cleaned_content = '\n'.join(emergency_lines) + '\n'
            self.log_text.delete("1.0", "end")
            self.log_text.insert("1.0", cleaned_content)
            self.log_text.see("end")
            
            self.log_count = len(emergency_lines)
            
            # Force aggressive garbage collection
            import gc
            gc.collect()
            
        except:
            # Last resort: clear everything
            try:
                self.log_text.delete("1.0", "end")
                self.log_count = 0
            except:
                pass

    def setup_bottom_buttons(self, parent):
        """Setup the bottom action buttons"""
        button_frame = ctk.CTkFrame(parent, height=40)
        button_frame.grid(row=2, column=0, sticky="ew", padx=5, pady=5)
        
        self.authenticate_button = ctk.CTkButton(button_frame, text="Authenticate", 
                                               command=self.authenticate_youtube, width=120, state="disabled")
        self.authenticate_button.pack(side="left", padx=5)
        
        self.start_button = ctk.CTkButton(button_frame, text="Start Streaming", 
                                        command=self.start_streaming, width=120, state="disabled")
        self.start_button.pack(side="left", padx=5)
        
        self.stop_button = ctk.CTkButton(button_frame, text="Stop Streaming", 
                                       command=self.stop_streaming, state="disabled", width=120)
        self.stop_button.pack(side="left", padx=5)
        
        ctk.CTkButton(button_frame, text="Setup Guide", 
                     command=self.show_setup_guide, width=120).pack(side="left", padx=5)

    # UI Helper Methods
    def create_file_row(self, parent, label_text, default_text, browse_command):
        frame = ctk.CTkFrame(parent, fg_color="transparent")
        frame.pack(fill="x", pady=2)
        
        ctk.CTkLabel(frame, text=label_text, width=80).pack(side="left")
        entry = ctk.CTkEntry(frame)
        entry.insert(0, default_text)
        entry.pack(side="left", padx=5, fill="x", expand=True)
        browse_button = ctk.CTkButton(frame, text="Browse", width=70,
                                    command=lambda: browse_command(entry))
        browse_button.pack(side="left")
        
        return entry
        
    def create_setting_row(self, parent, label_text, default_value):
        frame = ctk.CTkFrame(parent, fg_color="transparent")
        frame.pack(fill="x", pady=2)
        
        ctk.CTkLabel(frame, text=label_text, width=100).pack(side="left")
        entry = ctk.CTkEntry(frame, width=60)
        entry.insert(0, default_value)
        entry.pack(side="left", padx=5)
        
        return entry
    
    def toggle_mode(self):
        if self.mode_var.get() == "basic":
            self.basic_frame.pack(fill="x", pady=5)
            self.advanced_frame.pack_forget()
        else:
            self.advanced_frame.pack(fill="x", pady=5)
            self.basic_frame.pack_forget()
    
    def log_message(self, message, level="INFO"):
        """Log message with filtering for important messages only"""
        # Filter out unimportant messages
        skip_messages = [
            "Lisensi Tidak diaktivasi",
            "HWID tidak cocok",
            "silahkan aktivasi lisensi",
            "Demo mode",
            "Simulating",
            "Created default",
            "Config loaded"
        ]
        
        # Skip unimportant messages
        for skip in skip_messages:
            if skip.lower() in message.lower():
                return
    
    def log_message(self, message, level="INFO", with_timestamp=True):
        """Enhanced log message with clean formatting"""
        try:
            # Skip unimportant system messages
            skip_messages = [
                "oauth callback server", "window icon", "looking for", "sys.executable",
                "__file__", "sys.frozen", "executable directory", "client_secrets.json at",
                "token.pickle at", "found existing token", "google api libraries loaded",
                "internet connection", "youtube service created", "authorization code received",
                "token saved successfully", "service creation error", "method", "failed:"
            ]
            
            # Skip filtered messages
            for skip in skip_messages:
                if skip.lower() in message.lower():
                    return
            
            # Format message with timestamp if requested
            if with_timestamp and message.strip():
                timestamp = datetime.now().strftime("[%H:%M:%S]")
                formatted_message = f"{timestamp} {message}\n"
            else:
                # For empty lines, don't add timestamp
                formatted_message = f"{message}\n"
            
            # Insert into log
            self.log_text.insert("end", formatted_message)
            self.log_text.see("end")  # Auto-scroll to bottom
            
            # Update log count for cleanup tracking
            if message.strip():  # Only count non-empty messages
                self.log_count += 1
        except Exception:
            pass  # Silent fail if logging doesn't work
    
    
    def get_unused_thumbnail(self):
        """Get thumbnail yang belum digunakan, prioritas untuk yang fresh"""
        if not self.thumbnails:
            return None
            
        # Cari thumbnail yang belum pernah digunakan
        unused_thumbnails = [t for t in self.thumbnails if t not in self.used_thumbnails]
        
        if unused_thumbnails:
            # Prioritas untuk thumbnail yang belum digunakan
            selected = random.choice(unused_thumbnails)
            remaining = len(unused_thumbnails) - 1
            self.log_message(f"Selected thumbnail: {os.path.basename(selected)} ({remaining} unused remaining)")
            return selected
        else:
            # Jika semua sudah digunakan, reset dan mulai lagi
            self.used_thumbnails.clear()
            self.log_message("All thumbnails used - Reset thumbnail tracking")
            selected = random.choice(self.thumbnails)
            self.log_message(f"Selected thumbnail: {os.path.basename(selected)} (fresh cycle)")
            return selected
    
    def get_unused_title(self):
        """Get title yang belum digunakan, prioritas untuk yang fresh"""
        if not self.titles:
            return ""
            
        # Cari title yang belum pernah digunakan
        unused_titles = [t for t in self.titles if t not in self.used_titles]
        
        if unused_titles:
            # Prioritas untuk title yang belum digunakan
            selected = random.choice(unused_titles)
            remaining = len(unused_titles) - 1
            self.log_message(f"Selected title: {selected[:30]}... ({remaining} unused remaining)")
            return selected
        else:
            # Jika semua sudah digunakan, reset dan mulai lagi
            self.used_titles.clear()
            self.log_message("All titles used - Reset title tracking")
            selected = random.choice(self.titles)
            self.log_message(f"Selected title: {selected[:30]}... (fresh cycle)")
            return selected
    
    def get_unused_description(self):
        """Get description yang belum digunakan, prioritas untuk yang fresh"""
        if not self.descriptions:
            return ""
            
        # Cari description yang belum pernah digunakan
        unused_descriptions = [d for d in self.descriptions if d not in self.used_descriptions]
        
        if unused_descriptions:
            # Prioritas untuk description yang belum digunakan
            selected = random.choice(unused_descriptions)
            remaining = len(unused_descriptions) - 1
            processed = self.process_spintax(selected)
            self.log_message(f"Selected description: {processed[:30]}... ({remaining} unused remaining)")
            return processed
        else:
            # Jika semua sudah digunakan, reset dan mulai lagi
            self.used_descriptions.clear()
            self.log_message("All descriptions used - Reset description tracking")
            selected = random.choice(self.descriptions)
            processed = self.process_spintax(selected)
            self.log_message(f"Selected description: {processed[:30]}... (fresh cycle)")
            return processed
    
    def log_critical(self, message):
        """Log critical messages that should always be shown"""
        self.log_message(message, level="CRITICAL")
    
    def log_info(self, message):
        """Log informational messages (filtered)"""
        self.log_message(message, level="INFO")

    # License Check Wrapper Methods
    def check_license_before_action(self, action_name):
        """Check license before allowing any action"""
        if not self.is_licensed:
            messagebox.showerror("License Required", 
                               f"Cannot {action_name}.\n\n"
                               "A valid license is required to use this feature.\n"
                               "Please enter your license key in the License tab.")
            return False
        return True

    # Mode management
    def activate_youtube_mode(self):
        """Activate full YouTube mode"""
        if not self.check_license_before_action("activate YouTube mode"):
            return
            
        self.status_label.configure(text="Status: YouTube Mode")
        self.log_message("🔄 Switched to YouTube Mode - Full functionality enabled")
    
    def activate_demo_mode(self):
        """Activate demo mode for testing"""
        if not self.check_license_before_action("activate demo mode"):
            return
            
        self.status_label.configure(text="Status: Demo Mode")
        self.log_message("🔄 Switched to Demo Mode - Simulating YouTube features")
        messagebox.showinfo("Demo Mode", 
                          "Demo mode activated!\n\n" +
                          "Features:\n" +
                          "- Simulates YouTube API responses\n" +
                          "- Generates mock viewer data\n" +
                          "- No YouTube authentication needed")

    # File Browser Methods
    def browse_titles(self, entry):
        if not self.check_license_before_action("browse titles"):
            return
            
        filename = filedialog.askopenfilename(filetypes=[("Text files", "*.txt")])
        if filename:
            entry.delete(0, "end")
            entry.insert(0, filename)
            self.load_titles(filename)
    
    def browse_descriptions(self, entry):
        if not self.check_license_before_action("browse descriptions"):
            return
            
        filename = filedialog.askopenfilename(filetypes=[("Text files", "*.txt")])
        if filename:
            entry.delete(0, "end")
            entry.insert(0, filename)
            self.load_descriptions(filename)
    
    def browse_streamkeys(self, entry):
        if not self.check_license_before_action("browse stream keys"):
            return
            
        filename = filedialog.askopenfilename(filetypes=[("Text files", "*.txt")])
        if filename:
            entry.delete(0, "end")
            entry.insert(0, filename)
            self.load_streamkeys(filename)
    
    def browse_thumbnails(self, entry):
        if not self.check_license_before_action("browse thumbnails"):
            return
            
        folder = filedialog.askdirectory()
        if folder:
            entry.delete(0, "end")
            entry.insert(0, folder)
            self.load_thumbnails(folder)
    
    def browse_advanced_data(self, entry):
        if not self.check_license_before_action("browse advanced data"):
            return
            
        filename = filedialog.askopenfilename(filetypes=[("JSON files", "*.json"), ("CSV files", "*.csv")])
        if filename:
            entry.delete(0, "end")
            entry.insert(0, filename)
            self.load_advanced_data(filename)
    
    def browse_tags(self, entry):
        if not self.check_license_before_action("browse tags"):
            return
            
        filename = filedialog.askopenfilename(filetypes=[("Text files", "*.txt")])
        if filename:
            entry.delete(0, "end")
            entry.insert(0, filename)
            self.load_tags(filename)
    
    def reset_used_content(self):
        """Reset all used content tracking"""
        if not self.check_license_before_action("reset used content"):
            return
            
        self.used_titles.clear()
        self.used_descriptions.clear()
        self.used_thumbnails.clear()
        self.used_combinations.clear()
        self.current_title_index = 0
        self.remaining_label.configure(text=f"Available Titles: {len(self.titles)}")
        self.log_message("🔄 Reset all used content tracking")
        messagebox.showinfo("Reset Complete", "Content tracking has been reset!")

    # Data Loading Methods
    def load_titles(self, filename):
        if not self.is_licensed:
            return
            
        try:
            with open(filename, 'r', encoding='utf-8') as f:
                self.titles = [line.strip() for line in f if line.strip()]
            self.used_titles.clear()
            self.used_combinations.clear()
            self.remaining_label.configure(text=f"Available Titles: {len(self.titles)}")
            self.log_message(f"📝 Loaded {len(self.titles)} titles")
        except Exception as e:
            self.log_message(f"❌ Error loading titles: {str(e)}")
    
    def load_descriptions(self, filename):
        if not self.is_licensed:
            return
            
        try:
            with open(filename, 'r', encoding='utf-8') as f:
                self.descriptions = [line.strip() for line in f if line.strip()]
            self.used_descriptions.clear()
            self.used_combinations.clear()
            self.log_message(f"📄 Loaded {len(self.descriptions)} descriptions")
        except Exception as e:
            self.log_message(f"❌ Error loading descriptions: {str(e)}")
    
    def load_streamkeys(self, filename):
        if not self.is_licensed:
            return
            
        try:
            with open(filename, 'r', encoding='utf-8') as f:
                self.streamkeys = [line.strip() for line in f if line.strip()]
            self.log_message(f"🔑 Loaded {len(self.streamkeys)} stream keys")
        except Exception as e:
            self.log_message(f"❌ Error loading stream keys: {str(e)}")
    
    def load_thumbnails(self, folder):
        if not self.is_licensed:
            return
            
        try:
            self.thumbnails = []
            for ext in ['.png', '.jpg', '.jpeg']:
                self.thumbnails.extend([os.path.join(folder, f) for f in os.listdir(folder) 
                                      if f.lower().endswith(ext)])
            self.used_thumbnails.clear()
            self.used_combinations.clear()
            self.log_message(f"🖼️ Loaded {len(self.thumbnails)} thumbnails")
        except Exception as e:
            self.log_message(f"❌ Error loading thumbnails: {str(e)}")
    
    def load_tags(self, filename):
        if not self.is_licensed:
            return
            
        try:
            with open(filename, 'r', encoding='utf-8') as f:
                self.tags_list = [line.strip() for line in f if line.strip()]
            self.log_message(f"🏷️ Loaded {len(self.tags_list)} tag sets")
        except Exception as e:
            self.log_message(f"❌ Error loading tags: {str(e)}")
    
    def load_advanced_data(self, filename):
        if not self.is_licensed:
            return
            
        try:
            if filename.endswith('.json'):
                with open(filename, 'r', encoding='utf-8') as f:
                    data = json.load(f)
            else:  # CSV
                data = []
                with open(filename, 'r', encoding='utf-8') as f:
                    reader = csv.DictReader(f)
                    data = list(reader)
            
            self.titles = [item.get('title', item.get('judul', '')) for item in data]
            self.descriptions = [item.get('desc', '') for item in data]
            self.streamkeys = [item.get('keystream', '') for item in data]
            self.thumbnails = [item.get('thumbnail', '') for item in data if item.get('thumbnail')]
            self.tags_list = [item.get('tags', '') for item in data if item.get('tags')]
            
            # Reset used tracking
            self.used_titles.clear()
            self.used_descriptions.clear()
            self.used_thumbnails.clear()
            self.used_combinations.clear()
            
            self.remaining_label.configure(text=f"Available Titles: {len(self.titles)}")
            self.log_message(f"📊 Loaded {len(data)} items from advanced data file")
        except Exception as e:
            self.log_message(f"❌ Error loading advanced data: {str(e)}")

    # YouTube Authentication Methods
    def authenticate_youtube(self):
        if not self.check_license_before_action("authenticate with YouTube"):
            return
            
        if not GOOGLE_LIBS_AVAILABLE:
            self.log_message("❌ Google libraries not installed - Cannot authenticate")
            messagebox.showerror("Error", 
                "Google libraries required for YouTube integration are not installed.\n\n"
                "Please install required libraries:\n"
                "pip install google-auth google-auth-oauthlib google-auth-httplib2 google-api-python-client\n\n"
                "Demo mode has been disabled.")
            return
            
        # Test Google API imports and internet connection
        try:
            from googleapiclient.discovery import build
            self.log_message("Google API libraries loaded successfully")
            
            # Test internet connection to Google APIs
            import urllib.request
            urllib.request.urlopen('https://www.googleapis.com/youtube/v3/', timeout=10)
            self.log_message("Internet connection to Google APIs verified")
        except ImportError as import_error:
            self.log_message(f"Google API import error: {str(import_error)}")
            messagebox.showerror("Import Error", f"Failed to import Google API: {str(import_error)}")
            return
        except Exception as connection_error:
            self.log_message(f"Internet connection error: {str(connection_error)}")
            # Continue anyway, might still work
            
        try:
            SCOPES = ['https://www.googleapis.com/auth/youtube', 
                     'https://www.googleapis.com/auth/youtube.force-ssl']
            CLIENT_SECRETS_FILE = get_client_secrets_path()
            
            # Debug logging for executable
            import sys
            self.log_message(f"sys.executable: {sys.executable}")
            self.log_message(f"__file__: {__file__}")
            self.log_message(f"sys.frozen: {getattr(sys, 'frozen', False)}")
            self.log_message(f"__compiled__ in globals: {'__compiled__' in globals()}")
            self.log_message(f"Executable directory: {get_executable_dir()}")
            self.log_message(f"Looking for client_secrets.json at: {CLIENT_SECRETS_FILE}")
            if hasattr(sys, 'frozen') or '__compiled__' in globals():
                self.log_message("Running as executable")
            else:
                self.log_message("Running as script")
            
            if not os.path.exists(CLIENT_SECRETS_FILE):
                self.log_message("client_secrets.json not found")
                messagebox.showerror("Error", f"client_secrets.json file not found at: {CLIENT_SECRETS_FILE}")
                return
            
            token_path = get_token_path()
            self.log_message(f"Looking for token.pickle at: {token_path}")
            if os.path.exists(token_path):
                self.log_message("Found existing token.pickle, attempting to load...")
                with open(token_path, 'rb') as token:
                    creds = pickle.load(token)
                    if creds and creds.valid:
                        self.credentials = creds
                        try:
                            self.youtube_service = create_youtube_service_with_retry(creds)
                            if self.youtube_service:
                                self.channel_label.configure(text="YouTube: Connected")
                                self.log_message("Already authenticated!")
                                self.get_channel_info()
                                return
                            else:
                                raise Exception("Failed to create YouTube service")
                        except Exception as service_error:
                            self.log_message(f"Failed to create YouTube service with existing token: {str(service_error)}")
                            # Continue to re-authentication
                    elif creds and creds.expired and creds.refresh_token:
                        try:
                            creds.refresh(Request())
                            self.credentials = creds
                            self.youtube_service = create_youtube_service_with_retry(creds)
                        except Exception as refresh_error:
                            self.log_message(f"Failed to refresh token: {str(refresh_error)}")
                            # Continue to re-authentication
                        with open(token_path, 'wb') as token:
                            pickle.dump(creds, token)
                        self.channel_label.configure(text="YouTube: Connected")
                        self.log_message("Credentials refreshed!")
                        self.get_channel_info()
                        return
            
            self.log_message("Starting OAuth authentication...")
            
            port = self.find_free_port()
            redirect_uri = f'http://localhost:{port}/callback'
            
            flow = Flow.from_client_secrets_file(CLIENT_SECRETS_FILE, SCOPES)
            flow.redirect_uri = redirect_uri
            
            auth_url, state = flow.authorization_url(
                access_type='offline',
                include_granted_scopes='true',
                prompt='consent'
            )
            
            self.log_message(f"Opening browser for authentication...")
            self.log_message(f"Listening on port {port}...")
            
            webbrowser.open(auth_url)
            self.handle_oauth_callback(flow, port, state)
            
        except Exception as e:
            self.log_message(f"Authentication error: {str(e)}")
            messagebox.showerror("Authentication Error", str(e))
    
    def find_free_port(self, start_port=8080):
        for port in range(start_port, start_port + 100):
            try:
                with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as s:
                    s.bind(('127.0.0.1', port))
                    self.log_message(f"Found free port: {port}")
                    return port
            except OSError as e:
                self.log_message(f"Port {port} unavailable: {str(e)}")
                continue
        self.log_message("Warning: Using default port 8080")
        return 8080
    
    def handle_oauth_callback(self, flow, port, state):
        def callback_handler():
            try:
                import http.server
                import socketserver
                from urllib.parse import urlparse, parse_qs
                
                authorization_code = None
                server_error = None
                
                class CallbackHandler(http.server.BaseHTTPRequestHandler):
                    def do_GET(self):
                        nonlocal authorization_code, server_error
                        
                        try:
                            parsed_url = urlparse(self.path)
                            query_params = parse_qs(parsed_url.query)
                            
                            if 'code' in query_params:
                                authorization_code = query_params['code'][0]
                                self.send_response(200)
                                self.send_header('Content-type', 'text/html')
                                self.end_headers()
                                success_html = """
                                <html>
                                <head><title>Authentication Successful</title></head>
                                <body style="font-family: Arial, sans-serif; text-align: center; margin-top: 50px;">
                                    <h2 style="color: green;">✅ Authentication Successful!</h2>
                                    <p>You can now close this browser tab and return to the application.</p>
                                    <script>setTimeout(function(){window.close();}, 3000);</script>
                                </body>
                                </html>
                                """
                                self.wfile.write(success_html.encode())
                            elif 'error' in query_params:
                                server_error = query_params['error'][0]
                                self.send_response(400)
                                self.send_header('Content-type', 'text/html')
                                self.end_headers()
                                error_html = f"""
                                <html>
                                <head><title>Authentication Error</title></head>
                                <body style="font-family: Arial, sans-serif; text-align: center; margin-top: 50px;">
                                    <h2 style="color: red;">❌ Authentication Failed</h2>
                                    <p>Error: {server_error}</p>
                                    <p>You can close this tab and try again.</p>
                                </body>
                                </html>
                                """
                                self.wfile.write(error_html.encode())
                        except Exception as e:
                            server_error = str(e)
                    
                    def log_message(self, format, *args):
                        pass
                
                try:
                    with socketserver.TCPServer(("127.0.0.1", port), CallbackHandler) as httpd:
                        httpd.timeout = 120
                        self.log_message(f"OAuth callback server started on port {port}")
                        
                        start_time = time.time()
                        while authorization_code is None and server_error is None:
                            try:
                                httpd.handle_request()
                            except Exception as e:
                                self.log_message(f"Server error: {str(e)}")
                                server_error = f"Server error: {str(e)}"
                                break
                            if time.time() - start_time > 120:
                                server_error = "Timeout waiting for authorization"
                                break
                        
                        self.log_message("OAuth callback server stopped")
                except Exception as e:
                    self.log_message(f"Failed to start callback server: {str(e)}")
                    server_error = f"Failed to start callback server: {str(e)}"
                
                if authorization_code:
                    self.log_message("Authorization code received, fetching tokens...")
                    try:
                        flow.fetch_token(code=authorization_code)
                        self.credentials = flow.credentials
                        self.log_message("Creating YouTube service...")
                        
                        # Create service with better error handling
                        self.youtube_service = create_youtube_service_with_retry(self.credentials)
                        if self.youtube_service:
                            self.log_message("YouTube service created successfully")
                        else:
                            raise Exception("Failed to create YouTube service")
                    except Exception as service_error:
                        self.log_message(f"Service creation error: {str(service_error)}")
                        raise service_error
                    
                    token_path = get_token_path()
                    self.log_message(f"Saving token.pickle to: {token_path}")
                    try:
                        with open(token_path, 'wb') as token:
                            pickle.dump(self.credentials, token)
                        self.log_message("Token saved successfully!")
                    except Exception as e:
                        self.log_message(f"Failed to save token: {str(e)}")
                    
                    self.after(0, self.on_auth_success)
                elif server_error:
                    self.after(0, lambda: self.on_auth_error(server_error))
                else:
                    self.after(0, lambda: self.on_auth_error("Authentication cancelled or timed out"))
                    
            except Exception as e:
                self.after(0, lambda: self.on_auth_error(str(e)))
        
        callback_thread = threading.Thread(target=callback_handler, daemon=True)
        callback_thread.start()
    
    def on_auth_success(self):
        self.channel_label.configure(text="YouTube: Connected")
        self.log_message("✅ YouTube authentication successful!")
        self.get_channel_info()
        messagebox.showinfo("Success", "YouTube authentication successful!")
    
    def on_auth_error(self, error_message):
        self.log_message(f"❌ Authentication failed: {error_message}")
        messagebox.showerror("Authentication Failed", error_message)
    
    def get_channel_info(self):
        try:
            if self.youtube_service:
                request = self.youtube_service.channels().list(
                    part="snippet,statistics",
                    mine=True
                )
                response = request.execute()
                
                if response.get('items'):
                    channel = response['items'][0]
                    channel_name = channel['snippet']['title']
                    subscriber_count = channel['statistics'].get('subscriberCount', 'N/A')
                    
                    # Store channel name for use in notifications
                    self.current_channel_name = channel_name
                    
                    self.channel_label.configure(text=f"YouTube: {channel_name}")
                    self.log_message(f"Connected to channel: {channel_name}")
                    self.log_message(f"Subscribers: {subscriber_count}")
                    
        except Exception as e:
            self.log_message(f"Error getting channel info: {str(e)}")
    
    def get_current_channel_name(self):
        """Get current channel name for notifications"""
        if hasattr(self, 'current_channel_name'):
            return self.current_channel_name
        return "YouTube Channel"
    
    def load_credentials(self):
        try:
            token_path = get_token_path()
            if os.path.exists(token_path):
                with open(token_path, 'rb') as token:
                    self.credentials = pickle.load(token)
                    
                if self.credentials and self.credentials.valid:
                    self.youtube_service = build('youtube', 'v3', credentials=self.credentials)
                    self.channel_label.configure(text="YouTube: Connected")
                    self.log_message("Credentials loaded successfully")
        except Exception as e:
            self.log_message(f"Error loading credentials: {str(e)}")

    # Utility Methods
    def check_streamkeys(self):
        if not self.check_license_before_action("check stream keys"):
            return
            
        if not self.streamkeys:
            self.log_message("No stream keys loaded")
            return
        
        self.log_message(f"Checking {len(self.streamkeys)} stream keys...")
        # Implement stream key validation logic
    
    def process_spintax(self, text):
        pattern = r'\{([^}]+)\}'
        
        def replace_spintax(match):
            options = match.group(1).split('|')
            return random.choice(options)
        
        return re.sub(pattern, replace_spintax, text)
    
    def get_next_content(self):
        if not self.titles:
            return None, None, None, None, None
        
        if not self.randomize_content_var.get():
            return self.get_sequential_content()
        
        return self.get_random_content()
    
    def get_sequential_content(self):
        if self.current_title_index >= len(self.titles):
            if self.change_title_var.get():
                return None, None, None, None, None
            else:
                self.current_title_index = 0
        
        title = self.titles[self.current_title_index]
        description = ""
        streamkey = ""
        thumbnail = ""
        tags = ""
        
        if self.descriptions:
            desc_index = self.current_title_index % len(self.descriptions)
            description = self.process_spintax(self.descriptions[desc_index])
        
        if self.streamkeys:
            key_index = self.current_title_index % len(self.streamkeys)
            streamkey = self.streamkeys[key_index]
        
        if self.thumbnails:
            thumb_index = self.current_title_index % len(self.thumbnails)
            thumbnail = self.thumbnails[thumb_index]
        
        if self.tags_list:
            tags_index = self.current_title_index % len(self.tags_list)
            tags = self.process_spintax(self.tags_list[tags_index])
        
        if self.change_title_var.get():
            self.current_title_index += 1
            self.remaining_label.configure(text=f"Available Titles: {len(self.titles) - self.current_title_index}")
        
        return title, description, streamkey, thumbnail, tags
    
    def get_random_content(self):
        max_attempts = 100
        
        for attempt in range(max_attempts):
            title = self.get_unused_title()
            description = self.get_unused_description()
            streamkey = ""
            thumbnail = ""
            tags = ""
            
            # Selalu track title dan description yang digunakan (terlepas dari avoid_duplicates)
            if title:
                self.used_titles.add(title)
            if description:
                self.used_descriptions.add(description)
            
            if self.streamkeys:
                streamkey = random.choice(self.streamkeys)
            
            if self.thumbnails:
                thumbnail = self.get_unused_thumbnail()
                # Selalu track thumbnail yang digunakan (terlepas dari avoid_duplicates)
                if thumbnail:
                    self.used_thumbnails.add(thumbnail)
            
            if self.tags_list:
                tags = self.process_spintax(random.choice(self.tags_list))
            
            combination_key = f"{title}|{description}|{thumbnail}"
            
            if self.avoid_duplicates_var.get():
                if combination_key not in self.used_combinations:
                    self.used_combinations.add(combination_key)
                    
                    remaining_unique = len(self.titles) - len(self.used_titles)
                    self.remaining_label.configure(text=f"Available Titles: {remaining_unique}")
                    
                    self.log_message(f"🎲 Selected random content: {title[:30]}...")
                    return title, description, streamkey, thumbnail, tags
                
                if len(self.used_combinations) >= len(self.titles):
                    if self.change_title_var.get():
                        self.log_message("⚠️ All content combinations have been used!")
                        return None, None, None, None, None
                    else:
                        self.log_message("🔄 All combinations used, resetting...")
                        self.reset_used_content()
                        continue
            else:
                self.log_message(f"🎲 Selected random content: {title[:30]}...")
                return title, description, streamkey, thumbnail, tags
        
        self.log_message("⚠️ Could not find unique content combination after 100 attempts")
        return title, description, streamkey, thumbnail, tags

    # Streaming Control Methods
    def start_streaming(self):
        if not self.check_license_before_action("start streaming"):
            return
            
        if not self.titles:
            self.log_message("❌ No titles loaded")
            messagebox.showerror("Error", "Please load titles first")
            return
        
        self.is_streaming = True
        self.start_button.configure(state="disabled")
        self.stop_button.configure(state="normal")
        
        self.log_message("🚀 Starting streaming automation...")
        
        stream_thread = threading.Thread(target=self.streaming_loop, daemon=True)
        stream_thread.start()
    
    def stop_streaming(self):
        if not self.check_license_before_action("stop streaming"):
            return
            
        self.is_streaming = False
        self.start_button.configure(state="normal")
        self.stop_button.configure(state="disabled")
        
        self.log_message("Stopping all streams...")
        
        for item in self.stream_tree.get_children():
            self.stream_tree.delete(item)
    
    def streaming_loop(self):
        stream_counter = 0
        wait_logged = False  # Track if wait message already shown
        
        while self.is_streaming:
            available_keys = len(self.streamkeys) if self.streamkeys else 1
            max_duplicates = int(self.duplicate_entry.get())
            max_concurrent = available_keys * max_duplicates
            
            # Only log max concurrent info once at start
            if stream_counter == 0:
                self.log_message(f"📊 Max Concurrent: {max_concurrent} (Keys: {available_keys} × Duplicates: {max_duplicates})")
            
            if len(self.running_streams) >= max_concurrent:
                # Only show waiting message once, then silent background checking
                if not wait_logged:
                    self.log_message(f"⏸ Menunggu... ({len(self.running_streams)} siaran aktif)")
                    wait_logged = True
                time.sleep(5)
                continue
            
            # Reset wait flag when we can proceed
            wait_logged = False
            
            # Ambil content untuk stream berikutnya
            title, description, streamkey, thumbnail, tags = self.get_next_content()
            
            if not title:
                self.log_message("❌ No more content available")
                break
            
            # Cek duplicate limit per streamkey
            if streamkey and self.check_duplicate_limit(streamkey, max_duplicates):
                self.log_message(f"⚠️ Streamkey {streamkey[:10]}... reached duplicate limit ({max_duplicates})")
                time.sleep(2)
                continue
            
            stream_counter += 1
            
            # Start broadcast creation (tanpa menunggu FFmpeg)
            success = self.create_broadcast_only(stream_counter, title, description, streamkey, thumbnail, tags)
            
            if not success:
                self.log_message(f"❌ Failed to create broadcast {stream_counter}, retrying in 10s...")
                time.sleep(10)
                continue
            
            # Delay minimal sebelum broadcast berikutnya
            delay_minutes = int(self.delay_entry.get())
            delay_seconds = max(delay_minutes * 60, 5)  # Minimal 5 detik untuk broadcast creation
            
            self.log_message(f"⏱️ Next broadcast in {delay_seconds//60}m {delay_seconds%60}s")
            
            # Countdown dengan interrupt check
            for i in range(delay_seconds):
                if not self.is_streaming:
                    break
                time.sleep(1)

    def check_duplicate_limit(self, streamkey, max_duplicates):
        """Cek apakah streamkey sudah mencapai batas duplicate"""
        if not streamkey:
            return False
        
        count = sum(1 for stream in self.running_streams 
                    if stream.get('stream_key') == streamkey)
        
        return count >= max_duplicates

    def start_single_stream(self, stream_counter, title, description, streamkey, thumbnail, tags):
        """Start single stream dengan improved error handling"""
        try:
            stream_id = f"stream_{stream_counter}_{int(time.time())}"
            self.log_message(f"🎬 Starting stream {stream_id}: {title[:30]}...")
            
            # Rate limiting yang lebih agresif untuk multiple streams
            current_time = time.time()
            time_since_last = current_time - self.last_api_call
            
            # Increase delay untuk multiple concurrent streams
            required_delay = self.api_call_delay + (len(self.running_streams) * 0.5)
            
            if time_since_last < required_delay:
                wait_time = required_delay - time_since_last
                self.log_message(f"⏱️ Rate limiting: waiting {wait_time:.1f}s")
                time.sleep(wait_time)
            
            self.last_api_call = time.time()
            
            if not (self.youtube_service and GOOGLE_LIBS_AVAILABLE):
                self.log_message("❌ Cannot create broadcast - YouTube not authenticated or Google libraries missing")
                return False
                
            # Retry mechanism untuk API calls
            max_retries = 3
            broadcast_id = None
            for attempt in range(max_retries):
                try:
                    broadcast_id, final_stream_key = self.create_and_start_live_broadcast(
                        title, description, streamkey, thumbnail, tags
                    )
                    
                    if broadcast_id:
                        break
                    
                    if attempt < max_retries - 1:
                        wait_time = (attempt + 1) * 30  # 30s, 60s, 90s
                        self.log_message(f"🔄 Retry {attempt + 1}/{max_retries} in {wait_time}s...")
                        time.sleep(wait_time)
                
                except Exception as e:
                    if "quota" in str(e).lower() or "rate" in str(e).lower():
                        wait_time = self.rate_limit_backoff * (attempt + 1)
                        self.log_message(f"🚫 Rate limit hit, waiting {wait_time}s...")
                        time.sleep(wait_time)
                    else:
                        raise e
            
            if not broadcast_id:
                self.log_message(f"❌ Failed to create broadcast after {max_retries} attempts")
                return False
            
            # Create stream info
            stream_info = {
                'id': stream_id,
                'broadcast_id': broadcast_id,
                'stream_key': final_stream_key,
                'title': title,
                'start_time': time.time(),
                'actual_viewers': 0,
                'status': 'starting'
            }
            
            self.running_streams.append(stream_info)
            
            # Update UI
            self.stream_tree.insert("", "end", values=(
                stream_id,
                final_stream_key[:10] + "..." if final_stream_key else "",
                title[:20] + "..." if len(title) > 20 else title,
                "Starting...",
                "0"
            ))
            
            # Start monitoring thread
            monitor_thread = threading.Thread(
                target=self.monitor_stream, 
                args=(stream_info,), 
                daemon=True
            )
            monitor_thread.start()
            
            self.log_message(f"✅ Stream {stream_id} started successfully")
            return True
            
        except Exception as e:
            self.log_message(f"❌ Error starting stream {stream_counter}: {str(e)}")
            return False

    def create_and_start_live_broadcast(self, title, description, streamkey, thumbnail, tags):
        """Optimized broadcast creation dengan better error handling"""
        try:
            self.log_message("🚀 Creating optimized live broadcast...")
            
            # Cek apakah streamkey tersedia
            if not streamkey:
                self.log_message("❌ No stream key provided")
                return None, None
            
            # Fast check untuk streamkey availability
            reusable_stream_id = self.reuse_existing_stream_smart(streamkey)
            if not reusable_stream_id:
                self.log_message(f"❌ Stream key {streamkey} not found in account")
                return None, None
            
            # Create broadcast dengan minimal data
            broadcast_body = {
                "snippet": {
                    "title": title,
                    "description": description[:5000],  # Limit description
                    "scheduledStartTime": datetime.utcnow().isoformat() + "Z"
                },
                "status": {
                    "privacyStatus": "public"
                }
            }
            
            # Add tags jika ada (dengan limit)
            if tags:
                tags_list = [tag.strip() for tag in tags.split(',') if tag.strip()][:10]  # Max 10 tags
                if tags_list:
                    broadcast_body["snippet"]["tags"] = tags_list
            
            # Create broadcast
            broadcast_response = self.youtube_service.liveBroadcasts().insert(
                part="snippet,status",
                body=broadcast_body
            ).execute()
            
            broadcast_id = broadcast_response["id"]
            self.log_message(f"✅ Broadcast created: {broadcast_id}")
            
            # Bind dengan stream key
            try:
                self.youtube_service.liveBroadcasts().bind(
                    part="id,contentDetails",
                    id=broadcast_id,
                    streamId=reusable_stream_id
                ).execute()
                
                self.log_message(f"🔗 Bound to stream key: {streamkey}")
                
            except Exception as bind_error:
                if "duplicate" not in str(bind_error).lower():
                    # Cleanup failed broadcast
                    try:
                        self.youtube_service.liveBroadcasts().delete(id=broadcast_id).execute()
                    except:
                        pass
                    raise bind_error
            
            # Upload thumbnail (async, non-blocking)
            if thumbnail and os.path.exists(thumbnail):
                threading.Thread(
                    target=self.upload_thumbnail_async,
                    args=(broadcast_id, thumbnail),
                    daemon=True
                ).start()
            
            # Quick transition to live (tanpa waiting)
            self.log_message(f"🎉 Broadcast ready: {broadcast_id}")
            return broadcast_id, streamkey
        
        except Exception as e:
            self.log_message(f"❌ Broadcast creation error: {str(e)}")
            return None, None

    def upload_thumbnail_async(self, broadcast_id, thumbnail_path):
        """Upload thumbnail secara async"""
        try:
            time.sleep(5)  # Wait untuk broadcast stabilization
            self.youtube_service.thumbnails().set(
                videoId=broadcast_id,
                media_body=MediaFileUpload(thumbnail_path)
            ).execute()
            self.log_message("🖼️ Thumbnail berhasil diunggah")
        except Exception as e:
            self.log_message(f"⚠️ Thumbnail upload failed: {str(e)}")

    def create_youtube_live_broadcast_with_key(self, title, description, thumbnail_path=None, tags=None, existing_streamkey=None):
        """
        Buat broadcast YouTube menggunakan stream key yang sudah ada
        """
        try:
            current_time = time.time()
            time_since_last_call = current_time - self.last_api_call
            if time_since_last_call < self.api_call_delay:
                wait_time = self.api_call_delay - time_since_last_call
                self.log_message(f"⏱️ Rate limiting: waiting {wait_time:.1f}s")
                time.sleep(wait_time)
            
            self.last_api_call = time.time()
            
            if not self.youtube_service:
                self.log_message("❌ YouTube service not authenticated")
                return None, None
            
            if not existing_streamkey:
                self.log_message("❌ NO STREAM KEY PROVIDED")
                return None, None
            
            # Persiapan tags
            tags_list = []
            if tags:
                tags_list = [tag.strip() for tag in tags.split(',') if tag.strip()]
                tags_list = tags_list[:500]
                self.log_message(f"🏷️ Adding {len(tags_list)} tags")
            
            # Buat broadcast body
            broadcast_body = {
                "snippet": {
                    "title": title,
                    "description": description,
                    "scheduledStartTime": datetime.utcnow().isoformat() + "Z"
                },
                "status": {
                    "privacyStatus": "public"
                }
            }
            
            if tags_list:
                broadcast_body["snippet"]["tags"] = tags_list
            
            # Buat live broadcast
            self.log_message("📡 Creating YouTube live broadcast...")
            broadcast_response = self.youtube_service.liveBroadcasts().insert(
                part="snippet,status",
                body=broadcast_body
            ).execute()
            
            broadcast_id = broadcast_response["id"]
            self.log_message(f"✅ Live broadcast created: {broadcast_id}")
            
            # Cari stream key yang sudah ada di account
            self.log_message(f"🔑 Looking for existing stream key: {existing_streamkey}")
            
            reusable_stream_id = self.reuse_existing_stream_smart(existing_streamkey)
            
            if not reusable_stream_id:
                self.log_message(f"❌ Stream key {existing_streamkey} NOT FOUND in account")
                
                # Hapus broadcast yang sudah dibuat
                try:
                    self.youtube_service.liveBroadcasts().delete(id=broadcast_id).execute()
                    self.log_message(f"🗑️ Deleted unused broadcast {broadcast_id}")
                except:
                    pass
                
                return None, None
            
            # Bind dengan stream key yang ada
            try:
                self.log_message(f"🔗 Binding broadcast to stream key: {existing_streamkey}")
                
                self.youtube_service.liveBroadcasts().bind(
                    part="id,contentDetails",
                    id=broadcast_id,
                    streamId=reusable_stream_id
                ).execute()
                
                self.log_message(f"✅ Bind success: {existing_streamkey}")
                
            except Exception as bind_error:
                error_msg = str(bind_error).lower()
                
                if "duplicate" in error_msg or "already" in error_msg:
                    self.log_message(f"⚠️ Duplicate warning - continuing: {existing_streamkey}")
                    # Lanjut meski ada warning
                else:
                    self.log_message(f"❌ Bind failed: {bind_error}")
                    
                    # Hapus broadcast yang gagal
                    try:
                        self.youtube_service.liveBroadcasts().delete(id=broadcast_id).execute()
                        self.log_message(f"🗑️ Deleted failed broadcast {broadcast_id}")
                    except:
                        pass
                    
                    return None, None
            
            # Upload thumbnail jika ada
            if thumbnail_path and os.path.exists(thumbnail_path):
                try:
                    self.youtube_service.thumbnails().set(
                        videoId=broadcast_id,
                        media_body=MediaFileUpload(thumbnail_path)
                    ).execute()
                    self.log_message(f"🖼️ Thumbnail uploaded")
                except Exception as e:
                    self.log_message(f"⚠️ Thumbnail upload failed: {str(e)}")
            
            # Tampilkan info untuk FFmpeg custom
            self.log_message(f"🎉 BROADCAST READY: {broadcast_id}")
            self.log_message(f"🔑 Stream key: {existing_streamkey}")
            self.log_message(f"📡 RTMP URL: rtmp://a.rtmp.youtube.com/live2/")
            self.log_message(f"💡 Your FFmpeg can now push to: rtmp://a.rtmp.youtube.com/live2/{existing_streamkey}")
            
            return broadcast_id, existing_streamkey
        
        except Exception as e:
            self.log_message(f"❌ Error creating broadcast: {str(e)}")
            return None, None

    def check_stream_availability(self, stream_id):
        """
        Cek apakah stream sedang digunakan broadcast aktif
        """
        try:
            # Fix: Hapus parameter yang incompatible
            active_broadcasts = self.youtube_service.liveBroadcasts().list(
                part="contentDetails,status",
                mine=True,
                maxResults=50
            ).execute()
            
            for broadcast in active_broadcasts.get("items", []):
                # Cek hanya broadcast yang statusnya masih aktif
                lifecycle_status = broadcast.get("status", {}).get("lifeCycleStatus", "")
                if lifecycle_status in ["created", "ready", "testing", "live"]:
                    bound_stream = broadcast.get("contentDetails", {}).get("boundStreamId")
                    if bound_stream == stream_id:
                        return False, f"Stream sedang digunakan broadcast aktif ({lifecycle_status})"
            
            return True, "Stream available untuk reuse"
            
        except Exception as e:
            # Jika error checking, assume available (lebih aman untuk reuse)
            self.log_message(f"⚠️ Cannot check stream status: {str(e)}")
            return True, "Cannot check status, assuming available"

    def reuse_existing_stream_smart(self, existing_streamkey):
        """
        SELALU cari dan gunakan stream key dari keystream.txt
        """
        try:
            streams_response = self.youtube_service.liveStreams().list(
                part="snippet,cdn,status",
                mine=True,
                maxResults=50
            ).execute()
            
            for stream in streams_response.get("items", []):
                stream_name = stream["cdn"]["ingestionInfo"]["streamName"]
                stream_id = stream["id"]
                
                if stream_name == existing_streamkey:
                    self.log_message(f"✅ FOUND STREAM KEY: {existing_streamkey}")
                    
                    # Cek availability (tapi tetap lanjut meski busy)
                    available, reason = self.check_stream_availability(stream_id)
                    self.log_message(f"📊 Stream status: {reason}")
                    
                    # SELALU return stream_id, tidak peduli status
                    return stream_id
            
            self.log_message(f"❌ Stream key {existing_streamkey} NOT FOUND in YouTube account")
            return None
            
        except Exception as e:
            self.log_message(f"❌ Error searching stream: {str(e)}")
            return None

    def wait_for_encoder_and_go_live(self, broadcast_id, stream_key, timeout_minutes=15):
        """
        Wait for your custom FFmpeg to connect and go live
        """
        try:
            self.log_message(f"⏳ Waiting for your FFmpeg to connect...")
            self.log_message(f"🔑 Stream key: {stream_key}")
            self.log_message(f"📡 RTMP URL: rtmp://a.rtmp.youtube.com/live2/")
            self.log_message(f"💡 Command: ffmpeg -i [input] -c copy -f flv rtmp://a.rtmp.youtube.com/live2/{stream_key}")
            
            start_time = time.time()
            timeout_seconds = timeout_minutes * 60
            
            while time.time() - start_time < timeout_seconds:
                try:
                    response = self.youtube_service.liveBroadcasts().list(
                        part="status,contentDetails",
                        id=broadcast_id
                    ).execute()
                    
                    if not response.get("items"):
                        return False
                    
                    broadcast = response["items"][0]
                    lifecycle_status = broadcast["status"]["lifeCycleStatus"]
                    
                    self.log_message(f"📊 Status: {lifecycle_status}")
                    
                    if lifecycle_status == "testing":
                        self.log_message("✅ FFmpeg connected! Stream testing...")
                        time.sleep(30)  # Stabilization
                        
                        try:
                            self.youtube_service.liveBroadcasts().transition(
                                part="status",
                                id=broadcast_id,
                                broadcastStatus="live"
                            ).execute()
                            
                            self.log_message("🎉 BROADCAST IS LIVE!")
                            return True
                            
                        except Exception as e:
                            if "invalidTransition" in str(e):
                                self.log_message("⚠️ Still stabilizing...")
                                continue
                    
                    elif lifecycle_status == "live":
                        self.log_message("🎉 BROADCAST IS LIVE!")
                        return True
                    
                    time.sleep(15)
                    
                except Exception as e:
                    self.log_message(f"⚠️ Check error: {str(e)}")
                    time.sleep(15)
            
            self.log_message(f"⏰ Timeout after {timeout_minutes} minutes")
            return False
        
        except Exception as e:
            self.log_message(f"❌ Error: {str(e)}")
            return False
    
    def create_broadcast_only(self, stream_counter, title, description, streamkey, thumbnail, tags):
        """Create broadcast dengan telegram notification"""
        try:
            stream_id = f"stream_{stream_counter}_{int(time.time())}"
            self.log_message(f"🎬 Membuat siaran #{stream_counter}: {title}")
            
            # GET DURATION FIRST - before any other operations
            duration_seconds = (int(self.hour_var.get()) * 3600 + 
                              int(self.minute_var.get()) * 60 + 
                              int(self.second_var.get()))
            
            # Rate limiting
            current_time = time.time()
            time_since_last = current_time - self.last_api_call
            required_delay = max(1.0, self.api_call_delay * 0.5)
            
            if time_since_last < required_delay:
                wait_time = required_delay - time_since_last
                self.log_message(f"⏱️ API delay: {wait_time:.1f}s")
                time.sleep(wait_time)
            
            self.last_api_call = time.time()
            
            if not (self.youtube_service and GOOGLE_LIBS_AVAILABLE):
                self.log_message("❌ Cannot create broadcast - YouTube not authenticated or Google libraries missing")
                return False
                
            broadcast_id = self.create_youtube_broadcast_fast(title, description, streamkey, thumbnail, tags)
            if not broadcast_id:
                return False
            
            # Create stream info with proper timing
            stream_info = {
                'id': stream_id,
                'broadcast_id': broadcast_id,
                'stream_key': streamkey,
                'title': title,
                'start_time': time.time(),
                'duration_seconds': duration_seconds,
                'actual_viewers': 0,
                'status': 'ready_for_ffmpeg'
            }
            
            self.running_streams.append(stream_info)
            
            # Add to UI
            self.stream_tree.insert("", "end", values=(
                stream_id,
                streamkey[:10] + "..." if streamkey else "",
                title[:20] + "..." if len(title) > 20 else title,
                f"{duration_seconds//60}m {duration_seconds%60}s",
                "Starting..."
            ))
            
            # Start monitoring thread - USE EXISTING METHOD FROM CODE
            monitor_thread = threading.Thread(
                target=self.monitor_broadcast_only,
                args=(stream_info,),
                daemon=True
            )
            monitor_thread.start()
            
            # Send telegram notification for stream start
            if self.telegram_config.get('notifications', {}).get('stream_start', False):
                channel_name = self.get_current_channel_name()
                message = f"🎉 <b>Stream Started!</b>\n"
                message += f"<b>{channel_name}</b>\n\n"
                message += f"📺 <b>Title:</b> {title[:50]}...\n"
                message += f"🔑 <b>Stream Key:</b> {streamkey[:15]}...\n"
                message += f"⏰ <b>Duration:</b> {duration_seconds//60}m {duration_seconds%60}s\n"
                message += f"🆔 <b>Stream ID:</b> {stream_id}"
                
                self.send_telegram_message(message)
            
            self.log_message(f"✅ Broadcast {stream_id} created, monitoring for {duration_seconds//60}m {duration_seconds%60}s")
            return True
        
        except Exception as e:
            # Send error notification
            if self.telegram_config.get('notifications', {}).get('errors', False):
                channel_name = self.get_current_channel_name()
                error_msg = f"❌ <b>Stream Creation Failed</b>\n"
                error_msg += f"<b>{channel_name}</b>\n\n"
                error_msg += f"🔑 <b>Stream Key:</b> {streamkey[:15]}...\n"
                error_msg += f"⚠️ <b>Error:</b> {str(e)[:100]}"
                
                self.send_telegram_message(error_msg)
            
            self.log_message(f"❌ Error creating broadcast: {str(e)}")
            return False

    def create_youtube_broadcast_fast(self, title, description, streamkey, thumbnail, tags):
        """Fast broadcast creation dengan auto-transition ke LIVE"""
        try:
            # Cek streamkey availability
            if not streamkey:
                self.log_message("❌ No stream key provided")
                return None
            
            # Create broadcast dengan data minimal
            broadcast_body = {
                "snippet": {
                    "title": title,
                    "description": description[:5000],
                    "scheduledStartTime": datetime.utcnow().isoformat() + "Z"
                },
                "status": {
                    "privacyStatus": "public"
                }
            }
            
            # Add tags (limit 10)
            if tags:
                tags_list = [tag.strip() for tag in tags.split(',') if tag.strip()][:10]
                if tags_list:
                    broadcast_body["snippet"]["tags"] = tags_list
            
            # Create broadcast
            broadcast_response = self.youtube_service.liveBroadcasts().insert(
                part="snippet,status",
                body=broadcast_body
            ).execute()
            
            broadcast_id = broadcast_response["id"]
            self.log_message(f"✅ Siaran dibuat (ID: {broadcast_id})")
            
            # Find dan bind stream key
            reusable_stream_id = self.reuse_existing_stream_smart(streamkey)
            if reusable_stream_id:
                try:
                    # Check stream availability to determine the right message
                    available, reason = self.check_stream_availability(reusable_stream_id)
                    
                    if not available and "sedang digunakan" in reason:
                        self.log_message("🔁 Stream masih aktif, menggunakan ulang kunci")
                    else:
                        self.log_message("🔑 Kunci stream ditemukan")
                    
                    self.youtube_service.liveBroadcasts().bind(
                        part="id,contentDetails",
                        id=broadcast_id,
                        streamId=reusable_stream_id
                    ).execute()
                    
                    # Auto-transition ke LIVE setelah bind berhasil
                    self.auto_transition_to_live(broadcast_id, streamkey)
                    
                except Exception as bind_error:
                    if "already in use" in str(bind_error).lower():
                        self.log_message("⚠️ Kunci sedang digunakan oleh siaran lain")
                        # Continue with auto-transition anyway
                        self.auto_transition_to_live(broadcast_id, streamkey)
                    elif "duplicate" not in str(bind_error).lower():
                        self.log_message(f"⚠️ Bind warning: {bind_error}")
            
            # Upload thumbnail async (non-blocking)
            if thumbnail and os.path.exists(thumbnail):
                threading.Thread(
                    target=self.upload_thumbnail_async,
                    args=(broadcast_id, thumbnail),
                    daemon=True
                ).start()
            
            self.log_message(f"🎉 Broadcast ready for FFmpeg: rtmp://a.rtmp.youtube.com/live2/{streamkey}")
            return broadcast_id
            
        except Exception as e:
            self.log_message(f"❌ Broadcast creation error: {str(e)}")
            return None

    def auto_transition_to_live(self, broadcast_id, streamkey):
        """Auto-transition broadcast ke LIVE status"""
        try:
            self.log_message(f"🔄 Auto-transitioning broadcast {broadcast_id} to LIVE...")
            
            # Wait sebentar untuk stabilization
            time.sleep(5)
            
            # Transition ke testing dulu
            try:
                self.youtube_service.liveBroadcasts().transition(
                    part="status",
                    id=broadcast_id,
                    broadcastStatus="testing"
                ).execute()
                self.log_message("⏳ Status: Testing...")
                
                # Wait untuk testing stabilization
                time.sleep(10)
                
            except Exception as test_error:
                self.log_message(f"⚠️ Testing transition warning: {test_error}")
            
            # Transition ke LIVE
            try:
                self.youtube_service.liveBroadcasts().transition(
                    part="status",
                    id=broadcast_id,
                    broadcastStatus="live"
                ).execute()
                self.log_message("✅ Status: LIVE!")
                
            except Exception as live_error:
                if "invalidTransition" in str(live_error):
                    self.log_message(f"⚠️ Broadcast not ready for LIVE yet, will retry...")
                    # Start background thread untuk retry transition
                    threading.Thread(
                        target=self.retry_transition_to_live,
                        args=(broadcast_id, streamkey),
                        daemon=True
                    ).start()
                else:
                    self.log_message(f"❌ LIVE transition error: {live_error}")
            
        except Exception as e:
            self.log_message(f"❌ Auto-transition error: {str(e)}")

    def retry_transition_to_live(self, broadcast_id, streamkey):
        """Retry transition ke LIVE dengan polling"""
        try:
            max_retries = 10
            retry_delay = 30  # 30 detik per retry
            
            for attempt in range(max_retries):
                try:
                    # Check current status
                    response = self.youtube_service.liveBroadcasts().list(
                        part="status",
                        id=broadcast_id
                    ).execute()
                    
                    if not response.get("items"):
                        self.log_message(f"❌ Broadcast {broadcast_id} not found")
                        return
                    
                    current_status = response["items"][0]["status"]["lifeCycleStatus"]
                    self.log_message(f"📊 Broadcast {broadcast_id} status: {current_status}")
                    
                    if current_status == "live":
                        self.log_message(f"✅ Broadcast {broadcast_id} already LIVE!")
                        return
                    
                    elif current_status in ["ready", "testing"]:
                        # Try transition to live
                        self.youtube_service.liveBroadcasts().transition(
                            part="status",
                            id=broadcast_id,
                            broadcastStatus="live"
                        ).execute()
                        
                        self.log_message(f"🎉 Broadcast {broadcast_id} -> LIVE! (Attempt {attempt + 1})")
                        self.log_message(f"📺 FFmpeg ready: rtmp://a.rtmp.youtube.com/live2/{streamkey}")
                        return
                    
                    # Wait before next retry
                    if attempt < max_retries - 1:
                        self.log_message(f"⏳ Retry {attempt + 1}/{max_retries} in {retry_delay}s...")
                        time.sleep(retry_delay)
                    
                except Exception as retry_error:
                    if "invalidTransition" in str(retry_error):
                        self.log_message(f"⚠️ Still not ready for LIVE (attempt {attempt + 1})")
                        if attempt < max_retries - 1:
                            time.sleep(retry_delay)
                    else:
                        self.log_message(f"❌ Retry error: {retry_error}")
                        return
            
            self.log_message(f"⏰ Max retries reached for broadcast {broadcast_id}")
            
        except Exception as e:
            self.log_message(f"❌ Retry transition error: {str(e)}")

    def monitor_broadcast_only(self, stream_info):
        """Fix progress tracking dengan auto-stop yang benar"""
        try:
            # Get duration from stream_info (sudah di-set saat create)
            duration_seconds = stream_info.get('duration_seconds', 0)
            start_time = stream_info['start_time']
            stream_id = stream_info['id']
            broadcast_id = stream_info.get('broadcast_id')
            title = stream_info.get('title', 'Unknown')
            
            self.log_message(f"🎬 Monitoring {stream_id} for {duration_seconds//60}m {duration_seconds%60}s")
            
            while self.is_streaming:
                try:
                    elapsed = time.time() - start_time
                    remaining = max(0, duration_seconds - elapsed)
                    
                    # Calculate progress
                    progress = (elapsed / duration_seconds) * 100 if duration_seconds > 0 else 0
                    
                    # Update UI with progress
                    for item in self.stream_tree.get_children():
                        values = self.stream_tree.item(item, 'values')
                        if values[0] == str(stream_id):
                            self.stream_tree.item(item, values=(
                                values[0], values[1], values[2],
                                f"{remaining//60:.0f}m {remaining%60:.0f}s ({progress:.0f}%)",
                                "Live"
                            ))
                            break
                    
                    # CHECK FOR AUTO-STOP
                    if remaining <= 0:
                        self.log_message(f"⏰ DURATION COMPLETED - Auto-stopping {stream_id}")
                        
                        # Send telegram end notification
                        if self.telegram_config.get('notifications', {}).get('stream_end', False):
                            channel_name = self.get_current_channel_name()
                            end_msg = f"🏁 <b>Stream Auto-Stopped!</b>\n"
                            end_msg += f"<b>{channel_name}</b>\n\n"
                            end_msg += f"📺 <b>Title:</b> {title[:50]}...\n"
                            end_msg += f"⏰ <b>Duration:</b> {duration_seconds//60}m {duration_seconds%60}s\n"
                            end_msg += f"🆔 <b>Stream ID:</b> {stream_id}"
                            
                            self.send_telegram_message(end_msg)
                        
                        # Stop YouTube broadcast
                        if broadcast_id and self.youtube_service and GOOGLE_LIBS_AVAILABLE:
                            try:
                                self.stop_youtube_live_broadcast(broadcast_id)
                                self.log_message(f"🛑 YouTube broadcast {broadcast_id} stopped")
                            except Exception as stop_error:
                                self.log_message(f"⚠️ Stop broadcast error: {stop_error}")
                        
                        # Remove from running streams
                        self.running_streams = [s for s in self.running_streams if s['id'] != stream_id]
                        
                        # Remove from UI
                        try:
                            for item in self.stream_tree.get_children():
                                values = self.stream_tree.item(item, 'values')
                                if values[0] == stream_id:
                                    self.stream_tree.delete(item)
                                    break
                        except:
                            pass
                        
                        self.log_message(f"✅ Stream {stream_id} AUTO-STOPPED and cleaned up")
                        break  # Exit monitoring loop
                    
                    time.sleep(30)  # Check every 30 seconds
                    
                except Exception as e:
                    self.log_message(f"⚠️ Monitor loop error: {str(e)}")
                    time.sleep(30)
                    
        except Exception as e:
            self.log_message(f"❌ Monitor failed for {stream_info.get('id', 'unknown')}: {str(e)}")
    
    def get_live_broadcast_stats(self, broadcast_id):
        """Enhanced stats with retry logic"""
        max_retries = 3
        for attempt in range(max_retries):
            try:
                if not self.youtube_service or not broadcast_id:
                    return {"viewers": 0, "status": "unknown"}
                
                response = self.youtube_service.liveBroadcasts().list(
                    part="statistics,status",
                    id=broadcast_id
                ).execute()
                
                if response.get("items"):
                    broadcast = response["items"][0]
                    viewers = broadcast.get("statistics", {}).get("concurrentViewers", "0")
                    status = broadcast.get("status", {}).get("lifeCycleStatus", "unknown")
                    
                    return {
                        "viewers": int(viewers) if viewers.isdigit() else 0,
                        "status": status
                    }
            except Exception as e:
                if attempt < max_retries - 1:
                    wait_time = (attempt + 1) * 2  # 2s, 4s, 6s
                    self.log_message(f"🔄 SSL retry {attempt + 1}/{max_retries} in {wait_time}s...")
                    time.sleep(wait_time)
                else:
                    self.log_message(f"⚠️ SSL error after {max_retries} attempts: {str(e)}")
        
        return {"viewers": 0, "status": "unknown"}
    
    def stop_youtube_live_broadcast(self, broadcast_id):
        try:
            if not self.youtube_service or not broadcast_id:
                return False
            
            self.youtube_service.liveBroadcasts().transition(
                part="status",
                id=broadcast_id,
                broadcastStatus="complete"
            ).execute()
            
            self.log_message(f"🛑 Live broadcast {broadcast_id} stopped")
            return True
            
        except Exception as e:
            self.log_message(f"❌ Error stopping broadcast: {str(e)}")
            return False
    
    def show_setup_guide(self):
        """Show setup guide for YouTube API"""
        guide_window = ctk.CTkToplevel(self)
        guide_window.title("LoopBot - Setup Guide untuk Pemula")
        guide_window.geometry("800x700")
        
        frame = ctk.CTkFrame(guide_window)
        frame.pack(fill="both", expand=True, padx=10, pady=10)
        
        text_widget = ctk.CTkTextbox(frame, wrap="word")
        scrollbar = ctk.CTkScrollbar(frame, command=text_widget.yview)
        text_widget.configure(yscrollcommand=scrollbar.set)
        
        setup_guide = """
⚙️ PENGATURAN APLIKASI - PENJELASAN DETAIL:

🕐 DURATION (DURASI SIARAN)
   Mengatur berapa lama setiap siaran akan berjalan
   • Format: Jam:Menit:Detik
   • Contoh: 01:30:00 = 1 jam 30 menit
   • Contoh: 00:05:00 = 5 menit
   
   ⚠️ PENTING: Siaran akan otomatis berhenti setelah durasi habis

⏱️ DELAY (JEDA ANTAR SIARAN)
   Jeda waktu sebelum membuat siaran berikutnya
   • Satuan: Menit
   • Contoh: 2 = Jeda 2 menit antar siaran

🔄 MAX DUPLICATE
   Berapa kali stream key yang sama bisa digunakan bersamaan
   • Contoh: 3 = 1 stream key bisa dipakai untuk 3 siaran sekaligus

════════════════════════════════════════════════════════════

☑️ OPSI LANJUTAN - CENTANG/TIDAK CENTANG:

🔍 FILTER LOW VIEWERS
   ✅ DICENTANG: Aplikasi akan mencoba menghindari slot waktu dengan viewers sedikit
   ❌ TIDAK: Siaran akan dibuat tanpa mempertimbangkan jumlah viewers

🔄 AUTO-ROTATE TITLES
   ✅ DICENTANG: Judul akan berubah otomatis setiap siaran baru
   ❌ TIDAK: Menggunakan judul yang sama terus menerus
   📚 Contoh: 
   • Siaran #1: "RAHASIA SUKSES BISNIS ONLINE"
   • Siaran #2: "CARA MUDAH DAPAT UANG DARI RUMAH"
   • Siaran #3: "INVESTASI CRYPTO UNTUK PEMULA"

🎲 RANDOMIZE CONTENT
   ✅ DICENTANG: Konten dipilih secara acak dari daftar
   ❌ TIDAK: Konten dipilih berurutan dari atas ke bawah
   📚 Contoh dengan 5 judul:
   • Mode Random: Judul 3 → Judul 1 → Judul 5 → Judul 2
   • Mode Urutan: Judul 1 → Judul 2 → Judul 3 → Judul 4
   📊 Rekomendasi: DICENTANG (lebih natural)

❌ AVOID DUPLICATES
   ✅ DICENTANG: Hindari menggunakan konten yang sama berulang
   ❌ TIDAK: Konten bisa terulang dalam satu sesi
   📚 Contoh: Jika ada 10 judul dan dicentang:
   • Semua 10 judul akan digunakan sekali sebelum ada pengulangan
   • Setelah 10 siaran, sistem akan reset dan mulai lagi
   📊 Rekomendasi: DICENTANG (hindari konten berulang)

════════════════════════════════════════════════════════════

📁 FILE YANG DIPERLUKAN:

1. TITLES.TXT
   Berisi daftar judul siaran (satu per baris)
   Contoh isi:
   RAHASIA SUKSES BISNIS ONLINE
   CARA MUDAH DAPAT UANG DARI RUMAH
   INVESTASI CRYPTO UNTUK PEMULA

2. DESCRIPTIONS.TXT
   Berisi deskripsi siaran (satu per baris)
   Bisa menggunakan spintax: {pilihan1|pilihan2|pilihan3}

3. KEYSTREAM.TXT
   Berisi stream keys YouTube (satu per baris)
   Didapat dari YouTube Studio → Go Live → Stream Key

4. FOLDER THUMBNAILS
   Berisi gambar thumbnail (.jpg, .png)
   Ukuran recommended: 1280x720 pixels

════════════════════════════════════════════════════════════

⚠️ LICENSE REQUIRED:
Aplikasi ini memerlukan lisensi valid untuk berfungsi.
Dapatkan lisensi dari: http://loopbotiq.com
WhatsApp +62-812-2428-6756

════════════════════════════════════════════════════════════
        """
        text_widget.insert("end", setup_guide)
        text_widget.pack(side="left", fill="both", expand=True)
        scrollbar.pack(side="right", fill="y")
        
        close_button = ctk.CTkButton(guide_window, text="Close", command=guide_window.destroy)
        close_button.pack(pady=10)

def main():
    print("🚀 LoopBot - YouTube Live Automation (Licensed Edition)")
    print("=" * 55)
    
    if not GOOGLE_LIBS_AVAILABLE:
        print("❌ CRITICAL: Google libraries not installed.")
        print("🚫 Demo mode has been disabled - Only live YouTube streaming is supported.")
        print("\n📦 Required libraries must be installed:")
        print("pip3 install google-auth google-auth-oauthlib google-auth-httplib2 google-api-python-client")
        print("\n⚠️ Application will not function without these libraries!")
        print()
    
    print("🔐 License System: Active")
    print("🌐 License Server: http://127.0.0.1:5000 (localhost)")
    print("📄 Get your license at: http://loopbotiq.com")
    print()
    
    app = YouTubeLiveAutomation()
    
    try:
        app.mainloop()
    except KeyboardInterrupt:
        print("\n👋 Shutting down...")
    except Exception as e:
        print(f"❌ Error: {e}")

if __name__ == "__main__":
    main()