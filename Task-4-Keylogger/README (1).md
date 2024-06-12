

# 📝 Keylogger Project

### 📚 Overview

During my internship at Prodigy Infotech, I developed a basic keylogger to understand its mechanics, ethical implications, and prevention strategies. This project was conducted ethically and for educational purposes only.

# 🛠️ Project Details

The keylogger performs the following tasks:

- Keystroke Capture: Utilizes Python’s pynput library to capture and log keystrokes.
- Stealth Mode: Implements techniques to conceal the log file to evade detection.
- System Profiling: Gathers system information using Python’s platform module.
- Automated Reporting: Configures automated email transmission of logged data to a designated recipient.
- Robust Error Handling: Ensures continuous operation through comprehensive error management.
- Enhanced Distribution: Converts the keylogger script to a .exe file, facilitating ease of use and distribution without any malicious intent.
### 💻 GUI Integration
To make the keylogger more ethical, a GUI has been added using tkinter, allowing users to stop the keylogger if they choose.

# 📦 Libraries Used:

- pynput
- platform
- smtplib
- email
- tkinter
- ctypes
# 🚀 Usage
- Clone the Repository:

```bash
git clone https://github.com/yourusername/keylogger-project.git
cd keylogger-project
```
Install Required Libraries:

```bash
pip install pynput tkinter
```
# Edit the Script:

Add your email credentials in the send_email function:
python
Copy code
### Replace with your email details in the send_email function
```bash
message["From"] = "your_email@gmail.com"
message["To"] = "recipient_email@domain.com"
smtp.login("your_email@gmail.com", "your_password")
```
## Run the Keylogger:

```bash
Copy code
python keylogger.py
```
## Convert to Executable (Optional):

```bash
Copy code
pyinstaller --onefile keylogger.py
```
# 🛡️ Ethical Considerations
This keylogger project is intended for educational purposes only.
Unauthorized use of keyloggers is illegal and unethical.
Always ensure compliance with relevant laws and ethical guidelines.
# ⚠️ Disclaimer
My work with keyloggers is purely educational and conducted ethically as part of my internship. Unauthorized use of keyloggers is illegal and unethical. Always ensure compliance with relevant laws and ethical guidelines.

