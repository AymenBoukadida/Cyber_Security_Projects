# 🖥️ C2 Remote Agent — Educational Project

This repository contains a lightweight **Command & Control (C2) framework** developed for **ethical cybersecurity training and research**.  
The project demonstrates how a remote agent can collect system information, execute remote commands, and communicate with a central control server.

> ⚠️ **Educational Use Only**  
> This project was tested strictly inside a controlled laboratory environment using virtual machines and an isolated network.  
> It was also tested using a **malicious USB attack to simulate initial access**, exclusively for research and defensive learning purposes.

---

## 📌 Overview

The Python-based agent communicates with a Flask server to:

- Collect system & hardware information
- Execute remote system commands
- Capture screenshots & webcam images
- Retrieve browser history
- Perform heartbeat status communication
- Upload results to the C2 dashboard

The server provides:

- Real-time control dashboard (Flask + SocketIO)
- Command execution logs (SQLite database)
- File management and uploads

---

## 🛠️ Technologies & Libraries

### **Agent**
| Library | Purpose |
|---------|---------|
| `os`, `platform` | System information |
| `requests` | Communication with C2 server |
| `psutil` | CPU, RAM usage stats |
| `pyautogui` | Screenshots |
| `cv2` | Webcam images |
| `browser_history` | Extract browser history |
| `subprocess` | Shell command execution |
| `uuid` | Unique agent/device ID |

### **Server**
| Library | Purpose |
|---------|---------|
| `Flask` | API + Web dashboard |
| `Flask-SocketIO` | Real-time updates |
| `sqlite3` | Logging database |
| `threading` | Parallel agent handling |

---

## ⚙️ Key Features

- Remote shell command execution
- Screenshot and webcam capture
- Browser history extraction
- File upload and result logging
- Public IP detection
- Heartbeat communication protocol
- Real-time monitoring dashboard

---

## 🧪 Testing Environment

| Component | Version / Details |
|----------|-------------------|
| OS | Kali Linux 2024.3 (VirtualBox) |
| Python | 3.11+ |
| Attack Simulation | **Rubber Ducky malicious USB payload** |

Testing was performed entirely in an **isolated lab environment**.

---

## 🛡️ Ethical Considerations

- No persistence or replication
- No privilege escalation mechanisms
- No external targeting or uncontrolled execution
- For **red-team simulation & cybersecurity education only**
- Use only with **explicit authorization**

Unauthorized use may violate laws and ethical guidelines.  
You are responsible for complying with all security and legal policies.

---

## 📚 Learning Outcomes

- Understanding basic C2 architecture
- Remote execution concepts
- Data exfiltration channels
- SOC detection & defense awareness
- Red vs Blue team techniques

---

## 🚀 Future Improvements

- TLS encryption & certificate support
- Multi-agent management & tagging
- Authentication & role-based access
- Support for command scheduling
- Custom attack simulation scripts

---

## 👥 Authors

**Aymen Boukadida**  

Made with passion for cybersecurity research ❤️

---

## ⭐ Contribution

Pull requests are welcome for improvements and documentation additions.

---

## 📄 License

This project is provided for **educational and research purposes only** and is not intended for malicious use.

