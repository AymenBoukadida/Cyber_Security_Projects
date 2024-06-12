# 🔐 Password Complexity Checker:
During my internship at Prodigy Infotech, I developed a password complexity checker using the zxcvbn library. This tool evaluates password strength and checks for breaches using the "Have I Been Pwned" API.

# 🔏 Password Vault:
I expanded the project by adding a secure password vault. This feature allows users to store passwords safely, encrypted with the cryptography library and managed via an SQLite database.

# 🔑 Master Password & Recovery Key:
Users create a master password, which derives an encryption key using PBKDF2 with SHA-256. Additionally, a unique recovery key, generated with UUID and hashed with SHA-256, ensures account recovery if the master password is forgotten.

## Key Features
- Strength Evaluation: Assesses password complexity and crack time.
- Compromise Check: Verifies if passwords have been compromised in breaches.
- Secure Storage: Encrypts passwords before storing them.
- Recovery Key: Allows users to reset their master password securely.
Technologies Used

## Libraries: 
- zxcvbn, requests, sqlite3, cryptography, hashlib, uuid
## Encryption: Fernet symmetric encryption, PBKDF2 with SHA-256
# Challenges and Learning
- Encryption Management: Secure handling of encryption keys.
- API Integration: Efficient password breach checks.
- User Interface: Designing a user-friendly interface.
- Recovery Implementation: Developing a robust recovery key system.


# Installation
-
Clone the repository:

```bash
git clone https://github.com/AymenBoukadida/Prodigy-Infotech-CS-Tasks.git
```

### Navigate to the project directory:

```bash
cd Task-3-Password-ComplexityChecker+Vault
```
### Install the required libraries:

```bash
pip install -r requirements.txt
```

# Usage
Create Master Password: Set up a master password for secure access.
Check Password Strength: Use the tool to evaluate and store your passwords securely.
Recovery Key: Save the generated recovery key for future password resets.

## 🔗 Links

[![linkedin](https://img.shields.io/badge/linkedin-0A66C2?style=for-the-badge&logo=linkedin&logoColor=white)](www.linkedin.com/in/aymen-boukadida-869b19256)


