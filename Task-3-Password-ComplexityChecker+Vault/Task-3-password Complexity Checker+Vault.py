import re
import hashlib
import re
import sqlite3
import requests
from tkinter import *
from zxcvbn import zxcvbn
from tkinter import simpledialog
from functools import partial
import uuid
import pyperclip
import base64
import os
from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.primitives.kdf.pbkdf2 import PBKDF2HMAC
from cryptography.hazmat.backends import default_backend
from cryptography.fernet import Fernet


backend= default_backend()
salt =b'2444'
kdf =PBKDF2HMAC(
    algorithm=hashes.SHA256(),
    length=32,
    salt=salt,
    iterations=100000,
    backend=backend
)

encryptionKey = 0
def encrypt(message:bytes ,key:bytes) -> bytes:
    return Fernet(key).encrypt(message)
def decrypt(message:bytes ,token:bytes) -> bytes:
    return Fernet(token).decrypt(message)

# Database setup
with sqlite3.connect("./password_vault.db") as db:
    cursor = db.cursor()
cursor.execute("""
CREATE TABLE IF NOT EXISTS masterpassword(
id INTEGER PRIMARY KEY,
password TEXT NOT NULL,
recoveryKey  TEXT NOT NULL
)
""")

cursor.execute("""
CREATE TABLE IF NOT EXISTS vault(
id INTEGER PRIMARY KEY,
website TEXT NOT NULL,
username TEXT NOT NULL,
password TEXT NOT NULL
)
""")

# Popup for input
def popUp(text):
    answer = simpledialog.askstring("Input", text)
    return answer

# Initialize the main window
window = Tk()
window.title("PassVault")

def hashPassword(input):
    hash1 = hashlib.sha256(input)
    hash1=hash1.hexdigest()
    
    return hash1

# Define output labels globally so they can be destroyed when needed
pwned_output = None
output = None
crack_time_output = None
save_btn = None

import hashlib
import re
import requests

def check_pawned_status(password_input):
    """
    Check if the given password has been compromised in data breaches using the "Have I Been Pwned" API.

    Args:
        password_input (str or bytes): The password to check.

    Returns:
        str: A message indicating the status of the password:
             - If the password is found in the database: Returns the count of occurrences.
             - If the password is not found in the database: Returns "This password isn't in the list".
             - If there's an error during the API request: Returns an error message.
    """
    if isinstance(password_input, str):
        password_hash = hashlib.sha1(password_input.encode()).hexdigest()
    elif isinstance(password_input, bytes):
        password_hash = hashlib.sha1(password_input).hexdigest()
    else:
        return "Invalid input type. Password must be a string or bytes."

    prefix = password_hash[:5]
    url = f'https://api.pwnedpasswords.com/range/{prefix}'

    try:
        response = requests.get(url)
        response.raise_for_status()
        hash_suffix = password_hash[5:].upper()
        pattern = re.compile(r'[:\s]\s*')
        split_list = re.split(pattern, response.text)
        
        try:
            index = split_list.index(hash_suffix)
            return split_list[index + 1]
        except ValueError:
            return "This password isn't in the list"
    except requests.RequestException as e:
        return f"Error checking pwned status: {e}"


def firstScreen():
    for widget in window.winfo_children():
        widget.destroy()

    window.geometry("640x480")
    window.title("PassVault - Create Master Password")
    window.configure(bg="#222222")

    main_frame = Frame(window, bg="#222222")
    main_frame.pack(fill=BOTH, expand=True, padx=20, pady=20)

    lbl = Label(main_frame, text="Create Master Password", font=("Helvetica", 16), fg="#69FF69", bg="#222222")
    lbl.pack(pady=10)

    txt = Entry(main_frame, width=30, show="*")
    txt.pack(pady=5)
    txt.focus()

    lbl1 = Label(main_frame, text="Re-enter Password", fg="#69FF69", bg="#222222")
    lbl1.pack(pady=5)

    txt1 = Entry(main_frame, width=30, show="*")
    txt1.pack(pady=5)

    def save_password():
        try:
            if txt.get() == txt1.get():
                sql = "DELETE FROM masterpassword WHERE id = 1"
                cursor.execute(sql)
                hashPswd = hashPassword(txt.get().encode('utf-8'))
                key = str(uuid.uuid4().hex)
                recoveryKey = hashPassword(key.encode('utf-8'))
                global encryptionKey
                encryptionKey = base64.urlsafe_b64encode(kdf.derive(txt.get().encode()))

                insert_password = """INSERT INTO masterpassword(password, recoveryKey) VALUES(?, ?)"""
                cursor.execute(insert_password, (hashPswd, recoveryKey))
                db.commit()
                lbl.config(text="Password Saved", fg="#69FF69")
                recoveryScreen(key)
            else:
                lbl.config(text="Passwords do not match.", fg="#FF5A5A")
        except sqlite3.Error as e:
            lbl.config(text=f"Error saving password: {e}", fg="#FF5A5A")

    save_btn = Button(main_frame, text="Save Password", command=save_password, bg="#4CAF50", fg="white", padx=10, pady=5)
    save_btn.pack(pady=10)
    save_btn.pack_forget()  # Initially hide the save button

    def check_and_save_password():
        global pwned_output, output, crack_time_output

        if txt.get().strip() == "" or txt1.get().strip() == "":
            lbl.config(text="Fields cannot be empty!", fg="#FF5A5A")
            return

        if txt.get() == txt1.get():
            pswd = txt.get()
            response = check_pawned_status(pswd)

            if pwned_output:
                pwned_output.destroy()
            if output:
                output.destroy()
            if crack_time_output:
                crack_time_output.destroy()

            if "Error" in response:
                lbl.config(text=response, fg="#FF5A5A")
                return

            # Check password complexity
            password_strength = zxcvbn(pswd)
            crack_time = password_strength['crack_times_display']['offline_slow_hashing_1e4_per_second']
            crack_time_output = Label(main_frame, text=f"Estimated time to crack the password: {crack_time}", foreground="#69FF69", bg="#222222")
            crack_time_output.pack(pady=5)

            if response == "This password isn't in the list":
                lbl.config(text="Password is safe to use.", fg="#69FF69")
                pwned_output = Label(main_frame, text="Good news! - No pwnage found.", fg="#69FF69", bg="#222222", font=('Helvetica', 16))
                output = Label(main_frame, text="This password wasn't found in any of the sources loaded into Have I Been Pwned.",
                               fg="#69FF69", bg="#222222", wraplength=400, font=('Helvetica', 14))
                pwned_output.pack(pady=10)
                output.pack(pady=0)
                save_btn.pack()  # Show the save button

            else:
                lbl.config(text="Password is pwned! Please choose a different password.", fg="#FF5A5A")
                pwned_output = Label(main_frame, text="Your Password has been Pwned!", fg="#FF5A5A", bg="#222222", font=('Helvetica', 16))
                output = Label(main_frame, text=f"This password has previously appeared in a data breach and should never be used. There are {response} instances of this password in the Have I Been Pwned database.",
                               fg="#FF5A5A", bg="#222222", wraplength=400, font=('Helvetica', 14))
                pwned_output.pack(pady=10)
                output.pack(pady=0)
                save_btn.pack_forget()  # Hide the save button

        else:
            lbl.config(text="Passwords do not match.", fg="#FF5A5A")
            save_btn.pack_forget()  # Hide the save button

    btn_check_and_save = Button(main_frame, text="Check & Save", command=check_and_save_password, bg="#2196F3", fg="white", padx=10, pady=5)
    btn_check_and_save.pack(pady=10)

def recoveryScreen(key):
    for widget in window.winfo_children():
        widget.destroy()

    window.geometry("640x480")
    window.title("Recovery Key  - Save this Key to able to recover account")
    window.configure(bg="#222222")

    main_frame = Frame(window, bg="#222222")
    main_frame.pack(fill=BOTH, expand=True, padx=20, pady=20)

    

    lbl1 = Label(main_frame, text=key, fg="#69FF69", bg="#222222")
    lbl1.pack(pady=5)

    txt1 = Entry(main_frame, width=30, show="*")
    txt1.pack(pady=5)
    
    def copyKey():
        pyperclip.copy(lbl1.cget("text"))
        
    btn_Copy_Key = Button(main_frame, text="Copy Key", command=copyKey, bg="#2196F3", fg="white", padx=10, pady=5)
    btn_Copy_Key.pack(pady=10)
    
    def done():
        passwordVault()
    
    
    
    btn_done = Button(main_frame, text="Done", command=done, bg="#2196F3", fg="white", padx=10, pady=5)
    btn_done.pack(pady=10)
    
    
    
                   
def resetScreen():
    for widget in window.winfo_children():
        widget.destroy()

    window.geometry("640x480")
    window.title("Reset Password")
    window.configure(bg="#222222")

    main_frame = Frame(window, bg="#222222")
    main_frame.pack(fill=BOTH, expand=True, padx=20, pady=20)
    
    lbl = Label(main_frame, text="Enter Recovery Key", font=("Helvetica", 16), fg="#69FF69", bg="#222222")
    lbl.pack(pady=10)

    txt = Entry(main_frame, width=30)
    txt.pack(pady=5)
    txt.focus()
    
    lbl = Label(main_frame)
    lbl.pack(pady=10)
    
    
    def getRecoveryKey():
        input_text = txt.get().encode('utf-8')
        RecoveryKeyCheck = hashPassword(input_text)
        cursor.execute('SELECT * FROM masterpassword WHERE id =1 AND  recoveryKey = ? ',(RecoveryKeyCheck,))
        return cursor.fetchall()


        
        
    def checkRecoveryKey():
        check=getRecoveryKey()
        if check:
            firstScreen()
        else:
            txt.delete(0,'end')
            lbl.conf(Text="Wrong Key")
    
 
    btn_done = Button(main_frame, text="Check Key ", command=checkRecoveryKey, bg="#2196F3", fg="white", padx=10, pady=5)
    btn_done.pack(pady=10)
       

def login():
    for widget in window.winfo_children():
        widget.destroy()

    window.geometry("300x300")
    window.title("PassVault - Login")
    window.configure(bg="#222222")

    main_frame = Frame(window, bg="#222222")
    main_frame.pack(fill=BOTH, expand=True, padx=20, pady=20)

    lbl = Label(main_frame, text="Enter Master Password", font=("Helvetica", 16), fg="#69FF69", bg="#222222")
    lbl.pack(pady=10)

    txt = Entry(main_frame, width=30, show="*")
    txt.pack(pady=5)
    txt.focus()

    lbl1 = Label(main_frame, fg="#FF5A5A", bg="#222222")
    lbl1.pack(pady=5)
    
    def getMasterPassword():
        try:
            checkHashedPassword = hashPassword(txt.get().encode('utf-8'))
            global encryptionKey
            encryptionKey=base64.urlsafe_b64encode(kdf.derive(txt.get().encode()))
            cursor.execute("SELECT * FROM masterpassword WHERE id = 1 AND password = ?", (checkHashedPassword,))
            return cursor.fetchall()
        except sqlite3.Error as e:
            lbl1.config(text=f"Database error: {e}", fg="#FF5A5A")
            return []

    def checkPassword():
        match = getMasterPassword()
        if match:
            passwordVault()
        else:
            txt.delete(0, 'end')
            lbl1.config(text="Wrong Password", fg="#FF5A5A")
            
    def resetPassword():
        resetScreen()
        

    btn = Button(main_frame, text="Submit", command=checkPassword, bg="#2196F3", fg="white", padx=10, pady=5)
    btn.pack(pady=10)
    
    btn = Button(main_frame, text="Reset Password", command=resetPassword, bg="#2196F3", fg="white", padx=10, pady=5)
    btn.pack(pady=10)

def passwordVault():
    global pwned_output, output, crack_time_output

    for widget in window.winfo_children():
        widget.destroy()

    pwned_output = None
    output = None
    crack_time_output = None

    def addEntry():
        website = encrypt(popUp("Website").encode(),encryptionKey)
        username = encrypt(popUp("username").encode(),encryptionKey)
        password = encrypt(popUp("password").encode(),encryptionKey)

        if not website or not username or not password:
            return

        try:
            insert_fields = """INSERT INTO vault(website, username, password) VALUES(?, ?, ?)"""
            cursor.execute(insert_fields, (website, username, password))
            db.commit()
        except sqlite3.Error as e:
            print(f"Error adding entry: {e}")

        passwordVault()

    def removeEntry(entry_id):
        try:
            cursor.execute("DELETE FROM vault WHERE id = ?", (entry_id,))
            db.commit()
        except sqlite3.Error as e:
            print(f"Error removing entry: {e}")

        passwordVault()

    def checkPasswordStrength(password):
        global pwned_output, output, crack_time_output

        decrypted_password = decrypt(password, encryptionKey).decode('utf-8')  # Decode bytes to string

        response = check_pawned_status(decrypted_password)

        if pwned_output:
            pwned_output.destroy()
        if output:
            output.destroy()
        if crack_time_output:
            crack_time_output.destroy()

        # Check password complexity
        password_strength = zxcvbn(decrypted_password)
        crack_time = password_strength['crack_times_display']['offline_slow_hashing_1e4_per_second']
        crack_time_output = Label(main_frame, text=f"Estimated time to crack the password: {crack_time}", foreground="#69FF69", bg="#222222")
        crack_time_output.pack(pady=5)

        if response == "This password isn't in the list":
            pwned_output = Label(main_frame, text="Good news! - No pwnage found.", fg="#69FF69", bg="#222222", font=('Helvetica', 16))
            output = Label(main_frame, text="This password wasn't found in any of the sources loaded into Have I Been Pwned.",
                        fg="#69FF69", bg="#222222", wraplength=400, font=('Helvetica', 14))
            pwned_output.pack(pady=10)
            output.pack(pady=0)
        else:
            pwned_output = Label(main_frame, text="Your Password has been Pwned!", fg="#FF5A5A", bg="#222222", font=('Helvetica', 16))
            output = Label(main_frame, text=f"This password has previously appeared in a data breach and should never be used. There are {response} instances of this password in the Have I Been Pwned database.",
                        fg="#FF5A5A", bg="#222222", wraplength=400, font=('Helvetica', 14))
            pwned_output.pack(pady=10)
            output.pack(pady=0)



    window.geometry("800x800")
    window.title("PassVault - The Vault")
    window.configure(bg="#222222")

    main_frame = Frame(window, bg="#222222")
    main_frame.pack(fill=BOTH, expand=True, padx=20, pady=20)

    lbl = Label(main_frame, text="The Vault", font=("Helvetica", 16), fg="#69FF69", bg="#222222")
    lbl.pack(pady=10)

    btn_add = Button(main_frame, text="Add", command=addEntry, bg="#4CAF50", fg="white", padx=10, pady=5)
    btn_add.pack(pady=10)

    columns_frame = Frame(main_frame, bg="#222222")
    columns_frame.pack(pady=5)

    lbl_website = Label(columns_frame, text="Website", fg="#69FF69", bg="#222222", font=("Helvetica", 12))
    lbl_website.grid(row=0, column=0, padx=20)

    lbl_username = Label(columns_frame, text="Username", fg="#69FF69", bg="#222222", font=("Helvetica", 12))
    lbl_username.grid(row=0, column=1, padx=20)

    lbl_password = Label(columns_frame, text="Password", fg="#69FF69", bg="#222222", font=("Helvetica", 12))
    lbl_password.grid(row=0, column=2, padx=20)
    
    columns_frame.grid_columnconfigure(3, weight=1)

    rows_frame = Frame(main_frame, bg="#222222")
    rows_frame.pack(pady=5)

    cursor.execute("SELECT * FROM vault")
    for idx, row in enumerate(cursor.fetchall()):
        website_lbl = Label(rows_frame, text=decrypt(row[1],encryptionKey), fg="#FFFFFF", bg="#222222", font=("Helvetica", 12))
        website_lbl.grid(row=idx, column=0, padx=20, pady=5, sticky="w")

        username_lbl = Label(rows_frame, text=decrypt(row[2],encryptionKey), fg="#FFFFFF", bg="#222222", font=("Helvetica", 12))
        username_lbl.grid(row=idx, column=1, padx=20, pady=5, sticky="w")

        password_lbl = Label(rows_frame, text=decrypt(row[3],encryptionKey), fg="#FFFFFF", bg="#222222", font=("Helvetica", 12))
        password_lbl.grid(row=idx, column=2, padx=20, pady=5, sticky="w")
        
        rows_frame.grid_columnconfigure(3, weight=1)

        btn_check_password = Button(rows_frame, text="Check", command=partial(checkPasswordStrength, row[3]), bg="#2196F3", fg="white", padx=5, pady=2)
        btn_check_password.grid(row=idx, column=4, padx=10, pady=5, sticky='e')

        btn_remove = Button(rows_frame, text="Remove", command=partial(removeEntry, row[0]), bg="#FF5A5A", fg="white", padx=5, pady=2)
        btn_remove.grid(row=idx, column=5, padx=10, pady=5, sticky='e')




# Start the application
cursor.execute("SELECT * FROM masterpassword")
if cursor.fetchall():
    login()
else:
    firstScreen()
window.mainloop()