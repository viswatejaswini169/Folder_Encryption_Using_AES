import os
import sys
import uuid
import json
import time
import shutil
import smtplib
import webbrowser
from base64 import b64encode, b64decode
from email.mime.text import MIMEText
from email.mime.multipart import MIMEMultipart

import customtkinter as ctk
from tkinter import filedialog, messagebox

from Crypto.Cipher import AES
from Crypto.Random import get_random_bytes

# ---------- constants ----------
APP_NAME = "Folder Protector"
MAGIC_DATA = b"FENC1"
MAGIC_MAP  = b"FMAP1"
MAP_FILENAME = ".secure_vault_map.bin"

ctk.set_appearance_mode("dark")
ctk.set_default_color_theme("dark-blue")


# ---------- AES helpers ----------
def aes_encrypt_bytes(raw: bytes, key: bytes) -> bytes:
    cipher = AES.new(key, AES.MODE_EAX)
    ct, tag = cipher.encrypt_and_digest(raw)
    return cipher.nonce + tag + ct

def aes_decrypt_bytes(packed: bytes, key: bytes) -> bytes:
    if len(packed) < 32:
        raise ValueError("Invalid AES blob")
    nonce, tag, ct = packed[:16], packed[16:32], packed[32:]
    cipher = AES.new(key, AES.MODE_EAX, nonce=nonce)
    return cipher.decrypt_and_verify(ct, tag)


# ---------- mapping helpers ----------
def load_mapping(folder: str, key: bytes) -> dict:
    path = os.path.join(folder, MAP_FILENAME)
    if not os.path.exists(path):
        return {}
    with open(path, "rb") as f:
        blob = f.read()
    if not blob.startswith(MAGIC_MAP):
        raise ValueError("Mapping file format not recognized.")
    dec = aes_decrypt_bytes(blob[len(MAGIC_MAP):], key)
    return json.loads(dec.decode("utf-8"))

def save_mapping(folder: str, key: bytes, mapping: dict):
    path = os.path.join(folder, MAP_FILENAME)
    data = json.dumps(mapping, separators=(",", ":"), ensure_ascii=False).encode("utf-8")
    enc = MAGIC_MAP + aes_encrypt_bytes(data, key)
    with open(path, "wb") as f:
        f.write(enc)

# ---------- email ----------
def email_key(sender: str, app_password: str, receiver: str, key_b64: str):
    subject = "Secure Vault – AES Key"
    body = (
        "Here is your AES key (Base64):\n\n"
        f"{key_b64}\n\n"
        "Keep this key safe. It restores both content and original file names.\n"
        "Note: Files were encrypted in place and file names were obfuscated."
    )
    msg = MIMEMultipart()
    msg["From"] = sender
    msg["To"] = receiver
    msg["Subject"] = subject
    msg.attach(MIMEText(body, "plain"))

    srv = smtplib.SMTP("smtp.gmail.com", 587, timeout=30)
    srv.starttls()
    srv.login(sender, app_password)
    srv.send_message(msg)
    srv.quit()


# ---------- file utils ----------
def iter_files(folder: str, skip_names=None):
    skip_names = set(skip_names or [])
    for root, dirs, files in os.walk(folder):
        files = [f for f in files if f not in skip_names]
        for name in files:
            yield os.path.join(root, name)

def ensure_backup(src_folder: str) -> str:
    ts = time.strftime("%Y%m%d_%H%M%S")
    base = os.path.basename(src_folder.rstrip("/\\"))
    dst = os.path.join(os.path.dirname(src_folder), f"{base}_backup_{ts}")
    shutil.copytree(src_folder, dst, ignore=shutil.ignore_patterns(MAP_FILENAME))
    return dst

def cleanup_empty_dirs(folder: str):
    try:
        for root, dirs, files in os.walk(folder, topdown=False):
            if not os.listdir(root):
                os.rmdir(root)
    except Exception as e:
        print(f"Warning: Could not clean up all empty directories: {e}")


# ---------- UI ----------
class EmailCredentialsDialog(ctk.CTkToplevel):
    def __init__(self, parent):
        super().__init__(parent)
        self.title("Enter Email Credentials")
        self.geometry("400x250")
        self.transient(parent)
        self.grab_set()

        self.sender = None
        self.app_password = None
        self.receiver = None

        self.create_widgets()

    def create_widgets(self):
        self.columnconfigure(1, weight=1)
        ctk.CTkLabel(self, text="Gmail address:").grid(row=0, column=0, padx=10, pady=(20, 5), sticky="w")
        self.sender_entry = ctk.CTkEntry(self, width=250)
        self.sender_entry.grid(row=0, column=1, padx=10, pady=(20, 5), sticky="ew")
        ctk.CTkLabel(self, text="App Password:").grid(row=1, column=0, padx=10, pady=5, sticky="w")
        self.app_password_entry = ctk.CTkEntry(self, show="*", width=250)
        self.app_password_entry.grid(row=1, column=1, padx=10, pady=5, sticky="ew")
        ctk.CTkLabel(self, text="Receiver Email:").grid(row=2, column=0, padx=10, pady=5, sticky="w")
        self.receiver_entry = ctk.CTkEntry(self, width=250)
        self.receiver_entry.grid(row=2, column=1, padx=10, pady=5, sticky="ew")
        button_frame = ctk.CTkFrame(self, fg_color="transparent")
        button_frame.grid(row=3, column=0, columnspan=2, pady=(20, 10))
        ctk.CTkButton(button_frame, text="OK", command=self.on_ok).pack(side="left", padx=10)
        ctk.CTkButton(button_frame, text="Cancel", command=self.on_cancel).pack(side="left", padx=10)

    def on_ok(self):
        self.sender = self.sender_entry.get().strip()
        self.app_password = self.app_password_entry.get().strip()
        self.receiver = self.receiver_entry.get().strip()
        if not self.sender or not self.app_password or not self.receiver:
            messagebox.showwarning("Incomplete Information", "All fields are required.", parent=self)
            self.sender, self.app_password, self.receiver = None, None, None
            return
        self.destroy()

    def on_cancel(self):
        self.destroy()

    def get_credentials(self):
        self.wait_window()
        return self.sender, self.app_password, self.receiver


class KeyDisplayDialog(ctk.CTkToplevel):
    def __init__(self, parent, key_b64: str):
        super().__init__(parent)
        self.title("CRITICAL: Save Your AES Key")
        self.geometry("480x300")
        self.transient(parent)
        self.grab_set()
        self.key_b64 = key_b64
        self.user_agreed = False
        self.create_widgets()

    def create_widgets(self):
        self.columnconfigure(0, weight=1)
        ctk.CTkLabel(self, text="Your NEW Encryption Key", font=("Segoe UI", 18, "bold")).pack(pady=(20, 10))
        key_frame = ctk.CTkFrame(self)
        key_frame.pack(fill="x", padx=20, pady=5)
        self.key_entry = ctk.CTkEntry(key_frame, font=("Courier New", 14), width=350)
        self.key_entry.pack(side="left", fill="x", expand=True, padx=(10, 5), pady=10)
        self.key_entry.insert(0, self.key_b64)
        self.key_entry.configure(state="readonly")
        ctk.CTkButton(key_frame, text="Copy", width=60, command=self.copy_key).pack(side="left", padx=(5, 10), pady=10)
        ctk.CTkLabel(self, text="Copy this key and save it in a secure location, like a password manager.\nIT CANNOT BE RECOVERED.", wraplength=440, justify="center").pack(pady=10)
        self.confirm_var = ctk.BooleanVar()
        self.confirm_check = ctk.CTkCheckBox(self, text="I have saved this key. I understand if I lose it, my data is lost forever.", variable=self.confirm_var, command=self.toggle_continue_button)
        self.confirm_check.pack(pady=10)
        self.continue_btn = ctk.CTkButton(self, text="Encrypt My Files", command=self.on_continue, state="disabled")
        self.continue_btn.pack(pady=(10, 20), ipady=5)

    def copy_key(self):
        self.clipboard_clear()
        self.clipboard_append(self.key_b64)
        messagebox.showinfo("Copied", "Key copied to clipboard!", parent=self)

    def toggle_continue_button(self):
        self.continue_btn.configure(state="normal" if self.confirm_var.get() else "disabled")

    def on_continue(self):
        self.user_agreed = True
        self.destroy()

    def get_agreement(self):
        self.wait_window()
        return self.user_agreed

class KeyHandlingChoiceDialog(ctk.CTkToplevel):
    def __init__(self, parent):
        super().__init__(parent)
        self.title("Choose Key Handling Method")
        self.geometry("450x220")
        self.transient(parent)
        self.grab_set()

        self.choice = None

        self.create_widgets()

    def create_widgets(self):
        ctk.CTkLabel(self, text="How do you want to receive the encryption key?", font=("Segoe UI", 16, "bold")).pack(pady=(20, 15))

        btn_display = ctk.CTkButton(self, text="Display on Screen (Most Secure)", command=lambda: self.set_choice("display"), height=40)
        btn_display.pack(fill="x", padx=30, pady=8)
        ctk.CTkLabel(self, text="The key is shown for you to copy. You are responsible for saving it.").pack(padx=30, anchor="w")

        btn_email = ctk.CTkButton(self, text="Send via Email (Less Secure)", command=lambda: self.set_choice("email"), height=40, fg_color="#E59728", hover_color="#C78423")
        btn_email.pack(fill="x", padx=30, pady=(15, 8))
        ctk.CTkLabel(self, text="The key is sent to your email. Use a secure 'App Password'.").pack(padx=30, anchor="w")

    def set_choice(self, choice: str):
        self.choice = choice
        self.destroy()

    def get_choice(self):
        self.wait_window()
        return self.choice


class App(ctk.CTk):
    def __init__(self):
        super().__init__()
        self.title(APP_NAME)
        self.geometry("940x560")
        self.minsize(860, 520)
        self.folder = None
        self.status_var = ctk.StringVar(value="Select a folder to begin…")
        self.backup_var = ctk.BooleanVar(value=True)
        self.build_ui()

    def build_ui(self):
        header = ctk.CTkFrame(self, corner_radius=16)
        header.pack(fill="x", padx=16, pady=(16, 8))
        title = ctk.CTkLabel(header, text="🔐  Secure Vault", font=("Segoe UI", 26, "bold"))
        title.pack(side="left", padx=12, pady=12)
        subtitle = ctk.CTkLabel(header, text="AES-256 Encryption • File Obfuscation • Flexible Key Handling", font=("Segoe UI", 14))
        subtitle.pack(side="right", padx=12)
        body = ctk.CTkFrame(self, corner_radius=16)
        body.pack(fill="both", expand=True, padx=16, pady=8)
        left = ctk.CTkFrame(body, width=260, corner_radius=16)
        left.pack(side="left", fill="y", padx=12, pady=12)
        right = ctk.CTkFrame(body, corner_radius=16)
        right.pack(side="right", fill="both", expand=True, padx=12, pady=12)
        ctk.CTkLabel(left, text="Actions", font=("Segoe UI", 18, "bold")).pack(anchor="w", padx=12, pady=(12, 6))
        ctk.CTkButton(left, text="Choose Folder", command=self.choose_folder, height=42).pack(fill="x", padx=12, pady=6)
        self.backup_chk = ctk.CTkCheckBox(left, text="Backup before encrypt (recommended)", variable=self.backup_var)
        self.backup_chk.pack(anchor="w", padx=12, pady=(6, 10))
        self.encrypt_btn = ctk.CTkButton(left, text="Encrypt (in place)", fg_color="#1db954", hover_color="#18a549", height=44, command=self.encrypt_in_place)
        self.encrypt_btn.pack(fill="x", padx=12, pady=6)
        self.decrypt_btn = ctk.CTkButton(left, text="Decrypt (in place)", fg_color="#ff4d4f", hover_color="#e64547", height=44, command=self.decrypt_in_place)
        self.decrypt_btn.pack(fill="x", padx=12, pady=6)
        
        ctk.CTkButton(left, text="Project Info", command=self.show_project_info, height=38, fg_color="gray50", hover_color="gray40").pack(fill="x", padx=12, pady=(20, 6))

        self.folder_label = ctk.CTkLabel(right, text="No folder selected", font=("Segoe UI", 15))
        self.folder_label.pack(anchor="w", padx=12, pady=(12, 4))
        self.preview = ctk.CTkTextbox(right, wrap="none", height=360)
        self.preview.pack(fill="both", expand=True, padx=12, pady=8)
        self.preview.configure(state="disabled")
        self.progress = ctk.CTkProgressBar(right, height=10)
        self.progress.pack(fill="x", padx=12, pady=(4, 2))
        self.progress.set(0)
        self.status_label = ctk.CTkLabel(right, textvariable=self.status_var, font=("Segoe UI", 13))
        self.status_label.pack(anchor="w", padx=12, pady=(0, 12))

    def set_status(self, txt: str, p: float | None = None):
        self.status_var.set(txt)
        if p is not None: self.progress.set(max(0, min(1, p)))
        self.update_idletasks()

    def refresh_preview(self):
        self.preview.configure(state="normal")
        self.preview.delete("1.0", "end")
        if not self.folder: self.preview.insert("end", "—")
        else:
            for root, dirs, files in os.walk(self.folder):
                rel = os.path.relpath(root, self.folder)
                indent = "" if rel == "." else f"[{rel}]"
                for d in dirs: self.preview.insert("end", f"{indent}/ {d}/\n")
                for f in files: self.preview.insert("end", f"{indent}  {f}\n")
        self.preview.configure(state="disabled")

    def choose_folder(self):
        path = filedialog.askdirectory(title="Select folder to protect")
        if not path: return
        self.folder = path
        self.folder_label.configure(text=path)
        self.set_status("Folder selected. Ready.")
        self.refresh_preview()

    def show_project_info(self):
        html_content = """
        <!DOCTYPE html>
        <html lang="en">
        <head>
          <meta charset="UTF-8">
          <meta name="viewport" content="width=device-width, initial-scale=1.0">
          <title>Project Information</title>
          <style>
            body { font-family: Arial, sans-serif; background: #f0f0f0; color: #000; margin: 0; display: flex; justify-content: center; padding: 30px; }
            .container { max-width: 800px; width: 100%; padding: 30px 40px; background: #fff; border-radius: 12px; box-shadow: 0 4px 12px rgba(0, 0, 0, 0.15); box-sizing: border-box; }
            .header { display: flex; justify-content: space-between; align-items: center; }
            .header img { height: 100px; width: 100px; object-fit: contain; }
            h1 { margin-bottom: 10px; color: #111; }
            p { font-size: 14px; margin-bottom: 20px; line-height: 1.5; }
            table { width: 100%; border-collapse: collapse; margin-bottom: 20px; }
            table, th, td { border: 1px solid #ddd; }
            th { background-color: #f5f5f5; text-align: left; padding: 10px; width: 30%; }
            td { padding: 10px; }
            .section-title { font-weight: bold; font-size: 16px; margin: 15px 0 10px 0; }
          </style>
        </head>
        <body>
          <div class="container">
            <div class="header">
              <h1>Project Information</h1>
              <img src="https://suprajatechnologies.com/images/logo.png" alt="Supraja Technologies Logo">
            </div>
            <p>This project was developed by <b>TEAM-2</b> as part of a <b>Cyber Security Internship</b>. This project is designed to <b>Secure the Organizations in Real World from Cyber Frauds performed by Hackers</b>.</p>
            <table>
              <tr><th>Project Name</th><td>Folder Encryption</td></tr>
              <tr><th>Project Description</th><td>Implementing Secured Encryption Standards for Folders which Contain Secured Data</td></tr>
              <tr><th>Project Start Date</th><td>22-AUG-2024</td></tr>
              <tr><th>Project End Date</th><td>06-SEP-2024</td></tr>
              <tr><th>Project Status</th><td><b style="color:green;">Completed</b></td></tr>
            </table>
            <div class="section-title">Developer Details</div>
                       <table>
              <tr><th>Name</th><th>Employee ID</th><th>Email</th></tr>
              <tr><td>KAMI LIKHITH</td><td>ST#IS#8058</td><td>kamilikhith@gmail.com</td></tr>
              <tr><td>ANAMTOJI MAHESH</td><td>ST#IS#8064</td><td>anamtojimahesh@gmail.com</td></tr>
              <tr><td>VISWA TEJASWINI THALLAPAKA</td><td>ST#IS#8069</td><td>viswatejaswinit@gmail.com</td></tr>
              <tr><td>NANU SUMANJALI</td><td>ST#IS#8080</td><td>sumanjalinanu2005@gmail.com</td></tr>
              <tr><td>KATTA GURAVAIAH</td><td>ST#IS#8087</td><td>kattaguravaiah39@gmail.com@gmail.com</td></tr>
            </table>
            <div class="section-title">Company Details</div>
            <table>
              <tr><th>Company</th><th>Value</th></tr>
              <tr><td>Name</td><td>Supraja Technologies</td></tr>
              <tr><td>Email</td><td>contact@suprajatechnologies.com</td></tr>
            </table>
          </div>
        </body>
        </html>
        """
        try:
            info_file_path = os.path.join(os.path.dirname(sys.argv[0]), "project_info.html")
            with open(info_file_path, "w") as f:
                f.write(html_content)
            webbrowser.open('file://' + os.path.realpath(info_file_path))
        except Exception as e:
            messagebox.showerror("Error", f"Could not open project info: {e}")
    

    def encrypt_in_place(self):
        if not self.folder:
            messagebox.showwarning("No Folder Selected", "Please choose a folder before encrypting.")
            return

        choice_dialog = KeyHandlingChoiceDialog(self)
        key_choice = choice_dialog.get_choice()

        if not key_choice:
            self.set_status("Encryption cancelled by user.")
            return

        if self.backup_var.get():
            self.set_status("Creating backup…", 0.0)
            try:
                backup_dir = ensure_backup(self.folder)
            except Exception as e:
                messagebox.showerror("Backup failed", str(e))
                return
            self.set_status(f"Backup created: {backup_dir}", 0.05)
        
        key = get_random_bytes(32)
        key_b64 = b64encode(key).decode()
        
        email_creds = None
        if key_choice == "display":
            key_dialog = KeyDisplayDialog(self, key_b64)
            if not key_dialog.get_agreement():
                self.set_status("Encryption cancelled by user.")
                return
        elif key_choice == "email":
            creds_dialog = EmailCredentialsDialog(self)
            sender, app_pw, receiver = creds_dialog.get_credentials()
            if not sender or not app_pw or not receiver:
                self.set_status("Encryption cancelled by user.")
                return
            email_creds = {"sender": sender, "app_pw": app_pw, "receiver": receiver}

        mapping = {}
        all_files = [p for p in iter_files(self.folder, skip_names=[MAP_FILENAME])]
        total, changed = len(all_files), 0
        for i, path in enumerate(all_files, 1):
            if os.path.basename(path) == MAP_FILENAME: continue
            with open(path, "rb") as f:
                data = f.read()
            if data.startswith(MAGIC_DATA): continue
            enc = MAGIC_DATA + aes_encrypt_bytes(data, key)
            new_name = f"{uuid.uuid4().hex[:12]}.dat"
            new_path = os.path.join(os.path.dirname(path), new_name)
            with open(new_path, "wb") as f: f.write(enc)
            os.remove(path)
            rel_new = os.path.relpath(new_path, self.folder).replace(os.sep, '/')
            rel_orig = os.path.relpath(path, self.folder).replace(os.sep, '/')
            mapping[rel_new] = rel_orig
            changed += 1
            self.set_status(f"Encrypting… {i}/{total}", 0.1 + 0.8 * (i / max(1, total)))

        try:
            self.set_status("Writing encrypted name map…", 0.92)
            save_mapping(self.folder, key, mapping)
        except Exception as e:
            messagebox.showerror("Mapping save failed", f"Critical error: Map could not be saved:\n{e}\n\nRESTORE FROM YOUR BACKUP.")
            return

        if email_creds:
            try:
                self.set_status("Sending AES key via Gmail…", 0.96)
                email_key(email_creds["sender"], email_creds["app_pw"], email_creds["receiver"], key_b64)
            except smtplib.SMTPAuthenticationError:
                messagebox.showerror("Email Error", "Authentication failed.\nUse your Gmail *App Password* (not your normal password).")
                return
            except Exception as e:
                messagebox.showerror("Email Error", str(e))
                return

        self.set_status("Cleaning up empty directories...", 0.98)
        cleanup_empty_dirs(self.folder)
        self.set_status("Done.", 1.0)
        self.refresh_preview()
        msg = f"Encrypted files: {changed}\n\nYour folder is now secure."
        if email_creds:
            msg += f"\nAn email with the key has been sent to {email_creds['receiver']}."
        else:
            msg += "\nRemember to keep your AES key safe."
        messagebox.showinfo("Encryption Complete", msg)

    def decrypt_in_place(self):
        if not self.folder:
            messagebox.showwarning("No Folder Selected", "Please choose a folder before decrypting.")
            return
        from tkinter.simpledialog import askstring
        key_b64 = askstring("AES Key", "Enter your AES key (Base64):")
        if not key_b64: return
        try: key = b64decode(key_b64.strip())
        except Exception:
            messagebox.showerror("Invalid Key", "That does not look like a valid Base64 key.")
            return
        mapping = {}
        map_path = os.path.join(self.folder, MAP_FILENAME)
        if os.path.exists(map_path):
            try: mapping = load_mapping(self.folder, key)
            except Exception as e:
                messagebox.showerror("Mapping Error", f"Failed to open mapping file: {e}\n\nThis usually means the key is incorrect.")
                return
        changed = 0
        all_files = [p for p in iter_files(self.folder, skip_names=[MAP_FILENAME])]
        total = len(all_files)
        for i, path in enumerate(all_files, 1):
            with open(path, "rb") as f: blob = f.read()
            if not blob.startswith(MAGIC_DATA): continue
            try: dec = aes_decrypt_bytes(blob[len(MAGIC_DATA):], key)
            except ValueError:
                messagebox.showerror("Decrypt Error", f"Authentication failed for:\n{path}\n\nWrong key or file is corrupted.")
                return
            dest_path = path
            rel_obfus = os.path.relpath(path, self.folder).replace(os.sep, '/')
            if mapping and rel_obfus in mapping:
                orig_rel = mapping[rel_obfus]
                dest_path = os.path.join(self.folder, *orig_rel.split('/'))
            try:
                os.makedirs(os.path.dirname(dest_path), exist_ok=True)
                with open(dest_path, "wb") as f: f.write(dec)
                if path != dest_path: os.remove(path)
            except Exception as e:
                messagebox.showerror("File Write Error", f"Could not restore file to:\n{dest_path}\n\nError: {e}\n\nDecryption halted.")
                return
            changed += 1
            self.set_status(f"Decrypting… {i}/{total}", 0.1 + 0.8 * (i / max(1, total)))
        if os.path.exists(map_path):
            try: os.remove(map_path)
            except Exception: pass
        self.set_status("Cleaning up empty directories...", 0.98)
        cleanup_empty_dirs(self.folder)
        self.set_status("Done.", 1.0)
        self.refresh_preview()
        messagebox.showinfo("Decryption Complete", f"Files restored: {changed}\nOriginal names {'restored.' if mapping else 'could not be restored.'}")

# ---------- run ----------
if __name__ == "__main__":
    try:
        app = App()
        app.mainloop()
    except Exception as e:
        messagebox.showerror("Fatal Error", str(e))
        sys.exit(1)