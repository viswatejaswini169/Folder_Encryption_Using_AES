# Folder Encryption Using AES

## Overview

Folder Encryption Using AES is a Python-based desktop application that provides secure folder-level protection using AES-256 encryption. The application encrypts all files within a selected folder, obfuscates original file names, and securely manages encryption keys through manual storage or email delivery.

Built with a modern CustomTkinter graphical user interface, the application offers a simple and efficient way to protect sensitive data from unauthorized access.

---

## Features

* AES-256 encryption for strong data protection
* Encrypts all files within a selected folder
* File name obfuscation using random identifiers
* Secure encrypted mapping file for restoring original file names
* Optional folder backup before encryption
* Email-based AES key delivery using Gmail SMTP
* User-friendly CustomTkinter GUI
* Progress tracking and status updates
* Secure folder decryption using the generated AES key

---

## Technologies Used

| Technology       | Purpose                       |
| ---------------- | ----------------------------- |
| Python 3         | Core programming language     |
| PyCryptodome     | AES encryption and decryption |
| CustomTkinter    | Modern GUI development        |
| SMTP (smtplib)   | Email delivery of AES keys    |
| JSON             | Secure file mapping storage   |
| OS, UUID, Shutil | File and folder management    |

---

## Project Workflow

### Encryption Process

1. User selects a folder.
2. System generates a unique AES-256 key.
3. Optional backup of the folder is created.
4. Files are encrypted using AES-256.
5. Original file names are replaced with random identifiers.
6. An encrypted mapping file is created.
7. AES key is displayed or sent via email.

### Decryption Process

1. User selects the encrypted folder.
2. User enters the AES key.
3. Mapping file is decrypted.
4. Original file names and contents are restored.

---

## Installation

### Prerequisites

Ensure the following software is installed:

* Python 3.8 or later
* pip (Python Package Manager)

### Install Dependencies

```bash
pip install -r requirements.txt
```

Alternatively, install the required packages manually:

```bash
pip install customtkinter pycryptodome
```

### Run the Application

```bash
python team2.py
```

The graphical user interface will launch, allowing users to encrypt and decrypt folders securely.

---

## Usage

### Encrypt a Folder

1. Open the application.
2. Click **Choose Folder**.
3. Select the folder to encrypt.
4. Click **Encrypt (in place)**.
5. Choose one of the following options:

   * Display AES key on screen
   * Send AES key via email
6. Store the generated key securely.

### Decrypt a Folder

1. Open the application.
2. Select the encrypted folder.
3. Click **Decrypt (in place)**.
4. Enter the correct AES key.
5. Files and file names will be restored to their original state.

## Security Features

* AES-256 encryption
* AES EAX mode for confidentiality and integrity
* File name obfuscation
* Encrypted mapping file storage
* Secure key-based access control
* Optional backup and recovery support

## Conclusion

Folder Encryption Using AES provides a secure and efficient solution for protecting sensitive data stored in folders. By combining AES-256 encryption, file name obfuscation, encrypted mapping storage, and secure key management, the system ensures data confidentiality and integrity. The intuitive graphical interface makes the application accessible to both technical and non-technical users while maintaining strong security standards.
