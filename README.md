# Python Secure Password Manager

A local, desktop-based password manager built with Python and Tkinter. This application securely stores user credentials using industry-standard AES encryption and handles user authentication via PBKDF2 key derivation.

# Features

* Secure Authentication: User login is verified using SHA-256 hashing. The master password is never stored in plain text.
* AES-128 Encryption: All stored passwords (in the vault) are encrypted using Fernet (AES-128 in CBC mode).
* Salted Hashing: Uses a unique, randomly generated salt for every user to prevent rainbow table attacks.
* CRUD Functionality: Users can Create, Read, and Delete passwords from their local vault. (Updating coming soon)
* Password Strength Checker: Built-in regex validation ensures the Master Password meets security complexity standards.
* Local Storage: Data is persisted locally using SQLite.

# Tech Stack

* Language: Python 3.13.3
* GUI: Tkinter
* Database: SQLite3
* Cryptography: `cryptography` library (Fernet, PBKDF2HMAC)

# Installation & Usage

1.  Clone the repository
    git clone https://github.com/DarkCheese63/Password-Manager.git
    cd password-manager
    
2.  Install Dependencies
    This project requires the `cryptography` library.
    pip install cryptography
 
3.  Run the Application
    python password_manager.py

4.  First Run:
    * The app will detect that no database exists.
    * You will be prompted to create a Master Password.
    * Note: If you lose this password, your data cannot be recovered (as per secure design principles).

# Security Architecture

This application employs a "Trust No One" architecture regarding the database file:

1.  Master Password: When a user registers, a random 16-byte salt is generated. The password + salt are run through PBKDF2-HMAC-SHA256 (600,000 iterations) to derive a 32-byte key.
2.  Verification: Only the Hash and the Salt are stored in the `master_password` table.
3.  Vault Encryption: When the user logs in successfully, the derived key is loaded into memory and used to encrypt/decrypt entries in the `password_vault` table using*Fernet (AES).

# Screenshots

<img width="404" height="331" alt="image" src="https://github.com/user-attachments/assets/1e0825c8-32d9-46b0-ace7-e5642c398677" />


<img width="601" height="432" alt="image" src="https://github.com/user-attachments/assets/39e53bdf-7b2d-431b-a692-f81ce944c7de" />

