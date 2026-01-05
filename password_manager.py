from tokenize import String
from cryptography.fernet import Fernet # used for symmetric key encryption
import tkinter # used for the gui
import secrets # tool for generating cryptographically strong random numbers. It is designed specifically for managing sensitive data like passwords
# use SQLlite to store passwords
from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.primitives.kdf.pbkdf2 import PBKDF2HMAC
import base64
import os
import sqlite3
from tkinter import messagebox
import re
import sys



DB_Name = "passwords.db"

def check_if_new_user():
    conn = sqlite3.connect(DB_Name)
    cursor = conn.cursor()
    cursor.execute("SELECT * FROM master_password")
    data = cursor.fetchone()
    conn.close 
    return data is None

def new_user_gui(window):
    # clear any old widgets from the window
    for widget in window.winfo_children():
        widget.destroy()
    
    # add instuction tkinter input
    instruction = tkinter.Label(window, text = "Create Master Password")
    instruction.pack(pady=20)

    # add the input box
    txt_password = tkinter.Entry(window, width=20, show="*")
    txt_password.pack(pady=10)
    
    # define what happens when the user clicks save
    def save_password():
        password_txt = txt_password.get()
        score, string = strength_checker(password_txt)
        if int(score) <= 4:
            messagebox.showerror("Error", string)
            return

        conn = sqlite3.connect(DB_Name)
        cursor = conn.cursor()

        salt,encrypted_password = encrypt_password(password_txt)
        # spl automatically adds the id
        cursor.execute("""INSERT INTO master_password (password_hash, salt) VALUES (? , ?)""", (encrypted_password, salt))

        conn.commit()
        conn.close()
        messagebox.showinfo("Success", "Account created! Please restart the app to login.")
        window.destroy() # close the app 
    # save button
    btn_save = tkinter.Button(window, text="Save Master Password", command=save_password)
    btn_save.pack(pady=20)




    
def returning_user_gui(window):
    for widget in window.winfo_children():
        widget.destroy()
    
    # add instuction tkinter input
    instruction = tkinter.Label(window, text = "Enter Password")
    instruction.pack(pady=20)

    txt_password = tkinter.Entry(window, width = 20, show = "*")
    txt_password.pack(pady=20)

    def validate_login():
        password_input = txt_password.get()
        conn = sqlite3.connect(DB_Name)
        cursor = conn.cursor()
        cursor.execute("SELECT password_hash, salt FROM master_password")
        data = cursor.fetchone()
        conn.close()

        if data is None:
            messagebox.showerror("ERROR", "No user found. Please restart to register.")
            return
        stored_hash = data[0]
        stored_salt = data[1]

        kdf = PBKDF2HMAC(algorithm=hashes.SHA256(), length=32, salt=stored_salt, iterations=600000)
        # calculate what the hash should be with the salt from the database
        input_hash = kdf.derive(password_input.encode())
        if input_hash == stored_hash:
            encryption_key = base64.urlsafe_b64encode(input_hash)
            messagebox.showinfo("Success", "Login Accepted")
            vault_gui(window, encryption_key)
        else:
            messagebox.showerror("Error", "Incorrect Password")
            txt_password.delete(0, 'end') # clear the box so the user can try again
    btn_login = tkinter.Button(window, text="Login", command=validate_login)
    btn_login.pack(pady=20)
    



def encrypt_password(password):
    salt = os.urandom(16)
    kdf = PBKDF2HMAC(
        algorithm = hashes.SHA256(),
        length = 32,
        salt = salt,
        iterations = 600000
    )
    encrypted_password = kdf.derive(password.encode())
    return salt, encrypted_password

def strength_checker(password):
    string = ""
    score = 0

    # a good password should have a length of at least 12
    if len(password) >= 12:
        score+=1
    else:
        string += "password must have a length of at least 12, "
        

    # password should contain a capital letter
    if re.search(r"[A-Z]",password):
        score+=1
    else:
        string += "password must contain a capital letter, "
        
    
    # password should contain a lowercase letter
    if re.search(r"[a-z]",password):
        score+=1
    else:
        string += "password must contain a lowercase letter, "
        

    # password should contain a special character !#$%&'()*+,-./:;<=>?@[\]^_\`{|}~
    if re.search(r"[!#$%&'()*+,-./:;<=>?@""[\]^_\`{|}~]", password):
        score+=1
    else:
        string += "password must contain a special character, "
        

    # password should contain a number
    if re.search(r"[123456789]", password):
        score+=1
    else:
        string += "password must contain a number, "

    # password should not contain spaces
    if re.search(r"\s+",password):
        string += "password cannot contain a space, "
        sys.exit()

    return str(score), string





def add_password(window, key):
    for widget in window.winfo_children():
        widget.destroy()
    window.title("Add Password")

    
    # add instuction tkinter input
    instruction0 = tkinter.Label(window, text = "Enter Website Name:")
    instruction0.pack()
    txt_website = tkinter.Entry(window, width = 20)
    txt_website.pack()

    instruction1 = tkinter.Label(window, text = "Enter Username:")
    instruction1.pack()
    txt_username = tkinter.Entry(window, width = 20)
    txt_username.pack()


    instruction2 = tkinter.Label(window, text = "Enter Password:")
    instruction2.pack()    
    txt_password = tkinter.Entry(window, width = 20, show = "*")
    txt_password.pack()

    def save_password():
        password_txt = txt_password.get()
        username_txt = txt_username.get()
        website_txt = txt_website.get()

        score, string = strength_checker(password_txt)
        if int(score) <= 4:
            messagebox.showerror("Error", string)
            return
        if website_txt == "":
            messagebox.showerror("Error", "Website cannot be empty")
        if password_txt == "":
            messagebox.showerror("Error", "Password cannot be empty")
        
        conn = sqlite3.connect(DB_Name)
        cursor = conn.cursor()

        f = Fernet(key)
        encrypted_password = f.encrypt(password_txt.encode())
        # spl automatically adds the id
        cursor.execute("""INSERT INTO password_vault (website, username, encrypted_password) VALUES (? , ? , ?)""", (website_txt, username_txt, encrypted_password))

        conn.commit()
        conn.close()
        messagebox.showinfo("Success", "Password Saved")
        vault_gui(window, key)
        
    tkinter.Button(window, text="Save", command=save_password).pack(pady=10)
    tkinter.Button(window, text="Cancel", command=lambda: vault_gui(window, key)).pack()


def delete_password(window, key):
    for widget in window.winfo_children():
        widget.destroy()

    window.title("Delete Password")


    instruction0 = tkinter.Label(window, text = "Enter Website Name to Delete:")
    instruction0.pack()
    txt_website = tkinter.Entry(window, width = 20)
    txt_website.pack()

    conn = sqlite3.connect(DB_Name)
    cursor = conn.cursor()
    cursor.execute("SELECT website FROM password_vault")
    rows = cursor.fetchall()
    for row in rows:
            website = row[0]
            display_text = f"{website}"
            label = tkinter.Label(window, text = display_text)
            label.pack()
    conn.close()

    def delete_pass():
        website_txt = txt_website.get()
        if website_txt == "":
            messagebox.showerror("Error", "website cannot be empty")
        conn = sqlite3.connect(DB_Name)
        cursor = conn.cursor()
        
        cursor.execute("""DELETE FROM password_vault WHERE ? = ?""", (website, website_txt))

        conn.commit()
        conn.close()



        
    
        messagebox.showinfo("Success", "Password Deleted")
        vault_gui(window, key)

    tkinter.Button(window, text="Delete", command=delete_pass).pack(pady=10)
    tkinter.Button(window, text="Cancel", command=lambda: vault_gui(window, key)).pack()

def decrypt_pass(encrypted_pass, key):
        f = Fernet(key)
        try:
            return f.decrypt(encrypted_pass).decode()
        except:
            return "Error"
# this is the gui to view the stored passwords
def vault_gui(window, key):
    for widget in window.winfo_children():
        widget.destroy()

    window.geometry("600x400")
    window.title("My Password Vault")
    
    conn = sqlite3.connect(DB_Name)
    cursor = conn.cursor()
    cursor.execute("SELECT website, username, encrypted_password FROM password_vault")
    rows = cursor.fetchall()
    conn.close()

    header = tkinter.Label(window, text = "Website | Username | Password", font = ("Arial", 12, "bold"))
    header.pack(pady = 10)

    for row in rows:
        website = row[0]
        username = row[1]
        encrypted_password = row[2]

        decrypted_pass = decrypt_pass(encrypted_password, key)
        display_text = f"{website} | {username} | {decrypted_pass}"
        label = tkinter.Label(window, text = display_text)
        label.pack()
    
    def add_password_gui():
        add_password(window, key)
    def delete_password_gui():
        delete_password(window, key)

    btn_add = tkinter.Button(window, text = "Add New Password", command = add_password_gui)
    btn_add.pack(pady=10)
    btn_add2 = tkinter.Button(window, text = "Delete Password", command = delete_password_gui)
    btn_add2.pack(pady=10)


    



def start_app():
    # the connection is what allows us to edit the db file
    conn = sqlite3.connect(DB_Name)
    # the cursor is what runs the commands to actually edit the file
    cursor = conn.cursor()

    # table that stores the master password the one that logs the user into the manager
    cursor.execute("""
    CREATE TABLE IF NOT EXISTS master_password (id INTEGER PRIMARY KEY, password_hash BLOB NOT NULL, salt BLOB NOT NULL)
    """)
    cursor.execute("""
    CREATE TABLE IF NOT EXISTS password_vault (id INTEGER PRIMARY KEY AUTOINCREMENT, website TEXT NOT NULL, username TEXT, encrypted_password BLOB NOT NULL)
    """)

    conn.commit()
    conn.close()

    root = tkinter.Tk()
    root.title("Cheesy Password Manager")
    # creates a page in the terminal
    root.geometry("400x300")

    if check_if_new_user():
        new_user_gui(root)
    else:
        returning_user_gui(root)
       

    
    root.mainloop()




start_app()
