import customtkinter as ctk
import sqlite3
import os
import hashlib
import base64
from cryptography.fernet import Fernet
import tkinter as tk
from tkinter import ttk

# ---------------- UI ----------------
ctk.set_appearance_mode("dark")
ctk.set_default_color_theme("blue")

DB_FILE = "vault.db"

# ---------------- DB INIT ----------------
def init_db():
    conn = sqlite3.connect(DB_FILE)
    cur = conn.cursor()

    cur.execute("""
        CREATE TABLE IF NOT EXISTS vault (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            site TEXT,
            username TEXT,
            password TEXT
        )
    """)

    cur.execute("""
        CREATE TABLE IF NOT EXISTS auth (
            id INTEGER PRIMARY KEY,
            master_hash TEXT,
            salt TEXT
        )
    """)

    conn.commit()
    conn.close()

init_db()

# ---------------- CRYPTO ----------------
def derive_key(password, salt):
    key = hashlib.pbkdf2_hmac(
        "sha256",
        password.encode(),
        salt.encode(),
        100000
    )
    return base64.urlsafe_b64encode(key)

# ---------------- AUTH ----------------
def register_master(password):
    salt = os.urandom(16).hex()
    master_hash = hashlib.sha256((password + salt).encode()).hexdigest()

    conn = sqlite3.connect(DB_FILE)
    cur = conn.cursor()
    cur.execute("DELETE FROM auth")
    cur.execute("INSERT INTO auth (id, master_hash, salt) VALUES (1, ?, ?)", (master_hash, salt))
    conn.commit()
    conn.close()

def verify_master(password):
    conn = sqlite3.connect(DB_FILE)
    cur = conn.cursor()
    cur.execute("SELECT master_hash, salt FROM auth WHERE id=1")
    row = cur.fetchone()
    conn.close()

    if not row:
        return False, None

    stored_hash, salt = row
    test_hash = hashlib.sha256((password + salt).encode()).hexdigest()

    if test_hash == stored_hash:
        return True, salt
    return False, None

# ---------------- GLOBAL ----------------
fernet = None

# ---------------- LOGIN ----------------
def login():
    global fernet

    pwd = login_entry.get()

    ok, salt = verify_master(pwd)

    if not ok:
        login_status.configure(text="Wrong password!", text_color="red")
        return

    key = derive_key(pwd, salt)
    fernet = Fernet(key)

    login_frame.destroy()
    main_app()

def first_time_setup():
    pwd = login_entry.get()

    if not pwd:
        login_status.configure(text="Enter a password!", text_color="red")
        return

    register_master(pwd)
    login_status.configure(text="Setup done! Restart app.", text_color="green")

# ---------------- DATA ----------------
def load_data():
    conn = sqlite3.connect(DB_FILE)
    cur = conn.cursor()
    cur.execute("SELECT id, site, username, password FROM vault")
    rows = cur.fetchall()
    conn.close()
    return rows

def save_password():
    site = entry_site.get()
    user = entry_user.get()
    password = entry_pass.get()

    if not (site and user and password):
        status.configure(text="Fill all fields!", text_color="red")
        return

    enc = fernet.encrypt(password.encode()).decode()

    conn = sqlite3.connect(DB_FILE)
    cur = conn.cursor()
    cur.execute("INSERT INTO vault (site, username, password) VALUES (?, ?, ?)",
                (site, user, enc))
    conn.commit()
    conn.close()

    refresh_table()
    status.configure(text="Saved!", text_color="green")

    entry_site.delete(0, "end")
    entry_user.delete(0, "end")
    entry_pass.delete(0, "end")

def refresh_table():
    for row in table.get_children():
        table.delete(row)

    for row in load_data():
        try:
            dec = fernet.decrypt(row[3].encode()).decode()
        except:
            dec = "ERROR"

        table.insert("", "end", iid=row[0], values=(row[1], row[2], dec))

def delete_selected():
    sel = table.focus()

    if not sel:
        status.configure(text="Select a row!", text_color="red")
        return

    conn = sqlite3.connect(DB_FILE)
    cur = conn.cursor()
    cur.execute("DELETE FROM vault WHERE id=?", (sel,))
    conn.commit()
    conn.close()

    refresh_table()
    status.configure(text="Deleted!", text_color="green")

def copy_password():
    sel = table.focus()

    if not sel:
        status.configure(text="Select a row!", text_color="red")
        return

    item = table.item(sel)
    pwd = item["values"][2]

    app.clipboard_clear()
    app.clipboard_append(pwd)

    status.configure(text="Copied!", text_color="green")

def search():
    q = search_entry.get().lower()

    for row in table.get_children():
        table.delete(row)

    for row in load_data():
        if q in row[1].lower():
            try:
                dec = fernet.decrypt(row[3].encode()).decode()
            except:
                dec = "ERROR"

            table.insert("", "end", iid=row[0], values=(row[1], row[2], dec))

# ---------------- MAIN APP ----------------
def main_app():
    global app, entry_site, entry_user, entry_pass, table, status, search_entry

    app = ctk.CTk()
    app.title("Password Manager")
    app.geometry("850x600")

    ctk.CTkLabel(app, text="PASSWORD MANAGER", font=("Arial", 22, "bold")).pack(pady=10)

    entry_site = ctk.CTkEntry(app, placeholder_text="Website")
    entry_site.pack(pady=5)

    entry_user = ctk.CTkEntry(app, placeholder_text="Username")
    entry_user.pack(pady=5)

    entry_pass = ctk.CTkEntry(app, placeholder_text="Password", show="*")
    entry_pass.pack(pady=5)

    ctk.CTkButton(app, text="Save", command=save_password).pack(pady=5)

    search_entry = ctk.CTkEntry(app, placeholder_text="Search")
    search_entry.pack(pady=5)

    ctk.CTkButton(app, text="Search", command=search).pack(pady=5)

    frame = ctk.CTkFrame(app)
    frame.pack(fill="both", expand=True, pady=10)

    table = ttk.Treeview(frame, columns=("Site", "User", "Password"), show="headings")
    table.heading("Site", text="Site")
    table.heading("User", text="User")
    table.heading("Password", text="Password")
    table.pack(fill="both", expand=True)

    btn = ctk.CTkFrame(app)
    btn.pack(pady=10)

    ctk.CTkButton(btn, text="Refresh", command=refresh_table).grid(row=0, column=0, padx=5)
    ctk.CTkButton(btn, text="Delete", command=delete_selected).grid(row=0, column=1, padx=5)
    ctk.CTkButton(btn, text="Copy", command=copy_password).grid(row=0, column=2, padx=5)

    status = ctk.CTkLabel(app, text="")
    status.pack()

    refresh_table()

    app.mainloop()

# ---------------- LOGIN SCREEN ----------------
login_frame = ctk.CTk()
login_frame.title("Login")
login_frame.geometry("350x220")

ctk.CTkLabel(login_frame, text="Enter Master Password").pack(pady=10)

login_entry = ctk.CTkEntry(login_frame, show="*")
login_entry.pack(pady=10)

ctk.CTkButton(login_frame, text="Login", command=login).pack(pady=5)
ctk.CTkButton(login_frame, text="First Time Setup", command=first_time_setup).pack(pady=5)

login_status = ctk.CTkLabel(login_frame, text="")
login_status.pack()
login_frame.mainloop()
