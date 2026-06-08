import os
import json
import base64
import sqlite3
import webbrowser
import secrets
import hashlib
from cryptography.hazmat.primitives.ciphers import Cipher, algorithms, modes
from cryptography.hazmat.primitives.kdf.pbkdf2 import PBKDF2
from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.backends import default_backend
import tkinter as tk
from tkinter import ttk, messagebox, simpledialog
import threading
import time

class SecurePasswordVault:
    def __init__(self):
        self.app_data = os.path.join(os.environ['APPDATA'], 'SecureVault')
        os.makedirs(self.app_data, exist_ok=True)
        self.db_path = os.path.join(self.app_data, 'vault.db')
        self.master_key = None
        self.init_database()
    
    def init_database(self):
        conn = sqlite3.connect(self.db_path)
        cursor = conn.cursor()
        cursor.execute('''
            CREATE TABLE IF NOT EXISTS credentials (
                id INTEGER PRIMARY KEY AUTOINCREMENT,
                name TEXT NOT NULL,
                url TEXT NOT NULL,
                username TEXT NOT NULL,
                password TEXT NOT NULL,
                created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP
            )
        ''')
        cursor.execute('''
            CREATE TABLE IF NOT EXISTS config (
                key TEXT PRIMARY KEY,
                salt TEXT NOT NULL
            )
        ''')
        conn.commit()
        conn.close()
    
    def derive_key(self, master_password, salt):
        kdf = PBKDF2(
            algorithm=hashes.SHA256(),
            length=32,
            salt=salt,
            iterations=100000,
            backend=default_backend()
        )
        return kdf.derive(master_password.encode())
    
    def encrypt(self, data):
        iv = secrets.token_bytes(12)
        cipher = Cipher(algorithms.AES(self.master_key), modes.GCM(iv), backend=default_backend())
        encryptor = cipher.encryptor()
        encrypted = encryptor.update(data.encode()) + encryptor.finalize()
        return base64.b64encode(iv + encryptor.tag + encrypted).decode()
    
    def decrypt(self, encrypted_data):
        raw = base64.b64decode(encrypted_data)
        iv = raw[:12]
        tag = raw[12:28]
        ciphertext = raw[28:]
        cipher = Cipher(algorithms.AES(self.master_key), modes.GCM(iv, tag), backend=default_backend())
        decryptor = cipher.decryptor()
        decrypted = decryptor.update(ciphertext) + decryptor.finalize()
        return decrypted.decode()
    
    def setup_master_password(self):
        conn = sqlite3.connect(self.db_path)
        cursor = conn.cursor()
        cursor.execute("SELECT salt FROM config WHERE key='master_salt'")
        result = cursor.fetchone()
        conn.close()
        
        if not result:
            master_pw = simpledialog.askstring("Setup", "CREATE MASTER PASSWORD:", show='*')
            if not master_pw:
                return False
            confirm = simpledialog.askstring("Setup", "CONFIRM MASTER PASSWORD:", show='*')
            if master_pw != confirm:
                messagebox.showerror("Error", "Passwords don't match")
                return False
            
            salt = secrets.token_bytes(32)
            self.master_key = self.derive_key(master_pw, salt)
            
            conn = sqlite3.connect(self.db_path)
            cursor = conn.cursor()
            cursor.execute("INSERT INTO config (key, salt) VALUES (?, ?)", 
                          ('master_salt', base64.b64encode(salt).decode()))
            conn.commit()
            conn.close()
            return True
        else:
            salt = base64.b64decode(result[0])
            master_pw = simpledialog.askstring("Login", "ENTER MASTER PASSWORD:", show='*')
            if master_pw:
                self.master_key = self.derive_key(master_pw, salt)
                return True
        return False
    
    def add_credential(self, name, url, username, password):
        conn = sqlite3.connect(self.db_path)
        cursor = conn.cursor()
        encrypted_username = self.encrypt(username)
        encrypted_password = self.encrypt(password)
        cursor.execute("INSERT INTO credentials (name, url, username, password) VALUES (?, ?, ?, ?)",
                      (name, url, encrypted_username, encrypted_password))
        conn.commit()
        conn.close()
    
    def get_credentials(self):
        conn = sqlite3.connect(self.db_path)
        cursor = conn.cursor()
        cursor.execute("SELECT id, name, url, username, password FROM credentials")
        creds = cursor.fetchall()
        conn.close()
        
        decrypted = []
        for cred in creds:
            try:
                decrypted.append({
                    'id': cred[0],
                    'name': cred[1],
                    'url': cred[2],
                    'username': self.decrypt(cred[3]),
                    'password': self.decrypt(cred[4])
                })
            except:
                continue
        return decrypted
    
    def delete_credential(self, cred_id):
        conn = sqlite3.connect(self.db_path)
        cursor = conn.cursor()
        cursor.execute("DELETE FROM credentials WHERE id=?", (cred_id,))
        conn.commit()
        conn.close()
    
    def launch_and_login(self, url, username, password):
        self.clipboard_clear()
        self.clipboard_append(username)
        messagebox.showinfo("Info", f"✓ Username copied!\n\nOpening: {url}\n\nPaste username, then password will auto-copy")
        webbrowser.open(url)
        
        def copy_password():
            time.sleep(3)
            self.clipboard_clear()
            self.clipboard_append(password)
            messagebox.showinfo("Info", "✓ Password copied to clipboard!")
        
        threading.Thread(target=copy_password, daemon=True).start()

class VaultGUI:
    def __init__(self, vault):
        self.vault = vault
        self.root = tk.Tk()
        self.root.title("Secure Password Vault")
        self.root.geometry("900x600")
        
        style = ttk.Style()
        style.theme_use('clam')
        
        self.setup_ui()
        self.refresh_list()
    
    def setup_ui(self):
        toolbar = ttk.Frame(self.root)
        toolbar.pack(side=tk.TOP, fill=tk.X, padx=5, pady=5)
        
        ttk.Button(toolbar, text="➕ ADD NEW", command=self.add_dialog).pack(side=tk.LEFT, padx=2)
        ttk.Button(toolbar, text="❌ DELETE", command=self.delete_selected).pack(side=tk.LEFT, padx=2)
        ttk.Button(toolbar, text="🚀 LAUNCH & LOGIN", command=self.launch_selected).pack(side=tk.LEFT, padx=2)
        ttk.Button(toolbar, text="🔄 REFRESH", command=self.refresh_list).pack(side=tk.LEFT, padx=2)
        
        columns = ('Name', 'URL', 'Username')
        self.tree = ttk.Treeview(self.root, columns=columns, show='headings', height=25)
        
        for col in columns:
            self.tree.heading(col, text=col)
            self.tree.column(col, width=280)
        
        scrollbar = ttk.Scrollbar(self.root, orient=tk.VERTICAL, command=self.tree.yview)
        self.tree.configure(yscrollcommand=scrollbar.set)
        
        self.tree.pack(side=tk.LEFT, fill=tk.BOTH, expand=True, padx=5, pady=5)
        scrollbar.pack(side=tk.RIGHT, fill=tk.Y, pady=5)
        
        self.status = ttk.Label(self.root, text="Ready", relief=tk.SUNKEN)
        self.status.pack(side=tk.BOTTOM, fill=tk.X)
    
    def add_dialog(self):
        dialog = tk.Toplevel(self.root)
        dialog.title("Add New Credential")
        dialog.geometry("450x350")
        
        ttk.Label(dialog, text="NAME (e.g., Gmail):", font=('Arial', 10, 'bold')).pack(pady=5)
        name_entry = ttk.Entry(dialog, width=50)
        name_entry.pack(pady=5)
        
        ttk.Label(dialog, text="WEBSITE URL:", font=('Arial', 10, 'bold')).pack(pady=5)
        url_entry = ttk.Entry(dialog, width=50)
        url_entry.pack(pady=5)
        
        ttk.Label(dialog, text="USERNAME/EMAIL:", font=('Arial', 10, 'bold')).pack(pady=5)
        username_entry = ttk.Entry(dialog, width=50)
        username_entry.pack(pady=5)
        
        ttk.Label(dialog, text="PASSWORD:", font=('Arial', 10, 'bold')).pack(pady=5)
        password_entry = ttk.Entry(dialog, width=50, show='*')
        password_entry.pack(pady=5)
        
        def save():
            if all([name_entry.get(), url_entry.get(), username_entry.get(), password_entry.get()]):
                self.vault.add_credential(
                    name_entry.get(),
                    url_entry.get(),
                    username_entry.get(),
                    password_entry.get()
                )
                dialog.destroy()
                self.refresh_list()
                self.status.config(text="✓ Credential added successfully")
            else:
                messagebox.showerror("Error", "All fields are required!")
        
        ttk.Button(dialog, text="SAVE", command=save).pack(pady=20)
    
    def refresh_list(self):
        for item in self.tree.get_children():
            self.tree.delete(item)
        
        self.credentials = self.vault.get_credentials()
        for cred in self.credentials:
            self.tree.insert('', tk.END, values=(cred['name'], cred['url'], cred['username']), iid=cred['id'])
        
        self.status.config(text=f"✓ Loaded {len(self.credentials)} credentials")
    
    def delete_selected(self):
        selected = self.tree.selection()
        if selected:
            if messagebox.askyesno("Confirm", "Delete this credential?"):
                self.vault.delete_credential(int(selected[0]))
                self.refresh_list()
                self.status.config(text="✓ Credential deleted")
    
    def launch_selected(self):
        selected = self.tree.selection()
        if selected:
            cred_id = int(selected[0])
            cred = next((c for c in self.credentials if c['id'] == cred_id), None)
            if cred:
                self.vault.launch_and_login(cred['url'], cred['username'], cred['password'])
    
    def run(self):
        self.root.mainloop()

def main():
    vault = SecurePasswordVault()
    if vault.setup_master_password():
        app = VaultGUI(vault)
        app.run()
    else:
        messagebox.showerror("Error", "Authentication failed")

if __name__ == "__main__":
    main()
