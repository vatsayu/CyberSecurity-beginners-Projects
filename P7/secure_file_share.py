import tkinter as tk
from tkinter import filedialog, messagebox, scrolledtext, ttk
from cryptography.fernet import Fernet, InvalidToken
import base64
import os
import time
import hashlib
from tqdm import tqdm   # optional - remove if you don't want it

class SecureFileShareApp:
    def __init__(self, root):
        self.root = root
        self.root.title("Secure File Share System – P5")
        self.root.geometry("780x620")
        self.root.configure(bg="#f8f9fa")

        self.key = None
        self.current_file = None

        self.create_widgets()

    def create_widgets(self):
        # Title
        tk.Label(self.root, text="Secure File Share System", font=("Segoe UI", 16, "bold"),
                 bg="#f8f9fa", fg="#2c3e50").pack(pady=15)

        # Key frame
        key_frame = tk.Frame(self.root, bg="#f8f9fa")
        key_frame.pack(pady=10, fill="x", padx=20)

        tk.Label(key_frame, text="Encryption Key:", font=("Segoe UI", 10),
                 bg="#f8f9fa").pack(side=tk.LEFT)

        self.key_entry = tk.Entry(key_frame, width=70, font=("Consolas", 11))
        self.key_entry.pack(side=tk.LEFT, padx=10, fill="x", expand=True)

        tk.Button(key_frame, text="Generate Key", command=self.generate_key,
                  bg="#3498db", fg="white", width=15).pack(side=tk.RIGHT)

        # File selection
        file_frame = tk.Frame(self.root, bg="#f8f9fa")
        file_frame.pack(pady=10, fill="x", padx=20)

        tk.Button(file_frame, text="Select File to Encrypt/Decrypt", command=self.select_file,
                  bg="#2ecc71", fg="white", font=("Segoe UI", 11), width=30).pack(pady=5)

        self.file_label = tk.Label(file_frame, text="No file selected", font=("Segoe UI", 10),
                                   bg="#f8f9fa", fg="#7f8c8d", wraplength=700)
        self.file_label.pack(pady=5)

        # Action buttons
        action_frame = tk.Frame(self.root, bg="#f8f9fa")
        action_frame.pack(pady=15)

        tk.Button(action_frame, text="Encrypt File", command=self.encrypt_file,
                  bg="#e67e22", fg="white", font=("Segoe UI", 11, "bold"), width=18).pack(side=tk.LEFT, padx=10)

        tk.Button(action_frame, text="Decrypt File", command=self.decrypt_file,
                  bg="#27ae60", fg="white", font=("Segoe UI", 11, "bold"), width=18).pack(side=tk.LEFT, padx=10)

        tk.Button(action_frame, text="Copy Key to Clipboard", command=self.copy_key,
                  bg="#9b59b6", fg="white", font=("Segoe UI", 11, "bold"), width=22).pack(side=tk.LEFT, padx=10)

        # Output log
        self.log_text = scrolledtext.ScrolledText(self.root, height=12, font=("Consolas", 10),
                                                  bg="#2c3e50", fg="#ecf0f1", wrap=tk.WORD)
        self.log_text.pack(pady=10, padx=20, fill="both", expand=True)

        # Progress
        self.progress = ttk.Progressbar(self.root, orient="horizontal", length=700, mode="determinate")
        self.progress.pack(pady=5)
        self.progress.pack_forget()

        self.log("Welcome to Secure File Share System")
        self.log("→ Generate or paste a key, select a file, then encrypt/decrypt.")
        self.log("→ Never send the key together with the encrypted file!")

    def log(self, message, error=False):
        tag = "error" if error else "info"
        self.log_text.insert(tk.END, f"[{time.strftime('%H:%M:%S')}] {message}\n", tag)
        self.log_text.see(tk.END)

    def generate_key(self):
        self.key = Fernet.generate_key()
        self.key_entry.delete(0, tk.END)
        self.key_entry.insert(0, self.key.decode())
        self.log("New Fernet key generated and inserted.")
        self.log("Copy and save it securely — you will need it to decrypt!")

    def select_file(self):
        path = filedialog.askopenfilename(title="Select File")
        if path:
            self.current_file = path
            self.file_label.config(text=os.path.basename(path))
            self.log(f"Selected file: {os.path.basename(path)} ({os.path.getsize(path):,} bytes)")

    def copy_key(self):
        key_text = self.key_entry.get().strip()
        if key_text:
            self.root.clipboard_clear()
            self.root.clipboard_append(key_text)
            self.log("Key copied to clipboard.")
        else:
            messagebox.showwarning("No Key", "Generate or paste a key first.")

    def encrypt_file(self):
        if not self.current_file:
            messagebox.showwarning("No File", "Select a file first.")
            return

        key_str = self.key_entry.get().strip()
        if not key_str:
            messagebox.showwarning("No Key", "Generate or paste a key first.")
            return

        try:
            key = key_str.encode()
            fernet = Fernet(key)
        except Exception as e:
            messagebox.showerror("Invalid Key", f"Key format error:\n{str(e)}")
            return

        out_path = self.current_file + ".enc"
        self.progress.pack(pady=5)
        self.progress["value"] = 0
        self.root.update()

        try:
            file_size = os.path.getsize(self.current_file)
            chunk_size = 1024 * 1024  # 1 MB chunks

            with open(self.current_file, "rb") as f_in:
                with open(out_path, "wb") as f_out:
                    processed = 0
                    while True:
                        chunk = f_in.read(chunk_size)
                        if not chunk:
                            break
                        encrypted_chunk = fernet.encrypt(chunk)
                        f_out.write(encrypted_chunk)
                        processed += len(chunk)
                        self.progress["value"] = (processed / file_size) * 100
                        self.root.update()

            self.progress.pack_forget()

            # Verify hash
            orig_hash = self.file_hash(self.current_file)
            enc_hash = self.file_hash(out_path)

            self.log(f"Encryption successful → {out_path}")
            self.log(f"Original SHA-256: {orig_hash[:16]}...")
            self.log(f"Encrypted SHA-256: {enc_hash[:16]}...")
            self.log("Remember: Send .enc file and key SEPARATELY!")

        except Exception as e:
            self.progress.pack_forget()
            messagebox.showerror("Encryption Error", str(e))
            self.log(f"Encryption failed: {str(e)}", error=True)

    def decrypt_file(self):
        if not self.current_file or not self.current_file.endswith(".enc"):
            messagebox.showwarning("Invalid File", "Select a .enc file first.")
            return

        key_str = self.key_entry.get().strip()
        if not key_str:
            messagebox.showwarning("No Key", "Paste the key first.")
            return

        try:
            key = key_str.encode()
            fernet = Fernet(key)
        except Exception as e:
            messagebox.showerror("Invalid Key", f"Key format error:\n{str(e)}")
            return

        out_path = self.current_file[:-4]  # remove .enc
        self.progress.pack(pady=5)
        self.progress["value"] = 0
        self.root.update()

        try:
            file_size = os.path.getsize(self.current_file)
            chunk_size = 1024 * 1024 + 64  # Fernet overhead ~64 bytes

            with open(self.current_file, "rb") as f_in:
                with open(out_path, "wb") as f_out:
                    processed = 0
                    while True:
                        chunk = f_in.read(chunk_size)
                        if not chunk:
                            break
                        try:
                            decrypted_chunk = fernet.decrypt(chunk)
                        except InvalidToken:
                            raise ValueError("Wrong key or corrupted file")
                        f_out.write(decrypted_chunk)
                        processed += len(chunk)
                        self.progress["value"] = (processed / file_size) * 100
                        self.root.update()

            self.progress.pack_forget()

            self.log(f"Decryption successful → {out_path}")
            messagebox.showinfo("Success", f"File decrypted to:\n{out_path}")

        except InvalidToken:
            self.progress.pack_forget()
            messagebox.showerror("Decryption Failed", "Wrong key or corrupted encrypted file.")
            self.log("Decryption failed: Invalid key or corrupted data", error=True)
        except Exception as e:
            self.progress.pack_forget()
            messagebox.showerror("Decryption Error", str(e))
            self.log(f"Decryption failed: {str(e)}", error=True)

    def file_hash(self, filepath):
        sha256 = hashlib.sha256()
        with open(filepath, "rb") as f:
            for chunk in iter(lambda: f.read(4096), b""):
                sha256.update(chunk)
        return sha256.hexdigest()


if __name__ == "__main__":
    root = tk.Tk()
    app = SecureFileShareApp(root)
    root.mainloop()