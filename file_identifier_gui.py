import magic
import os
import csv
import tkinter as tk
from tkinter import filedialog, scrolledtext, messagebox, ttk
from PIL import Image, ImageTk
import time
import threading

# ────────────────────────────────────────────────
#                Core Functions (unchanged)
# ────────────────────────────────────────────────
def identify_file_type(file_path):
    if not os.path.exists(file_path):
        return "Error: File not found.", "error"
    if not os.access(file_path, os.R_OK):
        return "Error: Permission denied.", "error"
    
    ext = os.path.splitext(file_path)[1].lower().lstrip('.')
    
    # Basic magic number signatures (expand as needed)
    signatures = {
        b'\xff\xd8\xff':                    ('image/jpeg',       'JPEG image'),
        b'\x89PNG\r\n\x1a\n':               ('image/png',        'PNG image'),
        b'GIF87a':                          ('image/gif',        'GIF image'),
        b'GIF89a':                          ('image/gif',        'GIF image'),
        b'%PDF-':                           ('application/pdf',  'PDF document'),
        b'PK\x03\x04':                      ('application/zip',  'ZIP archive'),
        b'MZ':                              ('application/x-msdownload', 'Windows executable (EXE)'),
        b'BM':                              ('image/bmp',        'BMP image'),
        b'RIFF':                            ('audio/x-wav',      'WAV audio'),   # first 4 bytes
        b'ID3':                             ('audio/mpeg',       'MP3 audio'),
    }
    
    try:
        with open(file_path, 'rb') as f:
            header = f.read(16)  # enough for most signatures
        
        detected_mime = "application/octet-stream"  # unknown fallback
        detected_desc = "Unknown / binary data"
        
        for sig, (mime, desc) in signatures.items():
            if header.startswith(sig):
                detected_mime = mime
                detected_desc = desc
                break
        
        match_text = "Yes" if ext and ext in detected_mime else "No"
        result = f"Type: {detected_mime} | Description: {detected_desc} | Ext match: {match_text}"
        tag = "match" if match_text == "Yes" else "mismatch"
        return result, tag
    
    except Exception as e:
        return f"Error reading file: {str(e)}", "error"


def scan_directory(directory, progress_callback=None):
    total_files = sum(len(files) for _, _, files in os.walk(directory))
    if total_files == 0:
        return {}
    
    results = {}
    processed = 0
    
    for root_dir, _, files in os.walk(directory):
        for file in files:
            file_path = os.path.join(root_dir, file)
            result, tag = identify_file_type(file_path)
            results[file_path] = (result, tag)
            processed += 1
            if progress_callback:
                progress_callback(total_files, processed)
    return results


# ────────────────────────────────────────────────
#                GUI Logic
# ────────────────────────────────────────────────

class HackerGUI:
    def __init__(self, root):
        self.root = root
        self.root.title("FILE TYPE IDENTIFIER v3.1 - CYBER FORENSICS")
        self.root.geometry("900x650")
        self.root.configure(bg="#0a0f0a")
        self.root.resizable(True, True)
        
        # Global photo ref
        self.current_photo = None
        
        self.create_welcome_screen()
        
    def create_welcome_screen(self):
        self.welcome_frame = tk.Frame(self.root, bg="#0a0f0a")
        self.welcome_frame.pack(expand=True, fill="both")
        
        self.welcome_text = tk.Text(
            self.welcome_frame, bg="#0a0f0a", fg="#00ff41",
            font=("Courier New", 16, "bold"), insertbackground="#00ff41",
            borderwidth=0, highlightthickness=0
        )
        self.welcome_text.pack(expand=True, pady=60)
        
        self.blink_label = tk.Label(
            self.welcome_frame, text="PRESS ENTER TO CONTINUE...",
            bg="#0a0f0a", fg="#00ff41", font=("Courier New", 12)
        )
        self.blink_label.pack(pady=20)
        
        # Blinking cursor effect
        self.blinking = True
        self.blink()
        
        self.root.bind("<Return>", self.enter_pressed)
        
        # Type welcome message
        welcome_msg = """
        ╔════════════════════════════════════════════════════╗
        ║       FILE TYPE IDENTIFIER - HACKER EDITION        ║
        ║                                                    ║
        ║   Detect real file signatures • Ignore extensions  ║
        ║   Built for digital forensics & red-team tooling   ║
        ║                                                    ║
        ╚════════════════════════════════════════════════════╝
        
              ACCESS GRANTED • 02.06.2026 • SYS_STATUS: ONLINE
        """
        self.typewriter_effect(welcome_msg)
    
    def typewriter_effect(self, text, delay=0.03):
        def type():
            for char in text:
                self.welcome_text.insert(tk.END, char)
                self.welcome_text.see(tk.END)
                self.root.update()
                time.sleep(delay)
        threading.Thread(target=type, daemon=True).start()
    
    def blink(self):
        if self.blinking:
            fg = self.blink_label.cget("fg")
            self.blink_label.config(fg="#003300" if fg == "#00ff41" else "#00ff41")
            self.root.after(600, self.blink)
    
    def enter_pressed(self, event):
        self.blinking = False
        self.welcome_frame.destroy()
        self.create_main_interface()
    
    def create_main_interface(self):
        # Header
        header = tk.Label(self.root, text="FILE TYPE IDENTIFIER v3.1", 
                         bg="#0a0f0a", fg="#00ff9d", font=("Courier New", 18, "bold"))
        header.pack(pady=10)
        
        # Menu buttons (green hacker style)
        menu_frame = tk.Frame(self.root, bg="#0a0f0a")
        menu_frame.pack(pady=10)
        
        options = [
            ("[1] ANALYZE SINGLE FILE", self.select_file),
            ("[2] SCAN DIRECTORY", self.select_directory),
            ("[3] SAVE LAST REPORT", self.save_report),
            ("[4] CLEAR CONSOLE", self.clear_output),
            ("[5] ABOUT / HELP", self.show_about),
            ("[Q] QUIT", self.root.quit)
        ]
        
        for text, cmd in options:
            btn = tk.Button(menu_frame, text=text, command=cmd,
                           bg="#0a1a0a", fg="#00ff41", activebackground="#003300",
                           activeforeground="#00ff9d", font=("Courier New", 12, "bold"),
                           width=30, relief="flat", borderwidth=2, highlightthickness=1,
                           highlightbackground="#00ff41")
            btn.pack(pady=6)
        
        # Output console
        self.output_text = scrolledtext.ScrolledText(
            self.root, bg="#000800", fg="#00ff41", insertbackground="#00ff41",
            font=("Courier New", 11), wrap=tk.WORD, height=20
        )
        self.output_text.pack(padx=20, pady=10, fill=tk.BOTH, expand=True)
        
        # Progress
        self.progress = ttk.Progressbar(self.root, orient="horizontal", mode="determinate")
        self.progress.pack(pady=5, padx=20, fill=tk.X)
        self.progress.pack_forget()
        
        self.progress_label = tk.Label(self.root, text="", bg="#0a0f0a", fg="#00ff9d",
                                      font=("Courier New", 10))
        self.progress_label.pack(pady=2)
        self.progress_label.pack_forget()
        
        # Thumbnail
        self.thumbnail_label = tk.Label(self.root, bg="#0a0f0a")
        self.thumbnail_label.pack(pady=10)
        
        # Tags
        self.output_text.tag_config("match", foreground="#00ff9d")
        self.output_text.tag_config("mismatch", foreground="#ffaa00")
        self.output_text.tag_config("error", foreground="#ff4444")
        
        self.output_text.insert(tk.END, "> Welcome, operator. Select mission...\n\n")
    
    def log(self, msg, tag=""):
        self.output_text.insert(tk.END, msg + "\n", tag)
        self.output_text.see(tk.END)
    
    def select_file(self):
        path = filedialog.askopenfilename(title="SELECT TARGET FILE")
        if not path:
            return
        self.log(f"[+] Analyzing: {path}")
        result, tag = identify_file_type(path)
        self.log(f"    → {result}\n", tag)
        self.show_thumbnail(path)
    
    def select_directory(self):
        dir_path = filedialog.askdirectory(title="SELECT TARGET DIRECTORY")
        if not dir_path:
            return
        
        self.log(f"[+] Scanning directory: {dir_path}")
        self.progress.pack(pady=5, padx=20, fill=tk.X)
        self.progress_label.pack(pady=2)
        self.progress['value'] = 0
        
        def update_prog(total, current):
            self.progress['value'] = (current / total) * 100
            self.progress_label.config(text=f" {current}/{total} files processed...")
            self.root.update()
        
        results = scan_directory(dir_path, update_prog)
        
        for path, (res, tag) in results.items():
            self.log(f"    {path.split(os.sep)[-1]} → {res}", tag)
        
        self.log("\n[+] Scan complete.\n")
        self.progress.pack_forget()
        self.progress_label.pack_forget()
    
    def show_thumbnail(self, path):
        try:
            if os.path.splitext(path)[1].lower() not in ['.jpg','.jpeg','.png','.gif','.bmp','.webp']:
                self.thumbnail_label.config(image='', text="")
                return
            img = Image.open(path)
            img.thumbnail((220, 220))
            self.current_photo = ImageTk.PhotoImage(img)
            self.thumbnail_label.config(image=self.current_photo, text="")
        except:
            self.thumbnail_label.config(image='', text="[preview failed]")
    
    def save_report(self):
        content = self.output_text.get(1.0, tk.END).strip()
        if not content:
            messagebox.showinfo("NO DATA", "Nothing to save.")
            return
        # same save logic as before...
        file_path = filedialog.asksaveasfilename(
            defaultextension=".txt",
            filetypes=[("Text", "*.txt"), ("CSV", "*.csv")],
            title="SAVE LOG AS"
        )
        if not file_path:
            return
        try:
            if file_path.endswith(".csv"):
                # simplified csv export
                with open(file_path, 'w', encoding='utf-8', newline='') as f:
                    writer = csv.writer(f)
                    writer.writerow(["Content"])
                    for line in content.splitlines():
                        writer.writerow([line])
            else:
                with open(file_path, 'w', encoding='utf-8') as f:
                    f.write(content)
            self.log(f"[+] Report saved → {file_path}")
        except Exception as e:
            self.log(f"[-] Save failed: {e}", "error")
    
    def clear_output(self):
        self.output_text.delete(1.0, tk.END)
        self.thumbnail_label.config(image='', text="")
        self.log("> Console cleared.\n")
    
    def show_about(self):
        about = """
FILE TYPE IDENTIFIER v3.1 - HACKER GUI EDITION
Powered by python-magic + Tkinter
Created for digital forensics training & red-team exercises

Features:
 • Signature-based file type detection
 • Directory recursive scanning
 • Progress tracking
 • Image thumbnail preview
 • Green matrix-style interface

Use responsibly. Know your target. Stay stealthy.
"""
        messagebox.showinfo("ABOUT THIS TOOL", about)


if __name__ == "__main__":
    root = tk.Tk()
    app = HackerGUI(root)
    root.mainloop()