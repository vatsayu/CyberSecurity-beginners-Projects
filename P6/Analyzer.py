import tkinter as tk
from tkinter import ttk, scrolledtext, messagebox, filedialog
from zxcvbn import zxcvbn
import re
import pyperclip                 # pip install pyperclip
import hashlib                   # for saving hashed good passwords
import math                      # for entropy
from collections import Counter  # for entropy

# ────────────────────────────────────────────────
#   Built-in small list of very common/leaked passwords
# ────────────────────────────────────────────────
COMMON_PASSWORDS = {
    "123456", "password", "12345678", "qwerty", "123456789", "12345", "1234",
    "111111", "123123", "abc123", "password1", "iloveyou", "welcome", "admin",
    "letmein", "monkey", "sunshine", "princess", "flower", "superman", "batman",
    "trustno1", "ninja", "123qwe", "zaq1zaq1", "qazwsx", "1q2w3e4r", "passw0rd"
}

# ────────────────────────────────────────────────
#   HISTORY FILE (only hashes are saved)
# ────────────────────────────────────────────────
HISTORY_FILE = "good_passwords_hashed.txt"

def calculate_entropy(password):
    """Manual Shannon entropy calculation in bits"""
    if not password:
        return 0.0
    prob = [float(count) / len(password) for count in Counter(password).values()]
    return -sum(p * math.log2(p) for p in prob if p > 0)

def analyze_password(password):
    if not password:
        return {
            "score": 0,
            "strength": "Empty",
            "color": "gray",
            "crack_time": "Instant",
            "entropy_bits": 0.0,
            "feedback": ["Please enter a password"],
            "details": {}
        }

    # zxcvbn analysis
    z = zxcvbn(password)
    z_score = z["score"]
    z_warning = z["feedback"]["warning"] or ""
    z_suggestions = z["feedback"]["suggestions"]
    crack_time = z["crack_times_display"]["offline_fast_hashing_1e10_per_second"]

    # Custom policy checks
    details = {
        "length_ok": len(password) >= 12,
        "has_upper": bool(re.search(r"[A-Z]", password)),
        "has_lower": bool(re.search(r"[a-z]", password)),
        "has_digit": bool(re.search(r"\d", password)),
        "has_special": bool(re.search(r'[!@#$%^&*()_+\-=\[\]{};:\"\|\'<>,.?/]', password)),
        "no_sequential": not re.search(r"(123|abc|qwe|asd|zxc|password|letmein|qwerty)", password.lower()),
        "no_repeated": not re.search(r"(.)\1{3,}", password),
        "not_common": password.lower() not in COMMON_PASSWORDS
    }

    # Combine scores
    custom_points = sum(details.values()) * (100 / len(details))
    final_score = int((z_score * 25) + (custom_points * 0.3))
    final_score = min(max(final_score, 0), 100)

    # Strength & color
    if final_score >= 90:
        strength, color = "Excellent", "darkgreen"
    elif final_score >= 75:
        strength, color = "Strong", "green"
    elif final_score >= 50:
        strength, color = "Medium", "orange"
    else:
        strength, color = "Weak", "red"

    # Entropy
    entropy_bits = calculate_entropy(password)

    # Feedback
    feedback = []
    if z_warning:
        feedback.append(f"Warning: {z_warning}")
    feedback.extend(z_suggestions)

    if not details["length_ok"]:
        feedback.append("• Use at least 12 characters")
    if not (details["has_upper"] and details["has_lower"]):
        feedback.append("• Mix uppercase and lowercase letters")
    if not details["has_digit"]:
        feedback.append("• Add at least one number")
    if not details["has_special"]:
        feedback.append("• Include special characters (!@#$%^&*)")
    if not details["no_sequential"]:
        feedback.append("• Avoid keyboard patterns (123, abc, qwe...)")
    if not details["no_repeated"]:
        feedback.append("• Avoid repeating the same character many times")
    if not details["not_common"]:
        feedback.append("• This is a very common/leaked password – change it!")

    if not feedback:
        feedback.append("Great password! No major issues detected.")

    return {
        "score": final_score,
        "strength": strength,
        "color": color,
        "crack_time": crack_time,
        "entropy_bits": round(entropy_bits, 2),
        "feedback": feedback,
        "details": details
    }


class PasswordAnalyzerApp:
    def __init__(self, root):
        self.root = root
        self.root.title("Password Policy Analyzer")
        self.root.geometry("820x640")
        self.root.configure(bg="#f5f7fa")
        self.root.resizable(False, False)

        self.dark_mode = False

        # ──────────────────────────────
        #   Theme colors
        # ──────────────────────────────
        self.light_bg = "#f5f7fa"
        self.light_fg = "#2c3e50"
        self.dark_bg  = "#1e1e2e"
        self.dark_fg  = "#cdd6f4"

        self.current_bg = self.light_bg
        self.current_fg = self.light_fg

        # Title
        self.title_label = tk.Label(root, text="Password Strength Analyzer", font=("Segoe UI", 18, "bold"),
                                    bg=self.current_bg, fg=self.current_fg)
        self.title_label.pack(pady=(20, 10))

        # Password entry frame
        frame = tk.Frame(root, bg=self.current_bg)
        frame.pack(pady=10)

        tk.Label(frame, text="Enter Password:", font=("Segoe UI", 11), bg=self.current_bg, fg=self.current_fg).pack(side=tk.LEFT, padx=10)

        self.password_var = tk.StringVar()
        self.entry = tk.Entry(frame, textvariable=self.password_var, width=45,
                              font=("Consolas", 12), show="•")
        self.entry.pack(side=tk.LEFT, padx=5)
        self.entry.focus_set()

        self.show_var = tk.BooleanVar()
        tk.Checkbutton(frame, text="Show", variable=self.show_var, bg=self.current_bg,
                       command=self.toggle_show).pack(side=tk.LEFT)

        # Dark mode toggle
        tk.Button(frame, text="Dark Mode", command=self.toggle_dark_mode,
                  bg="#7f8c8d", fg="white", font=("Segoe UI", 9)).pack(side=tk.LEFT, padx=10)

        # Strength bar
        self.strength_var = tk.DoubleVar(value=0)
        self.strength_bar = ttk.Progressbar(root, orient="horizontal", length=600,
                                            mode="determinate", variable=self.strength_var,
                                            maximum=100)
        self.strength_bar.pack(pady=15)

        self.strength_label = tk.Label(root, text="Strength: —", font=("Segoe UI", 12, "bold"),
                                       bg=self.current_bg, fg=self.current_fg)
        self.strength_label.pack()

        # Result area
        self.result_text = scrolledtext.ScrolledText(root, width=90, height=16,
                                                     font=("Segoe UI", 11), wrap=tk.WORD,
                                                     bg="#ffffff", relief="flat", bd=1)
        self.result_text.pack(pady=15, padx=20, fill="both")

        # Buttons
        btn_frame = tk.Frame(root, bg=self.current_bg)
        btn_frame.pack(pady=10)

        tk.Button(btn_frame, text="Analyze", command=self.analyze_now,
                  bg="#3498db", fg="white", font=("Segoe UI", 11, "bold"),
                  width=15).pack(side=tk.LEFT, padx=10)

        tk.Button(btn_frame, text="Load from file", command=self.load_batch,
                  bg="#9b59b6", fg="white", font=("Segoe UI", 11, "bold"),
                  width=15).pack(side=tk.LEFT, padx=10)

        tk.Button(btn_frame, text="Copy Result", command=self.copy_result,
                  bg="#2ecc71", fg="white", font=("Segoe UI", 11, "bold"),
                  width=15).pack(side=tk.LEFT, padx=10)

        tk.Button(btn_frame, text="Clear", command=self.clear_all,
                  bg="#e74c3c", fg="white", font=("Segoe UI", 11, "bold"),
                  width=15).pack(side=tk.LEFT, padx=10)

        # Real-time update
        self.password_var.trace("w", lambda *args: self.update_strength())

        # Progress bar styles
        style = ttk.Style()
        style.theme_use("clam")
        style.configure("green.Horizontal.TProgressbar", troughcolor="#e0e0e0", background="#2ecc71")
        style.configure("orange.Horizontal.TProgressbar", troughcolor="#e0e0e0", background="#f39c12")
        style.configure("red.Horizontal.TProgressbar", troughcolor="#e0e0e0", background="#e74c3c")

    def toggle_show(self):
        self.entry.config(show="" if self.show_var.get() else "•")

    def toggle_dark_mode(self):
        self.dark_mode = not self.dark_mode
        if self.dark_mode:
            self.current_bg = "#1e1e2e"
            self.current_fg = "#cdd6f4"
            self.result_text.config(bg="#2d2d44", fg="#cdd6f4", insertbackground="white")
        else:
            self.current_bg = "#f5f7fa"
            self.current_fg = "#2c3e50"
            self.result_text.config(bg="#ffffff", fg="#2c3e50", insertbackground="black")

        # Update all widgets
        self.root.configure(bg=self.current_bg)
        self.title_label.config(bg=self.current_bg, fg=self.current_fg)
        self.strength_label.config(bg=self.current_bg, fg=self.current_fg)

        for widget in self.root.winfo_children():
            if isinstance(widget, tk.Frame):
                widget.config(bg=self.current_bg)
                for child in widget.winfo_children():
                    if isinstance(child, tk.Label) or isinstance(child, tk.Checkbutton):
                        child.config(bg=self.current_bg, fg=self.current_fg)

        self.update_strength()  # refresh bar color

    def update_strength(self):
        pwd = self.password_var.get()
        result = analyze_password(pwd)

        self.strength_var.set(result["score"])
        self.strength_label.config(text=f"Strength: {result['strength']} ({result['score']}%) – Entropy: {result['entropy_bits']:.2f} bits",
                                   fg=result["color"])

        # Progress bar color
        if result["score"] >= 75:
            self.strength_bar["style"] = "green.Horizontal.TProgressbar"
        elif result["score"] >= 50:
            self.strength_bar["style"] = "orange.Horizontal.TProgressbar"
        else:
            self.strength_bar["style"] = "red.Horizontal.TProgressbar"

    def analyze_now(self):
        pwd = self.password_var.get().strip()
        if not pwd:
            messagebox.showinfo("Input Required", "Please enter a password first.")
            return

        result = analyze_password(pwd)

        self.result_text.delete(1.0, tk.END)
        self.result_text.insert(tk.END, f"Strength: {result['strength']} ({result['score']}/100)\n")
        self.result_text.insert(tk.END, f"Entropy: {result['entropy_bits']:.2f} bits\n")
        self.result_text.insert(tk.END, f"Estimated crack time (fast attack): {result['crack_time']}\n\n")

        if result["feedback"]:
            self.result_text.insert(tk.END, "Feedback & Recommendations:\n")
            for line in result["feedback"]:
                self.result_text.insert(tk.END, f"  {line}\n")
        else:
            self.result_text.insert(tk.END, "Excellent password — very strong!\n")

        # Offer to save if strong
        if result["score"] >= 80:
            if messagebox.askyesno("Save Password?", "This password is strong. Save hashed version to history?"):
                hashed = hashlib.sha256(pwd.encode()).hexdigest()
                with open(HISTORY_FILE, "a", encoding="utf-8") as f:
                    f.write(f"{hashed}\n")
                messagebox.showinfo("Saved", "Hashed password added to history.")

        self.result_text.see(tk.END)

    def load_batch(self):
        file_path = filedialog.askopenfilename(
            title="Select password list file",
            filetypes=[("Text files", "*.txt"), ("All files", "*.*")]
        )
        if not file_path:
            return

        try:
            with open(file_path, "r", encoding="utf-8") as f:
                passwords = [line.strip() for line in f if line.strip()]

            if not passwords:
                messagebox.showinfo("No Data", "File is empty or contains no passwords.")
                return

            self.result_text.delete(1.0, tk.END)
            self.result_text.insert(tk.END, f"Batch analysis – {len(passwords)} passwords loaded\n\n")

            for i, pwd in enumerate(passwords, 1):
                result = analyze_password(pwd)
                self.result_text.insert(tk.END, f"#{i} | Score: {result['score']} | {result['strength']}\n")
                self.result_text.insert(tk.END, f"    Entropy: {result['entropy_bits']:.2f} bits | Crack time: {result['crack_time']}\n")
                if result["feedback"]:
                    self.result_text.insert(tk.END, "    Feedback:\n")
                    for line in result["feedback"]:
                        self.result_text.insert(tk.END, f"      {line}\n")
                self.result_text.insert(tk.END, "-"*70 + "\n")

            self.result_text.see(tk.END)
            messagebox.showinfo("Batch Complete", f"Analyzed {len(passwords)} passwords.")
        except Exception as e:
            messagebox.showerror("Error", f"Failed to read file:\n{str(e)}")

    def copy_result(self):
        text = self.result_text.get(1.0, tk.END).strip()
        if text:
            pyperclip.copy(text)
            messagebox.showinfo("Copied", "Result copied to clipboard!")
        else:
            messagebox.showinfo("Nothing to copy", "No result to copy yet.")

    def clear_all(self):
        self.password_var.set("")
        self.result_text.delete(1.0, tk.END)
        self.strength_var.set(0)
        self.strength_label.config(text="Strength: —", fg="gray")


if __name__ == "__main__":
    root = tk.Tk()
    app = PasswordAnalyzerApp(root)
    root.mainloop()