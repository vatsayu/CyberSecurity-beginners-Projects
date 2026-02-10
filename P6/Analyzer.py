import tkinter as tk
from tkinter import ttk, scrolledtext, messagebox
from zxcvbn import zxcvbn
import re
import pyperclip  # pip install pyperclip (optional - for copy to clipboard)

# ────────────────────────────────────────────────
#   Built-in small list of very common/leaked passwords
#   In real projects you can load a larger file (SecLists top-10000.txt etc.)
# ────────────────────────────────────────────────
COMMON_PASSWORDS = {
    "123456", "password", "12345678", "qwerty", "123456789", "12345", "1234",
    "111111", "123123", "abc123", "password1", "iloveyou", "welcome", "admin",
    "letmein", "monkey", "sunshine", "princess", "flower", "superman", "batman",
    "trustno1", "ninja", "123qwe", "zaq1zaq1", "qazwsx", "1q2w3e4r", "passw0rd"
}

def analyze_password(password):
    if not password:
        return {
            "score": 0,
            "strength": "Empty",
            "color": "gray",
            "crack_time": "Instant",
            "feedback": ["Please enter a password"],
            "details": {}
        }

    # zxcvbn analysis (very good at detecting patterns & real strength)
    z = zxcvbn(password)
    z_score = z["score"]           # 0–4
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
        "no_repeated": not re.search(r"(.)\1{3,}", password),  # 4+ same chars
        "not_common": password.lower() not in COMMON_PASSWORDS
    }

    # Combine scores (zxcvbn 0–4 → 0–100, plus custom bonuses)
    custom_points = sum(details.values()) * (100 / len(details))
    final_score = int((z_score * 25) + (custom_points * 0.3))  # weighted
    final_score = min(max(final_score, 0), 100)

    # Strength label & color
    if final_score >= 90:
        strength = "Excellent"
        color = "darkgreen"
    elif final_score >= 75:
        strength = "Strong"
        color = "green"
    elif final_score >= 50:
        strength = "Medium"
        color = "orange"
    else:
        strength = "Weak"
        color = "red"

    # Build feedback messages
    feedback = []
    if z_warning:
        feedback.append(f"Warning: {z_warning}")
    feedback.extend(z_suggestions)

    # Custom feedback
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
        "feedback": feedback,
        "details": details
    }


class PasswordAnalyzerApp:
    def __init__(self, root):
        self.root = root
        self.root.title("Password Policy Analyzer")
        self.root.geometry("780x580")
        self.root.configure(bg="#f5f7fa")
        self.root.resizable(False, False)

        # Title
        tk.Label(root, text="Password Strength Analyzer", font=("Segoe UI", 18, "bold"),
                 bg="#f5f7fa", fg="#2c3e50").pack(pady=(20, 10))

        # Password entry frame
        frame = tk.Frame(root, bg="#f5f7fa")
        frame.pack(pady=10)

        tk.Label(frame, text="Enter Password:", font=("Segoe UI", 11), bg="#f5f7fa").pack(side=tk.LEFT, padx=10)

        self.password_var = tk.StringVar()
        self.entry = tk.Entry(frame, textvariable=self.password_var, width=40,
                              font=("Consolas", 12), show="•")
        self.entry.pack(side=tk.LEFT, padx=5)
        self.entry.focus_set()

        self.show_var = tk.BooleanVar()
        tk.Checkbutton(frame, text="Show", variable=self.show_var, bg="#f5f7fa",
                       command=self.toggle_show).pack(side=tk.LEFT)

        # Strength bar
        self.strength_var = tk.DoubleVar(value=0)
        self.strength_bar = ttk.Progressbar(root, orient="horizontal", length=500,
                                            mode="determinate", variable=self.strength_var,
                                            maximum=100, style="green.Horizontal.TProgressbar")
        self.strength_bar.pack(pady=15)

        self.strength_label = tk.Label(root, text="Strength: —", font=("Segoe UI", 12, "bold"),
                                       bg="#f5f7fa", fg="gray")
        self.strength_label.pack()

        # Result area
        self.result_text = scrolledtext.ScrolledText(root, width=80, height=14,
                                                     font=("Segoe UI", 11), wrap=tk.WORD,
                                                     bg="#ffffff", relief="flat", bd=1)
        self.result_text.pack(pady=15, padx=20, fill="both", expand=False)

        # Buttons
        btn_frame = tk.Frame(root, bg="#f5f7fa")
        btn_frame.pack(pady=10)

        tk.Button(btn_frame, text="Analyze", command=self.analyze_now,
                  bg="#3498db", fg="white", font=("Segoe UI", 11, "bold"),
                  width=15).pack(side=tk.LEFT, padx=10)

        tk.Button(btn_frame, text="Copy Result", command=self.copy_result,
                  bg="#2ecc71", fg="white", font=("Segoe UI", 11, "bold"),
                  width=15).pack(side=tk.LEFT, padx=10)

        tk.Button(btn_frame, text="Clear", command=self.clear_all,
                  bg="#e74c3c", fg="white", font=("Segoe UI", 11, "bold"),
                  width=15).pack(side=tk.LEFT, padx=10)

        # Bind real-time update
        self.password_var.trace("w", lambda *args: self.update_strength())

        # Initial style for progress bar
        style = ttk.Style()
        style.theme_use("clam")
        style.configure("green.Horizontal.TProgressbar", troughcolor="#e0e0e0", background="#2ecc71")
        style.configure("orange.Horizontal.TProgressbar", troughcolor="#e0e0e0", background="#f39c12")
        style.configure("red.Horizontal.TProgressbar", troughcolor="#e0e0e0", background="#e74c3c")

    def toggle_show(self):
        self.entry.config(show="" if self.show_var.get() else "•")

    def update_strength(self):
        pwd = self.password_var.get()
        result = analyze_password(pwd)

        self.strength_var.set(result["score"])
        self.strength_label.config(text=f"Strength: {result['strength']} ({result['score']}%)",
                                   fg=result["color"])

        # Change progress bar color dynamically
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
        self.result_text.insert(tk.END, f"Estimated crack time (fast attack): {result['crack_time']}\n\n")

        if result["feedback"]:
            self.result_text.insert(tk.END, "Feedback & Recommendations:\n")
            for line in result["feedback"]:
                self.result_text.insert(tk.END, f"  {line}\n")
        else:
            self.result_text.insert(tk.END, "Excellent password — very strong!\n")

        self.result_text.see(tk.END)

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