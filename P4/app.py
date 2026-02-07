import tkinter as tk
from tkinter import scrolledtext, messagebox, ttk
import random

# ────────────────────────────────────────────────
#   EDUCATIONAL PHISHING AWARENESS SIMULATOR
#   For training purposes only - NEVER use maliciously
# ────────────────────────────────────────────────

EMAIL_TEMPLATES = [
    # Legitimate
    {
        "type": "legit",
        "sender": "no-reply@netflix.com",
        "subject": "Your monthly subscription update",
        "body": """Hello,

Your Netflix plan remains active. Next billing: March 10, 2026 ($15.99).

Watch anywhere, cancel anytime.

Netflix Team""",
        "red_flags": []
    },
    {
        "type": "legit",
        "sender": "orders@amazon.com",
        "subject": "Your Amazon order has shipped – #402-9876543-1234567",
        "body": """Hi,

Your package is on the way! Delivery estimate: Feb 14, 2026.

Track: https://www.amazon.com/gp/your-account/order-details?orderID=402-9876543-1234567

Thank you for shopping with Amazon.
""",
        "red_flags": []
    },
    {
        "type": "legit",
        "sender": "security-noreply@google.com",
        "subject": "New sign-in from Windows PC",
        "body": """We noticed a new sign-in to your Google Account.

Device: Windows • Location: Your city

If this was you → no action needed.
If not → secure your account: https://myaccount.google.com/security-checkup

Google Security""",
        "red_flags": []
    },

    # Phishing examples
    {
        "type": "phish",
        "sender": "support@paypa1.com",
        "subject": "URGENT: Account Limited – Verify Now",
        "body": """Dear PayPal User,

Your account has been limited due to unusual activity.

Please verify your identity within 24 hours to avoid permanent suspension:

Click here: https://paypa1-secure-verify.net/login

PayPal Security Department""",
        "red_flags": [
            "Domain misspelled (paypa1 instead of paypal)",
            "Urgency & threat of account loss",
            "Fake login link (not paypal.com)",
            "Generic greeting"
        ]
    },
    {
        "type": "phish",
        "sender": "award-team@intl-lottery.org",
        "subject": "WINNER NOTIFICATION: $950,000 USD Prize",
        "body": """Congratulations!

You are the selected winner of our International Online Draw.

To claim your funds, reply with:
- Full name
- Phone number
- Bank account details

Claim link: http://secure-prize-claim.net/redeem

Offer expires in 72 hours!

International Lottery Commission""",
        "red_flags": [
            "Unsolicited huge prize",
            "Requests sensitive personal/bank info",
            "Fake domain",
            "Time pressure"
        ]
    },
    {
        "type": "phish",
        "sender": "microsoft-support@microsoft-team.live",
        "subject": "Critical Security Alert – Office 365 Account",
        "body": """Microsoft Alert

We blocked suspicious sign-in attempts.

Protect your account: Confirm identity → https://office365-secure-login.com/verify

Microsoft Support""",
        "red_flags": [
            "Suspicious domain",
            "Fear tactic (blocked sign-ins)",
            "Fake verification link"
        ]
    },
    # Add even more if you want (bank, HR, crypto, etc.)
]

class PhishingSimulator:
    def __init__(self, root):
        self.root = root
        self.root.title("Phishing Awareness Simulator – Educational Tool")
        self.root.geometry("900x650")
        self.root.configure(bg="#f0f4f8")

        self.score = 0
        self.rounds = 0
        self.max_rounds = 10
        self.current_email = None

        self.create_widgets()

    def create_widgets(self):
        # Header
        tk.Label(self.root, text="Phishing Awareness Trainer", font=("Segoe UI", 18, "bold"),
                 bg="#f0f4f8", fg="#2c3e50").pack(pady=10)

        tk.Label(self.root, text="Read the email and decide: Phishing or Legitimate?",
                 font=("Segoe UI", 11), bg="#f0f4f8").pack()

        # Progress
        self.progress = ttk.Progressbar(self.root, orient="horizontal", length=600, mode="determinate")
        self.progress.pack(pady=10)
        self.progress_label = tk.Label(self.root, text="Round 0/10", bg="#f0f4f8", font=("Segoe UI", 10))
        self.progress_label.pack()

        # Email display
        self.email_frame = tk.Frame(self.root, bg="white", bd=2, relief="groove")
        self.email_frame.pack(padx=20, pady=10, fill="both", expand=True)

        self.sender_label = tk.Label(self.email_frame, text="", font=("Consolas", 11, "bold"),
                                     bg="white", anchor="w", justify="left")
        self.sender_label.pack(fill="x", padx=10, pady=5)

        self.subject_label = tk.Label(self.email_frame, text="", font=("Consolas", 11, "bold"),
                                      bg="white", anchor="w", justify="left")
        self.subject_label.pack(fill="x", padx=10, pady=5)

        self.body_text = scrolledtext.ScrolledText(self.email_frame, wrap=tk.WORD, font=("Segoe UI", 11),
                                                   bg="#fdfdfd", height=15)
        self.body_text.pack(padx=10, pady=5, fill="both", expand=True)

        # Buttons
        btn_frame = tk.Frame(self.root, bg="#f0f4f8")
        btn_frame.pack(pady=15)

        self.phish_btn = tk.Button(btn_frame, text="This is PHISHING", command=lambda: self.check_guess("phish"),
                                   bg="#e74c3c", fg="white", font=("Segoe UI", 12, "bold"), width=20)
        self.phish_btn.pack(side=tk.LEFT, padx=20)

        self.legit_btn = tk.Button(btn_frame, text="This is LEGITIMATE", command=lambda: self.check_guess("legit"),
                                   bg="#27ae60", fg="white", font=("Segoe UI", 12, "bold"), width=20)
        self.legit_btn.pack(side=tk.LEFT, padx=20)

        # Start
        self.next_round()

    def next_round(self):
        if self.rounds >= self.max_rounds:
            self.show_summary()
            return

        self.rounds += 1
        self.progress["value"] = (self.rounds / self.max_rounds) * 100
        self.progress_label.config(text=f"Round {self.rounds}/{self.max_rounds}")

        self.current_email = random.choice(EMAIL_TEMPLATES)

        self.sender_label.config(text=f"From: {self.current_email['sender']}")
        self.subject_label.config(text=f"Subject: {self.current_email['subject']}")

        self.body_text.delete(1.0, tk.END)
        self.body_text.insert(tk.END, self.current_email["body"])

        # Enable buttons
        self.phish_btn.config(state="normal")
        self.legit_btn.config(state="normal")

    def check_guess(self, guess):
        self.phish_btn.config(state="disabled")
        self.legit_btn.config(state="disabled")

        correct = guess == self.current_email["type"]

        if correct:
            self.score += 1
            feedback = "Correct! ✓"
            color = "green"
        else:
            feedback = "Incorrect ✗"
            color = "red"

        msg = f"{feedback}\nThis email was: {self.current_email['type'].upper()}\n\n"
        if self.current_email["red_flags"]:
            msg += "Red flags detected:\n" + "\n".join(f"• {f}" for f in self.current_email["red_flags"])

        messagebox.showinfo("Feedback", msg)

        self.root.after(800, self.next_round)  # small delay then next

    def show_summary(self):
        percent = (self.score / self.max_rounds) * 100
        title = "Training Complete!"
        msg = f"Your score: {self.score}/{self.max_rounds} ({percent:.0f}%)\n\n"

        if percent >= 80:
            msg += "Excellent awareness! You're difficult to phish."
        elif percent >= 50:
            msg += "Good effort – keep practicing the red flags."
        else:
            msg += "Time to review phishing indicators more closely."

        msg += "\n\nQuick Tips:\n• Always check sender domain\n• Hover over links before clicking\n• Be skeptical of urgency\n• Enable 2FA everywhere\n• Report suspicious emails"

        messagebox.showinfo(title, msg)
        self.root.quit()


if __name__ == "__main__":
    root = tk.Tk()
    app = PhishingSimulator(root)
    root.mainloop()