# P6 – Password Policy Analyzer 

A modern, real-time **password strength and policy compliance checker** with a clean Tkinter GUI.

Helps users, developers, and security professionals evaluate passwords against current best practices, estimate real-world crack resistance, and receive actionable improvement suggestions.

## What this tool does

- Analyzes password strength **as you type** (real-time feedback)
- Uses **zxcvbn** (Dropbox's realistic password strength library) for crack-time estimation
- Applies custom security rules (length, character classes, patterns, common passwords)
- Calculates **Shannon entropy** (bits of randomness) manually
- Displays visual strength meter (color-changing progress bar)
- Supports **batch analysis** from a text file (one password per line)
- Offers to save **hashed** versions of strong passwords (≥80 score) to a history file
- Includes **light/dark mode** toggle for better usability

Never stores plaintext passwords — only SHA-256 hashes are saved (user-confirmed).

## Features

- **Real-time analysis** — strength, entropy, and feedback update instantly
- **zxcvbn integration** — estimates offline/online crack times
- **Custom rules** — enforces minimum length, mixed case, digits, symbols, no sequences/repeats
- **Common password detection** — checks against built-in list of top leaked passwords
- **Shannon entropy** — shows actual randomness in bits
- **Batch mode** — load and analyze multiple passwords from .txt file
- **Dark mode** — easy theme switch
- **Copy result** to clipboard
- **History** — saves SHA-256 hashes of strong passwords (optional, user-approved)

## Requirements

```bash
pip install zxcvbn pyperclip

# Navigate to project folder
cd folder

# (Recommended) Create virtual environment
python -m venv venv
venv\Scripts\activate          # Windows
# or
source venv/bin/activate       # Linux/macOS

# Install dependencies
pip install zxcvbn pyperclip

# Launch GUI
python folder.py