# – Secure File Share System (GUI)

A simple, secure file encryption & decryption tool using **Fernet (AES-128 + HMAC-SHA256)**.  
Perfect for learning symmetric encryption, key management, and secure file sharing basics.

## Features

- Generate strong 256-bit encryption key
- Encrypt any file → produces `.enc` file
- Decrypt `.enc` file using the correct key
- Real-time progress bar during encryption/decryption
- SHA-256 hash verification (integrity check)
- Copy key to clipboard
- Clear log button
- Modern, clean Tkinter GUI with themed buttons

## Requirements

```bash
pip install cryptography tqdm