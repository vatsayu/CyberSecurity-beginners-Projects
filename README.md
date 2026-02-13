# CyberSec_beginners_Projects

# CyberSecurity Beginners Projects

A collection of beginner-friendly cybersecurity projects built for learning core security concepts, tools, and awareness techniques.

All projects are written in **Python** and are intended **strictly for educational and ethical purposes**.

## Project List

| #  | Project Name                  | Description                                                                 | Status    | Folder / Location                          |
|----|-------------------------------|-----------------------------------------------------------------------------|-----------|--------------------------------------------|
| P1 | Network Scanner (Bash)        | Bash script to scan local network for active devices (ping sweep + ARP)     | Completed | `P1/Typo-Game/` or `Network-Scanner-Bash/` |
| P2 | Typo Game (Bash)              | Bash-based typing speed & accuracy game (useful for awareness training)     | Completed | `P2/Typo-Game/`                            |
| P3 | File Type Identifier          | GUI tool to detect real file types using magic numbers (ignores extensions) | Completed | `File-Type-Identifier-GUI/`                |
| P4 | Phishing Awareness Simulator  | Interactive GUI trainer to recognize phishing vs legitimate emails          | Completed | `-Phishing-Awareness-Simulator/`           |
| P5 | Network Device Scanner        | (planned) Local network discovery tool                                      | Completed | —                                          |
| P6 | Password Policy Analyzer      | (planned) Strength & compliance checker                                     | Completed | —                                          |
| P7 | Secure File Share System      | (planned) Basic encrypted file transfer simulation                          | Completed | —                                          |
| P8 | Intrusion Detection System (IDS) | (planned) Simple network traffic monitor                                 | Planned   | —                                          |
| P9 | Web App Vulnerability Scanner | (planned) Basic scanner for common web vulnerabilities                      | Planned   | —                                          |

## Project Details

### – File Type Identifier (Hacker GUI Edition)

**Theory / Purpose**  
Many malware authors disguise dangerous files (e.g. executables) with innocent-looking extensions (.jpg, .pdf, .docx). Relying only on file extensions is insecure because they can be easily changed.  
The correct way is to examine the **file signature** (magic numbers) — specific byte patterns at the beginning of the file that identify its true format.

**What this tool does**  
- Uses `python-magic` library (based on libmagic / file command) to detect MIME type from content
- Shows real type vs extension match (Yes/No)
- Hacker-style green terminal GUI with welcome screen
- Single file analysis + thumbnail preview for images
- Recursive directory scanning with progress bar
- Export results to TXT or CSV

**Technologies**  
Python, Tkinter (GUI), python-magic-bin (Windows), Pillow (thumbnails)

**How to run**  
```bash
cd File-Type-Identifier-GUI
python -m venv venv
venv\Scripts\activate
pip install pillow python-magic-bin
python file_type_hacker_gui.py

# File Type Identifier – Hacker GUI Edition

Green matrix-style GUI tool that detects **true file types** using magic numbers (ignores extensions). Perfect for spotting disguised files/malware.

## Features
- Hacker-themed interface with welcome screen & menu
- Single file scan + image thumbnail preview
- Directory recursive scan with progress bar
- Color-coded results (green = match, orange = mismatch)
- Export reports (TXT/CSV)

## How to Run (Windows)
1. `python -m venv venv`
2. `venv\Scripts\activate`
3. `pip install pillow python-magic-bin`
4. `python file_type_hacker_gui.py`

Built as part of beginner cybersecurity projects collection.
