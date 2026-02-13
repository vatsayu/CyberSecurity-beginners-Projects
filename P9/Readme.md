#  – Web Vulnerability Scanner (Web App)

A simple, educational web-based vulnerability scanner built with **Flask** and styled with a modern **black neon / cyberpunk** theme.  
Scans URLs for common vulnerabilities such as reflective XSS, basic SQL injection errors, and open ports.

**Important Ethical & Legal Note**  
This tool is **strictly for learning and testing your own websites** or sites you have **explicit written permission** to scan.  
Unauthorized scanning of any website is illegal in most jurisdictions. Use responsibly.

## Features

- Clean, dark neon-themed dashboard (black background + glowing green accents)
- Input form to scan any URL
- Basic vulnerability checks:
  - Reflective XSS (payload injection & reflection detection)
  - Error-based SQL Injection (common error patterns in response)
  - Open ports scan (top common ports: 80, 443, 22, 21, etc.)
- Real-time results display with categorized sections
- Responsive design (mobile-friendly)
- Deployable on Vercel (free & serverless)

## Screenshots

<img width="1919" height="1113" alt="Screenshot 2026-02-13 225854" src="https://github.com/user-attachments/assets/9a5dc3a0-cb46-49a6-88f3-35e0740f9f19" />


## Tech Stack

- **Backend**: Flask (Python)
- **Frontend**: HTML + Tailwind CSS + custom neon CSS
- **Scanner libraries**: requests, BeautifulSoup4 (for parsing), socket (port check)
- **Deployment**: Vercel (with vercel.json config)

## Requirements (Local Development)

```bash
pip install flask requests beautifulsoup4
