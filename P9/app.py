from flask import Flask, render_template, request
import requests
from urllib.parse import urlparse
import socket
from bs4 import BeautifulSoup
import re

app = Flask(__name__)

def scan_xss(url):
    """Basic reflective XSS test"""
    payloads = ["<script>alert('XSS')</script>", "'><img src=x onerror=alert('XSS')>"]
    results = []
    for payload in payloads:
        test_url = f"{url}?q={payload}" if '?' in url else f"{url}?test={payload}"
        try:
            r = requests.get(test_url, timeout=5)
            if payload in r.text:
                results.append(f"Potential XSS vulnerability detected with payload: {payload}")
        except:
            pass
    return results if results else ["No XSS detected in basic test."]

def scan_sqli(url):
    """Basic error-based SQLi test"""
    payloads = ["' OR 1=1 --", '" OR 1=1 --', "' ; DROP TABLE users --"]
    results = []
    for payload in payloads:
        test_url = f"{url}?id={payload}" if '?' in url else f"{url}?id={payload}"
        try:
            r = requests.get(test_url, timeout=5)
            if re.search(r"(sql|syntax|error|database|mysql|sqlite|postgresql)", r.text.lower()):
                results.append(f"Potential SQL Injection detected with payload: {payload}")
        except:
            pass
    return results if results else ["No SQLi detected in basic test."]

def scan_ports(url):
    """Basic open ports check (top 10 common)"""
    host = urlparse(url).hostname
    ports = [80, 443, 22, 21, 25, 53, 110, 143, 3306, 5432]
    open_ports = []
    for port in ports:
        try:
            s = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
            s.settimeout(1)
            s.connect((host, port))
            open_ports.append(port)
            s.close()
        except:
            pass
    return open_ports if open_ports else "No open ports detected in basic scan."

@app.route("/", methods=["GET", "POST"])
def index():
    results = {}
    if request.method == "POST":
        url = request.form.get("url").strip()
        if not url:
            results["error"] = "Please enter a URL."
        else:
            results["url"] = url
            results["xss"] = scan_xss(url)
            results["sqli"] = scan_sqli(url)
            results["ports"] = scan_ports(url)

    return render_template("index.html", results=results)

if __name__ == "__main__":
    app.run(debug=True)