# – Network Device Scanner

Simple Python tool to discover devices on your local network using ARP requests.

## Features
- Lists IP, MAC address, and hostname
- CLI interface (easy to extend to GUI)

## Requirements
- Python 3
- scapy (`pip install scapy`)

## Usage
```bash
python network.py -r 192.168.1.0/24