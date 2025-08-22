# Project 1: Scanning and Enumerating a Local Network using Nmap

## Introduction
In this project, you will learn how to use Nmap, a powerful network scanning tool, to discover devices and services running on a local network. Network scanning and enumeration are critical skills for ethical hackers, as they help in identifying potential targets and vulnerabilities within a network. By the end of this project, you will be able to perform basic network scans, identify open ports, and gather information about the devices on your network using Kali Linux.

## Pre-requisites
- Basic understanding of networking concepts (IP addresses, ports, etc.).
- Familiarity with using the command line interface (CLI).
- Kali Linux installed on your machine (either natively, on a virtual machine, or as a live boot).

## Lab Set-up and Tools

### Tools
- **Kali Linux**: A Debian-derived Linux distribution designed for digital forensics and penetration testing.
- **Nmap**: Network exploration tool and security/port scanner (pre-installed on Kali Linux).
- A local network with multiple devices connected (computers, printers, IoT devices, etc.).

### Installation
Nmap is pre-installed on Kali Linux. You can verify the installation or update it using the following command:
```sh
sudo apt-get update && sudo apt-get install nmap
```

## Tasks

### Task 1: Basic Network Scan
Step 1: Open a terminal on your Kali Linux machine.
Step 2: Run a basic scan on your local network. Replace 192.168.1.0/24 with your network's IP range.
```sh
nmap 192.168.1.0/24
```
Expected Output: A list of devices on your network, their IP addresses, and the open ports.

<img width="1920" height="997" alt="Screenshot_2025-08-22_12_40_41" src="https://github.com/user-attachments/assets/480dcd93-ed45-412c-a08c-55aa4bcbcebd" />


### Task 2: Scanning for Specific Ports
Step 1: To scan for specific ports (e.g., HTTP port 80), use the -p option:
```sh
nmap -p 80 192.168.1.0/24
```
Expected Output: A list of devices with port 80 open.

<img width="1920" height="997" alt="Screenshot_2025-08-22_12_42_46" src="https://github.com/user-attachments/assets/4056189c-f055-485d-8a4f-05e096b65780" />

### Task 3: Service Version Detection
Step 1: Use the -sV option to detect the version of services running on open ports:
```sh
nmap -sV 192.168.1.0/24
```
Expected Output: A detailed list of open ports and the services running on them, including version information.

<img width="1920" height="997" alt="Screenshot_2025-08-22_12_51_58" src="https://github.com/user-attachments/assets/e71de110-b795-4cdf-b849-240434b766f5" />


### Task 4: Operating System Detection
Step 1: Use the -O option to detect the operating systems of devices on the network:
```sh
sudo nmap -O 192.168.1.0/24
```
Expected Output: The operating system details of the devices on the network.

<img width="1920" height="997" alt="Screenshot_2025-08-22_12_53_44" src="https://github.com/user-attachments/assets/460a2db5-e0f2-4a77-b3e0-18063eca746e" />


### Task 5: Aggressive Scan
Step 1: Perform an aggressive scan using the -A option, which includes OS detection, version detection, script scanning, and traceroute:
```sh
sudo nmap -A 192.168.1.0/24
```
Expected Output: Comprehensive information about the devices on the network, including open ports, services, versions, operating systems, and traceroute details.


<img width="1920" height="997" alt="Screenshot_2025-08-22_12_57_31" src="https://github.com/user-attachments/assets/527267c8-e3c1-486b-bbc1-3ee1a2177d10" />

## Additional Resources
Nmap Official Documentation
Nmap Cheat Sheet

This project will give you a solid foundation in using Nmap for network scanning and enumeration.




