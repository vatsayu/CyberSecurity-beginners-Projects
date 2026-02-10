import scapy.all as scapy
import socket
import argparse
import time

def get_local_ip():
    """Get your own IP to determine the network range"""
    s = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
    try:
        # Doesn't need to connect really
        s.connect(('10.255.255.255', 1))
        IP = s.getsockname()[0]
    except Exception:
        IP = '127.0.0.1'
    finally:
        s.close()
    return IP

def scan(ip_range):
    """Perform ARP scan on the given IP range (e.g., 192.168.1.0/24)"""
    print(f"[*] Scanning network: {ip_range}")
    print("[*] Sending ARP requests... (this may take 5-20 seconds)\n")

    arp_request = scapy.ARP(pdst=ip_range)
    broadcast = scapy.Ether(dst="ff:ff:ff:ff:ff:ff")
    arp_broadcast = broadcast / arp_request

    # Send and receive responses (timeout 2s, verbose off)
    answered_list = scapy.srp(arp_broadcast, timeout=2, verbose=False)[0]

    devices = []
    for sent, received in answered_list:
        try:
            hostname = socket.gethostbyaddr(received.psrc)[0]
        except:
            hostname = "Unknown"

        devices.append({
            "ip": received.psrc,
            "mac": received.hwsrc.upper(),
            "hostname": hostname
        })

    return devices

def print_results(devices):
    if not devices:
        print("[-] No devices found. Try running with admin privileges or check your network.")
        return

    print("IP\t\tMAC Address\t\tHostname")
    print("-" * 60)
    for device in sorted(devices, key=lambda x: x["ip"]):
        print(f"{device['ip']}\t{device['mac']}\t{device['hostname']}")

    print(f"\n[+] Found {len(devices)} active devices.")

if __name__ == "__main__":
    parser = argparse.ArgumentParser(description="Simple Network Device Scanner (ARP-based)")
    parser.add_argument("-r", "--range", help="IP range to scan (e.g., 192.168.1.0/24)", required=True)
    args = parser.parse_args()

    print("=== Network Device Scanner (P3) ===")
    print("Educational tool - Only scan networks you own / have permission for!\n")

    devices = scan(args.range)
    print_results(devices)