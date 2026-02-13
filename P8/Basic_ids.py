from scapy.all import sniff, IP, TCP, UDP, ICMP
from collections import defaultdict
import time
from colorama import init, Fore, Style
import argparse
import threading
import sys

# Initialize colorama for colored output (Windows support)
init(autoreset=True)

# ────────────────────────────────────────────────
#   Configuration & Thresholds (tune these!)
# ────────────────────────────────────────────────

PORT_SCAN_THRESHOLD = 20      # SYN packets from one IP in 10 seconds → port scan alert
SYN_FLOOD_THRESHOLD = 100     # SYN packets per second from one IP → flood alert
ALERT_COOLDOWN = 30           # Seconds before same alert type repeats for same IP

# Trackers
ip_syn_count = defaultdict(int)      # IP → number of SYN packets
ip_last_alert = defaultdict(float)   # IP → timestamp of last alert

lock = threading.Lock()              # Thread safety for counters

def packet_callback(packet):
    """Called for every captured packet"""
    if not packet.haslayer(IP):
        return

    src_ip = packet[IP].src
    current_time = time.time()

    with lock:
        # SYN packet detection (port scan / flood)
        if packet.haslayer(TCP) and packet[TCP].flags & 0x02:  # SYN flag
            ip_syn_count[src_ip] += 1

            # Check for port scan (many different ports)
            if ip_syn_count[src_ip] > PORT_SCAN_THRESHOLD:
                if current_time - ip_last_alert[src_ip] > ALERT_COOLDOWN:
                    print(f"{Fore.RED}[ALERT] Possible PORT SCAN detected from {src_ip} "
                          f"({ip_syn_count[src_ip]} SYN packets){Style.RESET_ALL}")
                    ip_last_alert[src_ip] = current_time

            # Check for SYN flood (high rate)
            elapsed = current_time - (ip_last_alert[src_ip] or current_time - 10)
            rate = ip_syn_count[src_ip] / max(elapsed, 1)
            if rate > SYN_FLOOD_THRESHOLD:
                if current_time - ip_last_alert[src_ip] > ALERT_COOLDOWN:
                    print(f"{Fore.RED}[ALERT] Possible SYN FLOOD from {src_ip} "
                          f"(rate: {rate:.1f} SYN/sec){Style.RESET_ALL}")
                    ip_last_alert[src_ip] = current_time

        # Optional: other detections (add more!)
        if packet.haslayer(ICMP) and packet[ICMP].type == 8:  # ICMP Echo Request
            print(f"{Fore.YELLOW}[INFO] ICMP ping from {src_ip} to {packet[IP].dst}{Style.RESET_ALL}")

        # Log basic packet info (optional – comment out if too noisy)
        # if packet.haslayer(TCP):
        #     print(f"{Fore.CYAN}{src_ip} → {packet[IP].dst} | TCP {packet[TCP].sport} → {packet[TCP].dport} "
        #           f"flags={packet[TCP].flags}{Style.RESET_ALL}")

def reset_counters():
    """Reset counters every 10 seconds to detect short bursts"""
    global ip_syn_count
    while True:
        time.sleep(10)
        with lock:
            ip_syn_count.clear()
            print(f"{Fore.GREEN}[INFO] Counters reset{Style.RESET_ALL}")

def main():
    parser = argparse.ArgumentParser(description="Basic Intrusion Detection System (P6)")
    parser.add_argument("-i", "--interface", default="eth0",
                        help="Network interface to monitor (e.g. eth0, wlan0, Ethernet)")
    parser.add_argument("-f", "--filter", default="tcp or udp or icmp",
                        help="BPF filter (default: tcp or udp or icmp)")
    args = parser.parse_args()

    print(f"{Fore.CYAN}=== Basic IDS (P6) – Monitoring started ==={Style.RESET_ALL}")
    print(f"Interface: {args.interface}")
    print(f"Filter: {args.filter}")
    print("Press Ctrl+C to stop\n")

    # Start background thread to reset counters
    threading.Thread(target=reset_counters, daemon=True).start()

    try:
        # Start sniffing
        sniff(iface=args.interface, filter=args.filter, prn=packet_callback, store=0)
    except KeyboardInterrupt:
        print(f"\n{Fore.YELLOW}Stopped by user. Goodbye.{Style.RESET_ALL}")
    except Exception as e:
        print(f"{Fore.RED}Error: {str(e)}{Style.RESET_ALL}")
        print("Common fixes:")
        print("1. Run as administrator (Windows) or with sudo (Linux/macOS)")
        print("2. Check Npcap is installed (Windows)")
        print("3. Verify interface name with 'scapy.get_if_list()'")

if __name__ == "__main__":
    main()