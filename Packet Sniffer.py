import scapy.all as scapy

def packet_callback(packet):
    if packet.haslayer(scapy.IP):
        src_ip = packet[scapy.IP].src
        dst_ip = packet[scapy.IP].dst
        protocol = packet[scapy.IP].proto
        print(f"[+] Packet: {src_ip} -> {dst_ip} | Protocol: {protocol}")

def start_sniffing(interface):
    print(f"[*] Starting packet sniffer on {interface}...")
    scapy.sniff(iface=interface, store=False, prn=packet_callback)

if __name__ == "__main__":
    interface = input("Enter network interface to sniff (e.g., eth0, wlan0): ")
    start_sniffing(interface)
