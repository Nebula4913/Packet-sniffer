from scapy.all import sniff, IP, TCP, UDP

def analyze_packet(packet):
    if IP in packet:
        source = packet[IP].src
        destination = packet[IP].dst
        
        if TCP in packet:
            protocol = "TCP"
        elif UDP in packet:
            protocol = "UDP"
        else:
            protocol = "Other"
        
        print(f"{source} --> {destination} | Protocol: {protocol}")

print("[*] Packet Sniffer Started...")
sniff(prn=analyze_packet, store=False)