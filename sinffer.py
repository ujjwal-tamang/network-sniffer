# network-sniffer
from scapy.all import sniff, IP, TCP, UDP

# Function to process each captured packet
def process_packet(packet):
    if IP in packet:
        ip_src = packet[IP].src
        ip_dst = packet[IP].dst
        proto = packet[IP].proto

        if TCP in packet:
            proto_name = "TCP"
            payload = str(bytes(packet[TCP].payload))
        elif UDP in packet:
            proto_name = "UDP"
            payload = str(bytes(packet[UDP].payload))
        else:
            proto_name = str(proto)
            payload = "N/A"

        print(f"[+] Source: {ip_src} -> Destination: {ip_dst} | Protocol: {proto_name}")
        print(f"    Payload: {payload[:50]}")  # show first 50 chars of payload

# Capture packets (CTRL+C to stop)
print("Starting packet capture... Press CTRL+C to stop.")
sniff(prn=process_packet, store=False)
