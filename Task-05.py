from scapy.all import sniff
from scapy.layers.inet import IP, TCP, UDP

# Define the packet analysis function
def packet_callback(packet):
    # Check if the packet has an IP layer
    if IP in packet:
        src_ip = packet[IP].src
        dst_ip = packet[IP].dst
        protocol = packet[IP].proto

        # Identify the protocol
        if packet.haslayer(TCP):
            proto_name = "TCP"
            sport = packet[TCP].sport
            dport = packet[TCP].dport
        elif packet.haslayer(UDP):
            proto_name = "UDP"
            sport = packet[UDP].sport
            dport = packet[UDP].dport
        else:
            proto_name = "Other"
            sport, dport = None, None

        # Print packet information
        print(f"Source IP: {src_ip}, Destination IP: {dst_ip}")
        print(f"Protocol: {proto_name}, Source Port: {sport}, Destination Port: {dport}")

        # Extract payload if any
        if packet.haslayer(Raw):
            payload = packet[Raw].load
            print(f"Payload: {payload}")
        print("-" * 60)

# Start sniffing
print("Starting packet capture...")
sniff(filter="ip", prn=packet_callback, count=10)  # Captures 10 packets
