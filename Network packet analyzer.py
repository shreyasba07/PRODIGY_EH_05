from scapy.all import *
from datetime import datetime

def packet_analyzer(packet):
    print("\n" + "="*60)
    print("Time:", datetime.now())

    # Check if IP layer exists
    if packet.haslayer(IP):
        ip_layer = packet[IP]
        print("Source IP      :", ip_layer.src)
        print("Destination IP :", ip_layer.dst)
        print("Protocol       :", ip_layer.proto)

    # Check TCP layer
    if packet.haslayer(TCP):
        tcp_layer = packet[TCP]
        print("Protocol Type  : TCP")
        print("Source Port    :", tcp_layer.sport)
        print("Destination Port:", tcp_layer.dport)

    # Check UDP layer
    elif packet.haslayer(UDP):
        udp_layer = packet[UDP]
        print("Protocol Type  : UDP")
        print("Source Port    :", udp_layer.sport)
        print("Destination Port:", udp_layer.dport)

    # Payload
    if packet.haslayer(Raw):
        payload = packet[Raw].load
        print("Payload (first 50 bytes):")
        print(payload[:50])

    print("="*60)


print("Starting Packet Sniffer...")
print("Press Ctrl+C to stop.\n")

# Start sniffing
sniff(prn=packet_analyzer, store=False)
