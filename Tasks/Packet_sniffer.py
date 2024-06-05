'''Task 05: Develop a packet sniffer tool that captures and analyzes network packets. Display relevant information such as source and destination IP addresses, protocols, and payload data.'''

from scapy.all import sniff, IP, TCP, UDP

def packet_handler(packet):
    if IP in packet:
        src_ip = packet[IP].src
        dst_ip = packet[IP].dst

        if TCP in packet:
            protocol = "TCP"
            src_port = packet[TCP].sport
            dst_port = packet[TCP].dport
        elif UDP in packet:
            protocol = "UDP"
            src_port = packet[UDP].sport
            dst_port = packet[UDP].dport
        else:
            protocol = "Other"
            src_port = dst_port = None

        print(f"Source IP: {src_ip}, Destination IP: {dst_ip}, Protocol: {protocol}")
        if src_port and dst_port:
            print(f"Source Port: {src_port}, Destination Port: {dst_port}")

sniff(filter="ip", prn=packet_handler, count=10000)
