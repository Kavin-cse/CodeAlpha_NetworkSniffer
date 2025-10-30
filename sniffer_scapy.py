#!/usr/bin/env python3
"""
Basic Network Sniffer using Scapy
"""

from scapy.all import sniff, IP, TCP, UDP, ICMP, Raw, wrpcap
import time

def packet_callback(packet):
    timestamp = time.strftime('%Y-%m-%d %H:%M:%S', time.localtime())
    
    if IP in packet:
        src_ip = packet[IP].src
        dst_ip = packet[IP].dst
        proto = ""
        sport = dport = ""
        payload = ""
        
        if TCP in packet:
            proto = "TCP"
            sport = packet[TCP].sport
            dport = packet[TCP].dport
        elif UDP in packet:
            proto = "UDP"
            sport = packet[UDP].sport
            dport = packet[UDP].dport
        elif ICMP in packet:
            proto = "ICMP"
        else:
            proto = "Other"
        
        if Raw in packet:
            try:
                payload = packet[Raw].load.decode(errors='ignore')[:80]
            except:
                payload = str(packet[Raw].load)
        
        print(f"[{timestamp}] {src_ip}:{sport} -> {dst_ip}:{dport} | {proto}")
        if payload:
            print(f"   Payload: {payload}")
    else:
        print(f"[{timestamp}] Non-IP Packet: {packet.summary()}")

# Capture packets
print("Starting packet capture... (Press Ctrl+C to stop)")
packets = sniff(iface="eth0", count=20, prn=packet_callback)

# Save packets to PCAP
wrpcap("captured_packets.pcap", packets)
print("\nPackets saved to 'captured_packets.pcap'")
