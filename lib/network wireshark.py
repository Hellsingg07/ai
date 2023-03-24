from scapy.all import *

# Load the pcap file
packets = rdpcap('C:\\Users\\leand\\Documents\\Projects\\ai\\data\\mynet.pcapng')

# Iterate over each packet in the pcap file
for packet in packets:
    # Check for unusual traffic patterns
    if packet.haslayer('IP') and packet['IP'].dst == '192.168.0.1' and packet['IP'].dport == 80:
        print(f"Unusual traffic pattern: {packet['IP'].src} - {packet['IP'].dst}:{packet['IP'].dport}")
    # Check for suspicious network activity
    elif packet.haslayer('TCP') and packet['TCP'].flags == 'S':
        print(f"Possible TCP SYN scan: {packet['IP'].src} - {packet['IP'].dst}")
    elif packet.haslayer('TCP') and packet['TCP'].flags == 'FPU':
        print(f"Possible TCP XMAS scan: {packet['IP'].src} - {packet['IP'].dst}")
    # Check for unusual DNS activity
    elif packet.haslayer('DNS') and packet['DNS'].haslayer('DNSQR') and packet['DNS'].qd.qtype == 1 and packet['DNS'].qd.qclass == 1:
        print(f"Unusual DNS activity: {packet['IP'].src} - {packet['DNS'].qd.qname}")
    # Check for suspicious User-Agent strings
    elif packet.haslayer('HTTP') and packet['HTTP'].User_Agent.startswith('Mozilla/5.0 (Windows NT 6.1; Win64; x64)'):
        print(f"Suspicious User-Agent string: {packet['IP'].src} - {packet['HTTP'].User_Agent}")

    