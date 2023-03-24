from scapy.all import *

# Load the pcap file
packets = rdpcap('C:\\Users\\leand\\Documents\\Projects\\ai\\data\\mynet.pcapng')

# Iterate over each packet in the pcap file
for packet in packets:
    # Check if the packet has any errors
    if packet.haslayer('ICMP') and packet['ICMP'].type == 3:
        print(f"Error: {packet['ICMP'].type} - {packet['ICMP'].code} - {packet['IP'].src} - {packet['IP'].dst}")
    # Check if the packet is a TCP SYN scan
    elif packet.haslayer('TCP') and packet['TCP'].flags == 'S':
        print(f"Possible TCP SYN scan: {packet['IP'].src} - {packet['IP'].dst}")
    # Check if the packet is a TCP XMAS scan
    elif packet.haslayer('TCP') and packet['TCP'].flags == 'FPU':
        print(f"Possible TCP XMAS scan: {packet['IP'].src} - {packet['IP'].dst}")

    