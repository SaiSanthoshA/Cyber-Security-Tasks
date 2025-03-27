from scapy.all import sniff
def packet_handler(packet):
    source = packet.src
    destination = packet.dst
    protocol = packet.proto if hasattr(packet, 'proto') else 'Unknown'  # Protocol
    print(f"Source: {source}, Destination: {destination}, Protocol: {protocol}")
sniff(prn=packet_handler, count=10)
