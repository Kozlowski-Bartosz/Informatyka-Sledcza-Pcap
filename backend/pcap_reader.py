from scapy.all import rdpcap, IP, TCP, UDP, ICMP


def read_packets(pcap_packets):
    packets = rdpcap(pcap_packets.pcap_file)
    filtered_packets = filter_packets(
        packets, ip=pcap_packets.ip, port=pcap_packets.port, protocol=pcap_packets.protocol)

    if filtered_packets:
        for pkt in filtered_packets:
            show_packet_info(pkt)
    else:
        print("No packets matching filters found.")


def filter_packets(packets, ip=None, port=None, protocol=None):
    def packet_matches(packet):
        if ip and (IP not in packet or (packet[IP].src != ip and packet[IP].dst != ip)):
            return False
        if port and (TCP not in packet and UDP not in packet or
                     (TCP in packet and packet[TCP].dport != port and packet[TCP].sport != port) and
                     (UDP in packet and packet[UDP].dport != port and packet[UDP].sport != port)):
            return False
        if protocol and ((protocol.lower() == 'tcp' and TCP not in packet) or
                         (protocol.lower() == 'udp' and UDP not in packet) or
                         (protocol.lower() == 'icmp' and ICMP not in packet)):
            return False
        return True

    return [packet for packet in packets if packet_matches(packet)]


def show_packet_info(pkt):
    if IP in pkt:
        print(f"IP: {pkt[IP].src} -> {pkt[IP].dst}")
    if TCP in pkt:
        print(f"TCP: {pkt[TCP].sport} -> {pkt[TCP].dport}")
    elif UDP in pkt:
        print(f"UDP: {pkt[UDP].sport} -> {pkt[UDP].dport}")
    elif ICMP in pkt:
        print(f"ICMP: {pkt[ICMP].type}")
    print("-" * 40)
