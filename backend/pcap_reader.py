from scapy.all import rdpcap, IP, TCP, UDP, ICMP


def read_packets(pcap_packets):
    packets = rdpcap(pcap_packets)
    packet_data = []
    for packet in packets:
        packet_info = {
            "source": packet.sprintf("{IP:%IP.src%}"),
            "destination": packet.sprintf("{IP:%IP.dst%}"),
            "protocol": packet.sprintf("{IP:%IP.proto%}"),
            "summary": packet.summary(),
            "details": str(packet.show(dump=True)),
        }
        packet_data.append(packet_info)
    return packet_data


# Currently unused
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


# Currently unused
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
