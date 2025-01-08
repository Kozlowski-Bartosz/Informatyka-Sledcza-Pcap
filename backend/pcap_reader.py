from scapy.all import rdpcap, IP, TCP, UDP, ICMP
import pandas as pd
import matplotlib.pyplot as plt
import io


def read_packets(pcap_packets):
    packet_data = []
    try:
        packets = rdpcap(pcap_packets)
    except AttributeError:
        return packet_data

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

# Export packets to pandas dataframe


def packets_to_df(pcap_packets):
    data = read_packets(pcap_packets)
    df = pd.DataFrame(data)
    return df

# Plot pie chart and generate png


def plot_pie_png(df, column):
    value_counts = df[column].value_counts()

    # Define a threshold for grouping marginal values
    threshold = 5

    # Group marginal values into "Others"
    grouped_counts = value_counts[value_counts >= threshold]
    others_count = value_counts[value_counts < threshold].sum()

    # Add the "Others" category if necessary
    if others_count > 0:
        grouped_counts['Others'] = others_count

    # Plot as a pie chart
    fig, ax = plt.subplots(figsize=(6, 6))
    grouped_counts.plot.pie(autopct='%1.1f%%', ax=ax,
                            title="Distribution of Values")
    ax.set_ylabel('')  # Hide the y-axis label

    # Save the plot to a BytesIO object
    buf = io.BytesIO()
    plt.savefig(buf, format='png')
    buf.seek(0)
    plt.close(fig)  # Close the figure to free memory
    return buf


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
