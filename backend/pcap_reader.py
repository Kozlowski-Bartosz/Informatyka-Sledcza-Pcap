from scapy.all import rdpcap, IP, TCP, UDP, ICMP
from scapy.layers import http
from scapy.layers.tls.handshake import TLSClientHello
from scapy.layers.tls.extensions import TLS_Ext_ServerName
import pandas as pd
import matplotlib.pyplot as plt


def read_packets(pcap_packets):
    packet_data = []
    try:
        packets = rdpcap(pcap_packets)
    except AttributeError:
        return packet_data

    for packet in packets:
        packet_info = {
            "source": packet.sprintf("{ARP:%ARP.hwsrc%}{IP:%IP.src%}"),
            "destination": packet.sprintf("{ARP:%ARP.hwdst%}{IP:%IP.dst%}"),
            "protocol": packet.sprintf("{ARP:arp}{IP:%IP.proto%}"),
            "src_port": packet.sprintf("{TCP:%r,TCP.sport%}{UDP:%r,UDP.sport%}{QUIC:%r,QUIC.sport%}"),
            "dst_port": packet.sprintf("{TCP:%r,TCP.dport%}{UDP:%r,UDP.dport%}{QUIC:%r,QUIC.dport%}"),
            "flags": packet.sprintf("{TCP:%TCP.flags%}"),
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

# Plot pie chart and save png as file

def plot_pie_png_file(df, column, caption, file_name):
    value_counts = df[column].value_counts()

    # Define a threshold for grouping marginal values
    threshold = 5 # todo: percent value of all packets

    # Group marginal values into "Others"
    grouped_counts = value_counts[value_counts >= threshold]
    others_count = value_counts[value_counts < threshold].sum()

    # Add the "Others" category if necessary
    if others_count > 0:
        grouped_counts['Others'] = others_count

    # Plot as a pie chart
    fig, ax = plt.subplots(figsize=(6, 6))
    grouped_counts.plot.pie(autopct='%1.1f%%', ax=ax,
                            title=caption)
    ax.set_ylabel('')  # Hide the y-axis label

    # Save the plot to a file
    directory = 'frontend/static/images/' + file_name
    plt.savefig(directory)
    plt.close(fig)

def seek_https_requests(pcap_packets):
    url_list = []
    try:
        packets = rdpcap(pcap_packets)
    except AttributeError:
        return url_list

    for packet in packets:
        # Processes a TCP packet, and if it contains an HTTP request, it prints it.
        if packet.haslayer(http.HTTPRequest):    
            http_layer = packet.getlayer(http.HTTPRequest)
            ip_layer = packet.getlayer(IP)
            url = ('\n{} just requested a {} {}{}'.format(
                ip_layer.fields['src'], 
                http_layer.fields['Method'].decode('utf-8'), 
                http_layer.fields['Host'].decode('utf-8'), 
                http_layer.fields['Path'].decode('utf-8')))
            url_list.append(url)
            continue
        elif packet.haslayer(TLSClientHello):
        # Iterate through the extensions of the Client Hello packet
            exts = packet[TLSClientHello].ext
            for ext in exts:
                if isinstance(ext, TLS_Ext_ServerName):
                    # Extract the server name from the extension
                    server_names = ext.servernames
                    if server_names:
                        url = "Server Name Indication:", server_names[0].servername.decode()
                        url_list.append(url)
    return url_list