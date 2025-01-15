from scapy.all import rdpcap, IP, load_layer
from scapy.layers import http
from scapy.layers.tls.handshake import TLSClientHello
from scapy.layers.tls.extensions import TLS_Ext_ServerName
from datetime import datetime
import pandas as pd
import matplotlib.pyplot as plt
import matplotlib


def read_packets(pcap_packets):
    packet_data = []
    try:
        packets = rdpcap(pcap_packets)
    except AttributeError:
        return packet_data

    for packet in packets:
        packet_info = {
            "timestamp": packet.time,
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

# Take stats from pcap file

def pcap_statistics(df):
    duration = df['timestamp'].iloc[-1] - df['timestamp'].iloc[0]
    count = df.shape[0]
    return {
        "pcap_duration": duration,
        "packets_count": count,
        "pps": round(count / duration, 2),
        "first_packet_time": datetime.fromtimestamp(float(df['timestamp'].iloc[0])).strftime('%Y-%m-%d %H:%M:%S'),
        "last_packet_time": datetime.fromtimestamp(float(df['timestamp'].iloc[-1])).strftime('%Y-%m-%d %H:%M:%S')
    }


def plot_pie_png_file(df, column, caption, file_name):
    value_counts = df[column].value_counts()
    threshold = 5 # TODO: Percent values of all packets for improved readability
    grouped_counts = value_counts[value_counts >= threshold]
    others_count = value_counts[value_counts < threshold].sum()
    if others_count > 0:
        grouped_counts['Others'] = others_count
    matplotlib.use('agg')
    fig, ax = plt.subplots(figsize=(6, 6))
    grouped_counts.plot.pie(autopct='%1.1f%%', ax=ax, title=caption)
    ax.set_ylabel('')
    plt.tight_layout()
    plt.savefig(f'frontend/static/images/{file_name}')
    plt.close(fig)

def info_tables(df):
    df.replace('', pd.NA, inplace=True)
    # Count occurrences and convert to DataFrame
    dst_port_count = df['dst_port'].value_counts().reset_index()
    dst_port_count.columns = ['Port Number', 'Count']  # Rename columns

    # Sort the DataFrame by 'Count' in descending order
    dst_port_count = dst_port_count.sort_values(by='Count', ascending=False)
    dst_port_list = dst_port_count.to_dict(orient='records')

    return dst_port_list


def seek_https_requests(pcap_packets):
    load_layer("tls")
    url_list = []
    try:
        packets = rdpcap(pcap_packets)
    except AttributeError:
        return url_list

# TODO better result output
    for packet in packets:
        if packet.haslayer(http.HTTPRequest):
            http_layer = packet.getlayer(http.HTTPRequest)
            ip_layer = packet.getlayer(IP)
            url = ('\n{} just requested a {} {}{}'.format(
                ip_layer.fields['src'],
                http_layer.fields['Method'].decode('utf-8'),
                http_layer.fields['Host'].decode('utf-8'),
                http_layer.fields['Path'].decode('utf-8')))
            url_list.append(url)
        elif packet.haslayer(TLSClientHello):
            exts = packet[TLSClientHello].ext
            for ext in exts:
                if isinstance(ext, TLS_Ext_ServerName):
                    server_names = ext.servernames
                    if server_names:
                        url = f" Server Name Indication (SNI): {server_names[0].servername.decode()}"
                        url_list.append(url)
    return url_list
