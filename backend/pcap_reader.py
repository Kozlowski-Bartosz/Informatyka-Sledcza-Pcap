from scapy.all import rdpcap
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
        "pcap_duration": round(duration, 3),
        "packets_count": count,
        "pps": round(count / duration, 2),
        "first_packet_time": datetime.fromtimestamp(float(df['timestamp'].iloc[0])).strftime('%Y-%m-%d %H:%M:%S'),
        "last_packet_time": datetime.fromtimestamp(float(df['timestamp'].iloc[-1])).strftime('%Y-%m-%d %H:%M:%S')
    }


def plot_pie_png_file(df, column, caption, file_name):
    value_counts = df[column].value_counts()

    total = value_counts.sum()
    threshold = 0.04 * total
    
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
    mac_address_regex = r'([0-9A-Fa-f]{2}[:-]){5}([0-9A-Fa-f]{2})'
    df = df[~(df['source'].str.match(mac_address_regex) | df['destination'].str.match(mac_address_regex))]
    
    src_ip_count = df['source'].value_counts().reset_index()
    src_ip_count.columns = ['Source IP', 'Count']  # Rename columns
    src_ip_count = src_ip_count.sort_values(by='Count', ascending=False)
    src_ip_count = src_ip_count.to_dict(orient='records')

    dst_ip_count = df['destination'].value_counts().reset_index()
    dst_ip_count.columns = ['Destination IP', 'Count']  # Rename columns
    dst_ip_count = dst_ip_count.sort_values(by='Count', ascending=False)
    dst_ip_count = dst_ip_count.to_dict(orient='records')
    
    src_port_count = df['src_port'].value_counts().reset_index()
    src_port_count.columns = ['Port Number', 'Count']  # Rename columns
    src_port_count = src_port_count.sort_values(by='Count', ascending=False)
    src_port_count = src_port_count.to_dict(orient='records')

    dst_port_count = df['dst_port'].value_counts().reset_index()
    dst_port_count.columns = ['Port Number', 'Count']  # Rename columns
    dst_port_count = dst_port_count.sort_values(by='Count', ascending=False)
    dst_port_list = dst_port_count.to_dict(orient='records')

    return src_ip_count, dst_ip_count, src_port_count, dst_port_list
