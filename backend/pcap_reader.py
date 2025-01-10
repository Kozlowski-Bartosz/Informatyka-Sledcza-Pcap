from scapy.all import rdpcap, IP, TCP, UDP, ICMP, load_layer, Raw
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

def statistics(df):
    stats = {
        "pcap_duration": df['timestamp'].iloc[-1] - df['timestamp'].iloc[0],
        "first_packet_time": datetime.fromtimestamp(float(df['timestamp'].iloc[0])).strftime('%Y-%m-%d %H:%M:%S'),
        "last_packet_time": datetime.fromtimestamp(float(df['timestamp'].iloc[-1])).strftime('%Y-%m-%d %H:%M:%S')
    }
    return stats

# Plot pie chart and save png as file

def plot_pie_png_file(df, column, caption, file_name):
    value_counts = df[column].value_counts()

    # Define a threshold for grouping marginal values
    threshold = 5  # todo: percent value of all packets

    # Group marginal values into "Others"
    grouped_counts = value_counts[value_counts >= threshold]
    others_count = value_counts[value_counts < threshold].sum()

    # Add the "Others" category if necessary
    if others_count > 0:
        grouped_counts['Others'] = others_count

    # Plot as a pie chart
    matplotlib.use('agg')   # Necessary, not sure about placement. Would be better to call globally?
    fig, ax = plt.subplots(figsize=(6, 6))
    grouped_counts.plot.pie(autopct='%1.1f%%', ax=ax,
                            title=caption)
    ax.set_ylabel('')  # Hide the y-axis label

    # Save the plot to a file
    directory = 'frontend/static/images/' + file_name
    plt.savefig(directory)
    plt.close(fig)


def seek_https_requests(pcap_packets):
    load_layer("tls")
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
                        url = " Server Name Indication (SNI): " + \
                            server_names[0].servername.decode()
                        url_list.append(url)
    return url_list


def extract_images_from_http(pcap_packets):
    # I'd like to make this more readable
    image_count = 0
    image_paths = []
    try:
        packets = rdpcap(pcap_packets)
        sessions = packets.sessions()
    except AttributeError:
        return image_paths

    for session in sessions.values():
        http_payload = b""
        tcp_packets = []

        for packet in session:
            if packet.haslayer('HTTP'):
                tcp_packets.append(packet)

        for packet in tcp_packets:
            if hasattr(packet[TCP], 'payload'):
                http_payload += bytes(packet[TCP].payload)

        if b"Content-Type: image" in http_payload:
            # Find the start of the image data
            headers_end = http_payload.find(b"\r\n\r\n") + 4
            image_data = http_payload[headers_end:]

            if b"image/jpeg" in http_payload:
                image_extension = "jpg"
            elif b"image/png" in http_payload:
                image_extension = "png"
            elif b"image/gif" in http_payload:
                image_extension = "gif"
            elif b"image/bmp" in http_payload:
                image_extension = "bmp"
            else:
                continue  # Skip unsupported image types

            # Save the image
            # TODO: Use actual image name
            image_path = f"output/images/image_{image_count}.{image_extension}"
            image_paths.append(image_path)
            with open(image_path, "wb") as image_file:
                image_file.write(image_data)
                print(f"Saved: {image_path}")
                image_count += 1
    return image_paths
