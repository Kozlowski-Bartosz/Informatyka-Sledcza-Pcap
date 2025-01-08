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
