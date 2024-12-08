# Console interface. To be removed in future versions.

import argparse
import backend.pcap_reader as pcap_reader

def main():
    parser = argparse.ArgumentParser(description="Filter pcap file")
    parser.add_argument("pcap_file", help="Pcap filepath")
    parser.add_argument("--ip", help="IP address to filter by")
    parser.add_argument("--port", type=int, help="Port to filter by")
    parser.add_argument("--protocol", choices=['tcp', 'udp', 'icmp'], help="Protocol to filter by")
    args = parser.parse_args()

    pcap_reader.read_packets(args)

if __name__ == "__main__":
    main()