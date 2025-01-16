from scapy.all import rdpcap, TCP, load_layer
from scapy.layers import http
from scapy.layers.tls.handshake import TLSClientHello
from scapy.layers.tls.extensions import TLS_Ext_ServerName
from base64 import b64decode
import re


def extract_https_requests(pcap_packets):
    load_layer("tls")
    url_list = []
    try:
        packets = rdpcap(pcap_packets)
    except AttributeError:
        return url_list

    for packet in packets:
        if packet.haslayer(http.HTTPRequest):
            http_layer = packet.getlayer(http.HTTPRequest)
            url = ('\n HTTP request: {}{}'.format(
                http_layer.fields['Host'].decode('utf-8'),
                http_layer.fields['Path'].decode('utf-8')))
            url_list.append(url)
        elif packet.haslayer(TLSClientHello):
            exts = packet[TLSClientHello].ext
            for ext in exts:
                if isinstance(ext, TLS_Ext_ServerName):
                    server_names = ext.servernames
                    if server_names:
                        url = f" HTTPS request (SNI): {server_names[0].servername.decode()}"
                        url_list.append(url)
    return url_list


def extract_images_from_http(pcap_packets):
    image_count = 0
    image_paths = []
    try:
        packets = rdpcap(pcap_packets)
        sessions = packets.sessions()
    except AttributeError:
        return image_paths

    for session in sessions.values():
        http_payload = b""
        http_packets = [packet for packet in session if packet.haslayer('HTTP')]

        for packet in http_packets:
            if hasattr(packet[TCP], 'payload'):
                http_payload += bytes(packet[TCP].payload)

        payload_start = http_payload.find(b"Content-Type: image")
        http_payload = http_payload[payload_start:]
        images_found = http_payload.count(b"Content-Type: image")

        for i in range(images_found):
            headers_end = http_payload.find(b"\r\n\r\n") + 4
            packet_end = http_payload.find(b"HTTP/", headers_end)
            image_data = http_payload[headers_end:packet_end]

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
            image_path = f"output/images/image_{image_count}.{image_extension}"
            image_paths.append(image_path)
            with open(image_path, "wb") as image_file:
                image_file.write(image_data)
                print(f"Saved: {image_path}")
                image_count += 1

            # Search for the next image in session
            http_payload = http_payload[packet_end:]

    return image_paths

def extract_authentication_data_from_http(pcap_packets):
    type_list, cred_list = [], []
    try:
        packets = rdpcap(pcap_packets)
    except AttributeError:
        return type_list, cred_list
    
    for packet in packets:
        http_pkt = packet.getlayer("HTTP Request")
        if http_pkt:
            auth = http_pkt.Authorization
            if auth:
                print(auth)
                if auth.startswith(b"Basic"):
                    type_list.append("Basic")
                    cred_list.append(b64decode(auth[6:]).decode())
                elif auth.startswith(b"Digest"):
                    print(f"Digest Auth: {auth}")
                    type_list.append("Digest")
                    cred_list.append(auth[7:].decode())

    return list(zip(type_list, cred_list))

def extract_ftp_credentials(pcap_packets):
    ftp_login_list, ftp_pass_list = [], []
    try:
        packets = rdpcap(pcap_packets)
    except AttributeError:
        return ftp_login_list, ftp_pass_list

    for packet in packets:
        if packet.haslayer('TCP') and packet.haslayer('Raw'):
            if packet['TCP'].dport == 21 or packet['TCP'].sport == 21:
                payload = packet['Raw'].load.decode(errors='ignore')
                if 'USER' in payload:
                    ftp_login_list.append(payload)
                elif 'PASS' in payload:
                    ftp_pass_list.append(payload)
    return list(zip(ftp_login_list, ftp_pass_list))

def infer_ftp_file_type(data):
    if data.startswith(b'\xFF\xD8\xFF'):
        return 'jpg'
    elif data.startswith(b'\x89PNG\r\n\x1a\n'):
        return 'png'
    elif data.startswith(b'GIF'):
        return 'gif'
    elif data[0] == 0x25 and data[1] == 0x50 and data[2] == 0x44 and data[3] == 0x46:
        return 'pdf'
    elif data.isascii():
        return 'txt'
    return 'bin'

def extract_file_from_ftp(pcap_packets):
    passive_mode_codes = ['227 Entering Passive Mode', '228 Entering Long Passive Mode', '229 Entering Extended Passive Mode']
    #TODO: Make active mode work
    passive_ports = []
    files_paths = []
    try:
        packets = rdpcap(pcap_packets)
        sessions = packets.sessions()
    except AttributeError:
        return files_paths

    for session in sessions:
        payload_data = b""
        for packet in sessions[session]:
            try:
                if packet.haslayer('TCP') and packet.haslayer('Raw'):
                    payload = bytes(packet[TCP].payload).decode(errors='ignore')
                    if any(code in payload for code in passive_mode_codes):
                        passive_port = re.search(r'\((.*?)\)', payload).group(1).split(',')[-2:]
                        passive_port = int(passive_port[0].strip("|"))
                        passive_ports.append(passive_port)
                        print(f"Passive port: {passive_port}")
                if (packet['TCP'].dport in passive_ports or packet['TCP'].sport in passive_ports) and packet.haslayer('Raw'):
                    payload_data += packet['Raw'].load
            except:
                continue

        if payload_data:
            file_type = infer_ftp_file_type(payload_data)
            filename = str_to_filename(f"extracted_file_from_ftp_session_{session}.{file_type}")
            filepath = f"output/files/{filename}"
            files_paths.append(filepath)

            with open(filepath, "wb") as f:
                f.write(payload_data)
                print(f"File saved: {filepath}")
    return files_paths


def str_to_filename(s):
    s = str(s).strip().replace(" ", "_")
    s = re.sub(r"(?u)[^-\w.]", "", s)
    if s in {"", ".", ".."}:
        return"_"
    return s