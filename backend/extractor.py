from scapy.all import rdpcap, TCP
from base64 import b64decode
import re

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
        if packet.haslayer(TCP) and packet.haslayer(Raw):
            if packet[TCP].dport == 21 or packet[TCP].sport == 21:
                payload = packet[Raw].load.decode(errors='ignore')
                if 'USER' in payload:
                    ftp_login_list.append(payload)
                elif 'PASS' in payload:
                    ftp_pass_list.append(payload)
    return list(zip(ftp_login_list, ftp_pass_list))

def infer_file_type(data):
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
                # Check for FTP data on non-standard ports (not control port 21)
                if packet[TCP].dport != 21 and packet[TCP].sport != 21 and packet.haslayer(Raw):
                    payload_data += packet[Raw].load
            except:
                continue

        if payload_data:
            # Determine file type and extension
            file_type = infer_file_type(payload_data)
            filename = str_to_filename(f"output/files/extracted_file_from_ftp_session_{session}.{file_type}")
            files_paths.append(filename)

            # Save the extracted file
            with open(filename, "wb") as f:
                f.write(payload_data)
                print(f"File saved: {filename}")
    return files_paths


def str_to_filename(s):
    s = str(s).strip().replace(" ", "_")
    s = re.sub(r"(?u)[^-\w.]", "", s)
    if s in {"", ".", ".."}:
        return"_"
    return s