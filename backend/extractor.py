from scapy.all import rdpcap, TCP
from base64 import b64decode

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