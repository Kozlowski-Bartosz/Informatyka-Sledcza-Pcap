from scapy.all import rdpcap, TCP
from scapy.layers import http
from base64 import b64decode
import re

# list taken from net-creds, which in turn based it off of PCredz
USERFIELDS = ['log','login', 'wpname', 'ahd_username', 'unickname', 'nickname', 'user', 'user_name',
             'alias', 'pseudo', 'email', 'username', '_username', 'userid', 'form_loginname', 'loginname',
             'login_id', 'loginid', 'session_key', 'sessionkey', 'pop_login', 'uid', 'id', 'user_id', 'screename',
             'uname', 'ulogin', 'acctname', 'account', 'member', 'mailaddress', 'membername', 'login_username',
             'login_email', 'loginusername', 'loginemail', 'uin', 'sign-in', 'usuario']
PASSFIELDS = ['ahd_password', 'pass', 'password', '_password', 'passwd', 'session_password', 'sessionpassword', 
             'login_password', 'loginpassword', 'form_pw', 'pw', 'userpassword', 'pwd', 'upassword', 'login_password'
             'passwort', 'passwrd', 'wppassword', 'upasswd','senha','contrasena']

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

        images_found = http_payload.count(b"Content-Type: image")

        for i in range(images_found):
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

            # Search for the next image in session
            http_payload = http_payload[http_payload.find(b"\r\n\r\n") + 4:]

    return image_paths

def extract_authentication_data_from_http(pcap_packets):
    type_list, cred_list = [], []

    try:
        packets = rdpcap(pcap_packets)
    except AttributeError:
        return type_list, cred_list
    
    http_packets = [packet for packet in packets if packet.haslayer('HTTP')]

    for packet in http_packets:
        http_pkt = packet.getlayer("HTTP Request")
        if http_pkt:
            auth = http_pkt.Authorization
            if auth:
                print(auth)
                if auth.startswith(b"Basic"):
                    auth = b64decode(auth[6:]).decode()
                    cred_list.append(auth)
                elif auth.startswith(b"Digest"):
                    print(f"Digest Auth: {auth}")
                    type_list.append("Digest")
                    cred_list.append(auth)



    # for ufield in USERFIELDS:
    #     username = re.search('(%s=[^&]+)' % ufield, body, re.IGNORECASE)
    #     if username:
    #         username_list.append(username.group())
    
    # for pfield in PASSFIELDS:
    #     password = re.search('(%s=[^&]+)' % pfield, body, re.IGNORECASE)
    #     if password:
    #         password_list.append(password.group())
    return list(zip(type_list, cred_list))