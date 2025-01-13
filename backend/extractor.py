from scapy.all import rdpcap, TCP

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
        tcp_packets = [packet for packet in session if packet.haslayer('HTTP')]

        for packet in tcp_packets:
            if hasattr(packet[TCP], 'payload'):
                http_payload += bytes(packet[TCP].payload)

        if b"Content-Type: image" in http_payload:
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
