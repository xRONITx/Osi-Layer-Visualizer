"""
packet_engine.py — pure Python packet construction, no root required.
"""
import random, struct, socket


def internet_checksum(data: bytes) -> int:
    if len(data) % 2 != 0:
        data += b'\x00'
    total = 0
    for i in range(0, len(data), 2):
        total += (data[i] << 8) + data[i + 1]
    while total >> 16:
        total = (total & 0xFFFF) + (total >> 16)
    return ~total & 0xFFFF


def to_hex(b: bytes) -> str:
    return ' '.join(f'{x:02x}' for x in b)


def build_packet(message, protocol, src_ip, dst_ip, corrupt=False):
    msg   = '' if message is None else str(message)
    proto = (protocol or 'tcp').lower()
    use_osi = proto == 'osi'
    use_tcp = proto in ('tcp', 'http', 'osi')

    # ── L7 Application ───────────────────────────────────────────────────
    if proto == 'http':
        app_bytes = (
            f"GET / HTTP/1.1\r\nHost: {dst_ip}\r\n"
            f"User-Agent: OSI-Visualizer/1.0\r\n"
            f"Content-Length: {len(msg.encode())}\r\n\r\n{msg}"
        ).encode('utf-8')
        app_name, app_field, app_method = "HTTP", "HTTP/1.1", "GET"
        app_desc = ("Application layer formats data as an HTTP/1.1 request. "
                    "Adds method, Host header, Content-Length, and CRLF separators.")
    else:
        app_bytes = msg.encode('utf-8')
        app_name  = "OSI Data" if use_osi else "Raw Data"
        app_field = "OSI" if use_osi else "Raw"
        app_method = "N/A"
        app_desc  = ("Application layer passes raw user data to the layer below. "
                     "No additional headers are added for plain TCP/UDP payloads.")

    # ── L6 Presentation & L5 Session (OSI full mode only) ────────────────
    pres_bytes, sess_bytes = b'', b''
    session_id = session_flags = 0
    if use_osi:
        pres_bytes = struct.pack('!BBBB', 1, 1, 0, 0)   # ver, enc=UTF8, comp, crypt
        session_id    = random.randint(1000, 65000)
        session_flags = 0x12
        sess_bytes    = struct.pack('!HBB', session_id, session_flags, 1)

    # payload seen by transport
    tp_payload = sess_bytes + pres_bytes + app_bytes if use_osi else app_bytes

    # ── L4 Transport ─────────────────────────────────────────────────────
    src_port = random.randint(49152, 65535)
    tcp_csum = tcp_seq = 0
    if use_tcp:
        dst_port = 80
        tcp_seq  = random.randint(1_000_000, 9_999_999)
        dof      = (5 << 12) | 0x018   # offset=5, PSH+ACK
        tcp_raw  = struct.pack('!HHIIHHHH', src_port, dst_port, tcp_seq, 0, dof, 65535, 0, 0)
        pseudo   = (socket.inet_aton(src_ip) + socket.inet_aton(dst_ip) +
                    b'\x00\x06' + struct.pack('!H', len(tcp_raw) + len(tp_payload)))
        tcp_csum = internet_checksum(pseudo + tcp_raw + tp_payload)
        transport_bytes = struct.pack('!HHIIHHHH', src_port, dst_port, tcp_seq, 0, dof, 65535, tcp_csum, 0)
        trans_proto = "TCP"
        trans_desc  = ("Transport layer adds a 20-byte TCP header providing reliable, "
                       "ordered, error-checked delivery. Sequence numbers enable "
                       "reassembly; the checksum detects corruption.")
        trans_fields = {
            "Source port":      str(src_port),
            "Destination port": str(dst_port),
            "Protocol":         "TCP (6)",
            "Sequence number":  str(tcp_seq),
            "Flags":            "PSH, ACK (0x018)",
            "Window size":      "65535 bytes",
            "Checksum":         f"0x{tcp_csum:04x}",
            "Header size":      "20 bytes",
        }
    else:
        dst_port = 53
        udp_len  = 8 + len(tp_payload)
        transport_bytes = struct.pack('!HHHH', src_port, dst_port, udp_len, 0)
        trans_proto = "UDP"
        trans_desc  = ("Transport layer adds an 8-byte UDP header. No connection "
                       "setup or retransmission — minimal overhead for DNS, "
                       "streaming, and real-time protocols.")
        trans_fields = {
            "Source port":      str(src_port),
            "Destination port": str(dst_port),
            "Protocol":         "UDP (17)",
            "Length":           f"{udp_len} bytes",
            "Checksum":         "0x0000 (disabled)",
            "Header size":      "8 bytes",
            "Reliability":      "None — fire and forget",
        }

    # ── L3 Network (IPv4 20 B) ───────────────────────────────────────────
    proto_num   = 6 if use_tcp else 17
    total_ip_len = 20 + len(transport_bytes) + len(tp_payload)
    ip_id       = random.randint(1000, 65000)
    ip_raw      = struct.pack('!BBHHHBBH4s4s',
                              0x45, 0, total_ip_len, ip_id,
                              0x4000, 64, proto_num, 0,
                              socket.inet_aton(src_ip), socket.inet_aton(dst_ip))
    ip_csum = internet_checksum(ip_raw)
    if corrupt:
        ip_csum ^= 0xFFFF
    network_bytes = struct.pack('!BBHHHBBH4s4s',
                                0x45, 0, total_ip_len, ip_id,
                                0x4000, 64, proto_num, ip_csum,
                                socket.inet_aton(src_ip), socket.inet_aton(dst_ip))
    net_fields = {
        "Version":        "4 (IPv4)",
        "IHL":            "5 (20 bytes)",
        "Source IP":      src_ip,
        "Destination IP": dst_ip,
        "TTL":            "64 hops",
        "Protocol":       f"{proto_num} ({'TCP' if use_tcp else 'UDP'})",
        "Total length":   f"{total_ip_len} bytes",
        "Flags":          "DF — Don't Fragment",
        "Checksum":       f"0x{ip_csum:04x}" + (" ⚠ CORRUPTED" if corrupt else " (valid)"),
    }

    # ── L2 Data Link (Ethernet II 14 B) ──────────────────────────────────
    dst_mac = bytes([0xff]*6)
    raw_mac = random.randint(0, 2**48 - 1) & ~(1 << 40)
    src_mac = raw_mac.to_bytes(6, 'big')
    dl_bytes = dst_mac + src_mac + struct.pack('!H', 0x0800)
    src_mac_str  = ':'.join(f'{b:02x}' for b in src_mac)
    frame_total  = len(dl_bytes) + total_ip_len

    # ── L1 Physical (preamble + SFD) ─────────────────────────────────────
    preamble  = b'\x55' * 7 + b'\xd5'
    total_bits = (len(preamble) + frame_total) * 8

    raw_frame = dl_bytes + network_bytes + transport_bytes + tp_payload

    # ── Cumulative hex — each layer shows from its header outward ─────────
    # Header bytes are always at position 0 in cumulative, so the frontend
    # can highlight bytes [0 .. header_size-1] correctly.
    cum_app  = app_bytes
    cum_pres = pres_bytes + app_bytes           if use_osi else b''
    cum_sess = sess_bytes + pres_bytes + app_bytes if use_osi else b''
    cum_trans = transport_bytes + tp_payload
    cum_net   = network_bytes + transport_bytes + tp_payload
    cum_dl    = dl_bytes + network_bytes + transport_bytes + tp_payload
    cum_phys  = preamble + dl_bytes + network_bytes + transport_bytes + tp_payload

    # ── Layer list (Application → Physical) ──────────────────────────────
    layers = [{
        "layer_number":   7,
        "layer_name":     "Application",
        "protocol":       app_name,
        "header_hex":     to_hex(app_bytes),
        "header_size":    len(app_bytes),
        "cumulative_hex": to_hex(cum_app),
        "color":          "#6366f1",
        "corrupt":        False,
        "description":    app_desc,
        "fields": {
            "Protocol":     app_field,
            "Method":       app_method,
            "Host":         dst_ip,
            "Payload":      msg[:48] + ("…" if len(msg) > 48 else ""),
            "Payload size": f"{len(app_bytes)} bytes",
            "Encoding":     "UTF-8",
        },
    }]

    if use_osi:
        layers.append({
            "layer_number":   6,
            "layer_name":     "Presentation",
            "protocol":       "Syntax/Encoding",
            "header_hex":     to_hex(pres_bytes),
            "header_size":    len(pres_bytes),
            "cumulative_hex": to_hex(cum_pres),
            "color":          "#38bdf8",
            "corrupt":        False,
            "description":    ("Presentation layer negotiates syntax, character encoding, "
                               "compression, and encryption between communicating systems."),
            "fields": {
                "Version":     "1",
                "Encoding":    "UTF-8 (0x01)",
                "Compression": "None (0x00)",
                "Encryption":  "None (0x00)",
                "Header size": f"{len(pres_bytes)} bytes",
            },
        })
        layers.append({
            "layer_number":   5,
            "layer_name":     "Session",
            "protocol":       "Session Control",
            "header_hex":     to_hex(sess_bytes),
            "header_size":    len(sess_bytes),
            "cumulative_hex": to_hex(cum_sess),
            "color":          "#facc15",
            "corrupt":        False,
            "description":    ("Session layer establishes, maintains, and terminates "
                               "communication sessions. Manages dialog control and "
                               "synchronization checkpoints."),
            "fields": {
                "Session ID":    str(session_id),
                "Control flags": f"0x{session_flags:02x} (data + full-duplex)",
                "State":         "Established",
                "Keepalive":     "30 s",
                "Header size":   f"{len(sess_bytes)} bytes",
            },
        })

    layers.extend([
        {
            "layer_number":   4,
            "layer_name":     "Transport",
            "protocol":       trans_proto,
            "header_hex":     to_hex(transport_bytes),
            "header_size":    len(transport_bytes),
            "cumulative_hex": to_hex(cum_trans),
            "color":          "#10b981",
            "corrupt":        False,
            "description":    trans_desc,
            "fields":         trans_fields,
        },
        {
            "layer_number":   3,
            "layer_name":     "Network",
            "protocol":       "IPv4",
            "header_hex":     to_hex(network_bytes),
            "header_size":    len(network_bytes),
            "cumulative_hex": to_hex(cum_net),
            "color":          "#f97316",
            "corrupt":        corrupt,
            "description":    ("Network layer routes packets across multiple networks "
                               "using logical IP addressing. TTL prevents routing loops. "
                               "The checksum protects the header from corruption."),
            "fields":         net_fields,
        },
        {
            "layer_number":   2,
            "layer_name":     "Data Link",
            "protocol":       "Ethernet II",
            "header_hex":     to_hex(dl_bytes),
            "header_size":    len(dl_bytes),
            "cumulative_hex": to_hex(cum_dl),
            "color":          "#f43f5e",
            "corrupt":        False,
            "description":    ("Data link layer frames data for local network delivery "
                               "using MAC addresses. EtherType 0x0800 signals an IPv4 "
                               "payload. Broadcast destination reaches all local hosts."),
            "fields": {
                "Destination MAC": "ff:ff:ff:ff:ff:ff (Broadcast)",
                "Source MAC":      src_mac_str,
                "EtherType":       "0x0800 — IPv4",
                "Header size":     "14 bytes",
                "Frame total":     f"{frame_total} bytes",
            },
        },
        {
            "layer_number":   1,
            "layer_name":     "Physical",
            "protocol":       "Ethernet Bits",
            "header_hex":     to_hex(preamble),
            "header_size":    len(preamble),
            "cumulative_hex": to_hex(cum_phys),
            "color":          "#a8a29e",
            "corrupt":        False,
            "description":    ("Physical layer transmits raw bits over the medium. "
                               "The 7-byte preamble (0x55…) synchronises sender and "
                               "receiver clocks. SFD byte 0xD5 marks the frame start."),
            "fields": {
                "Preamble":   "7 × 0x55 (alternating 1/0 bits)",
                "SFD":        "0xD5 — Start Frame Delimiter",
                "Encoding":   "Manchester / NRZ-I",
                "Medium":     "Copper / Fibre (Ethernet)",
                "Bit rate":   "1 Gbps (nominal)",
                "Total bits": f"{total_bits} bits",
            },
        },
    ])

    return layers, raw_frame
