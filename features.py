def engineer_features(packet):
    features = {
        "is_syn": int("SYN" in packet["flags"]),
        "is_ack": int("ACK" in packet["flags"]),
        "is_rst": int("RST" in packet["flags"]),
        "is_fin": int("FIN" in packet["flags"]),
        "direction": "outbound" if packet["src_ip"].startswith("192.168") else "inbound"
    }
    return features
