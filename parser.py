def parse_tcpdump_line(line):
    parts = line.split()
    return {
        "time": float(parts[1]),
        "src_ip": parts[2],
        "dst_ip": parts[4],
        "protocol": parts[5],
        "src_port": parts[6],
        "dst_port": parts[8],
        "flags": parts[9].strip("[]")
    }
