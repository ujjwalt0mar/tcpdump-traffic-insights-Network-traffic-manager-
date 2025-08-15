import pandas as pd
import re

def parse_tcpdump_file(file_path):
    rows = []

    patterns = [
        # TCP/UDP with optional [TCP ...] annotation before ports and with flags
        re.compile(
            r"^\s*\d+\s+([\d\.]+)\s+(\S+)\s+→\s+(\S+)\s+(TCP|UDP)(?: \[[^\]]+\])?\s+\d+\s+(\d+)\s+→\s+(\d+)\s+\[([^\]]*)\]"
        ),
        # TCP/UDP without flags
        re.compile(
            r"^\s*\d+\s+([\d\.]+)\s+(\S+)\s+→\s+(\S+)\s+(TCP|UDP)(?: \[[^\]]+\])?\s+\d+\s+(\d+)\s+→\s+(\d+)"
        ),
        # TLS/SSL with ports
        re.compile(
            r"^\s*\d+\s+([\d\.]+)\s+(\S+)\s+→\s+(\S+)\s+(TLSv\d\.\d|SSL)\s+\d+\s+(\d+)\s+→\s+(\d+)\s*(?:\[([^\]]*)\])?"
        ),
        # TLS/SSL without ports
        re.compile(
            r"^\s*\d+\s+([\d\.]+)\s+(\S+)\s+→\s+(\S+)\s+(TLSv\d\.\d|SSL)\s+(\d+)\s+(.+)$"
        ),
    ]

    with open(file_path, "r", encoding="utf-8", errors="replace") as f:
        for line in f:
            line = line.replace("â†’", "→").strip()
            matched = False

            for pattern in patterns:
                match = pattern.match(line)
                if match:
                    matched = True
                    groups = match.groups()

                    if pattern == patterns[0]:  # TCP/UDP with flags
                        time, src, dst, proto, src_port, dst_port, flags = groups
                        app_proto = None
                    elif pattern == patterns[1]:  # TCP/UDP without flags
                        time, src, dst, proto, src_port, dst_port = groups
                        flags = None
                        app_proto = None
                    elif pattern == patterns[2]:  # TLS/SSL with ports
                        time, src, dst, app_proto, src_port, dst_port, flags = groups
                        proto = "TCP"
                    elif pattern == patterns[3]:  # TLS/SSL without ports
                        time, src, dst, app_proto, length, desc = groups
                        proto = "TCP"
                        src_port = None
                        dst_port = None
                        flags = None

                    rows.append({
                        "time": float(time),
                        "src": src,
                        "dst": dst,
                        "protocol": proto,
                        "app_protocol": app_proto,
                        "src_port": int(src_port) if src_port else None,
                        "dst_port": int(dst_port) if dst_port else None,
                        "flags": flags,
                    })
                    break

            # Fallback: capture at least time, src, dst
            if not matched:
                fallback_match = re.match(
                    r"^\s*\d+\s+([\d\.]+)\s+(\S+)\s+→\s+(\S+)", line
                )
                if fallback_match:
                    time, src, dst = fallback_match.groups()
                    rows.append({
                        "time": float(time),
                        "src": src,
                        "dst": dst,
                        "protocol": "OTHER",
                        "app_protocol": None,
                        "src_port": None,
                        "dst_port": None,
                        "flags": None,
                    })

    return pd.DataFrame(rows)


# Example usage
df = parse_tcpdump_file("tcpdump.txt")
print(f"Parsed {len(df)} / 133 lines ({len(df)/133:.1%})")
print(df.tail())
