import pandas as pd
import re

def parse_tcpdump_file(file_path):
    rows = []
    
    with open(file_path, 'r', encoding="utf-8", errors="replace") as f:
        for line in f:
            # Fix arrow symbol
            line = line.replace("â†’", "→").strip()

            # Match TCP or UDP packets (IPv4 or IPv6)
            match = re.match(
                r"^\s*\d+\s+([\d\.]+)\s+"         # Time
                r"(\S+)\s+→\s+(\S+)\s+"           # Src → Dst
                r"(TCP|UDP)\s+\d+\s+"             # Protocol + length
                r"(\d+)\s+→\s+(\d+)\s*"            # Src port → Dst port
                r"(?:\[([^\]]*)\])?",              # Optional [FLAGS]
                line
            )

            if match:
                time, src, dst, proto, src_port, dst_port, flags = match.groups()
                flags = flags or ""

                # Extract optional Seq, Ack, Win, Len
                seq_match = re.search(r"Seq=(\d+)", line)
                ack_match = re.search(r"Ack=(\d+)", line)
                win_match = re.search(r"Win=(\d+)", line)
                len_match = re.search(r"Len=(\d+)", line)

                rows.append({
                    "time": float(time),
                    "src": src,
                    "dst": dst,
                    "protocol": proto,
                    "src_port": int(src_port),
                    "dst_port": int(dst_port),
                    "flags": flags,
                    "seq": int(seq_match.group(1)) if seq_match else None,
                    "ack": int(ack_match.group(1)) if ack_match else None,
                    "win": int(win_match.group(1)) if win_match else None,
                    "length": int(len_match.group(1)) if len_match else None
                })
    
    return pd.DataFrame(rows)