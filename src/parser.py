import pandas as pd
import re

def parse_tcpdump(filepath="tcpdump.txt"):
    records = []

    with open(filepath, "r", encoding="utf-8") as f:
        for line in f:
            # Same as your original regex, PLUS a capture group for the
            # flags bracket (e.g. "[SYN, ACK]") that sits between the
            # port pair and "Len=". Made optional with (?:...)? since
            # UDP lines / some TCP lines won't always have it.
            match = re.search(
                r"\s*(\d+\.\d+)\s+([\da-fA-F\.:]+)\s+→\s+([\da-fA-F\.:]+)\s+(TCP|UDP)\s+\d+\s+"
                r"(\d+)\s+→\s+(\d+)\s*(?:\[([^\]]*)\])?.*Len=(\d+)",
                line
            )
            if match:
                time, src_ip, dst_ip, proto, src_port, dst_port, flags, length = match.groups()
                app = "HTTPS" if int(dst_port) == 443 else "OTHER"

                # TCP options - only present on handshake packets (SYN/SYN-ACK),
                # never on a plain ACK. This is the real signal that
                # distinguishes them, since length/ports alone can't.
                win_match = re.search(r"Win=(\d+)", line)
                mss_match = re.search(r"MSS=(\d+)", line)

                records.append({
                    "time": float(time),
                    "src_ip": src_ip,
                    "dst_ip": dst_ip,
                    "protocol": proto,
                    "src_port": int(src_port),
                    "dst_port": int(dst_port),
                    "flags": flags if flags else "",
                    "length": int(length),
                    "application": app,
                    "win_size": int(win_match.group(1)) if win_match else 0,
                    "has_mss": bool(mss_match),
                    "has_sack_perm": "SACK_PERM" in line,
                    "has_ws": bool(re.search(r"\bWS=\d+", line)),
                })

    return pd.DataFrame(records)


if __name__ == "__main__":
    # Quick test against a few synthetic tshark-style lines, covering:
    # - a line WITH flags (typical TCP)
    # - a line with multiple flags
    # - a line with NO flags bracket (should not crash, flags="")
    sample_lines = """1.234567 192.168.1.5 → 8.8.8.8 TCP 66 51234 → 443 [SYN] Seq=0 Win=64240 Len=0
2.345678 192.168.1.5 → 8.8.8.8 TCP 66 51234 → 443 [SYN, ACK] Seq=0 Ack=1 Win=64240 Len=0
3.456789 192.168.1.5 → 1.1.1.1 UDP 74 51235 → 53 Len=32
"""
    with open("sample_tcpdump.txt", "w") as f:
        f.write(sample_lines)

    df = parse_tcpdump("sample_tcpdump.txt")
    print(df)
    print("\ncolumns:", list(df.columns))
