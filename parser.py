import pandas as pd
import re

records = []

with open("tcpdump.txt", "r", encoding="utf-8") as f:
    for line in f:
        # Regex to match: time, source IP, dest IP, protocol, source port, dest port, and packet length
        match = re.search(
            r"\s*(\d+\.\d+)\s+([\da-fA-F\.:]+)\s+→\s+([\da-fA-F\.:]+)\s+(TCP|UDP)\s+\d+\s+(\d+)\s+→\s+(\d+).*Len=(\d+)",
            line
        )
        if match:
            time, src_ip, dst_ip, proto, src_port, dst_port, length = match.groups()
            app = "HTTPS" if int(dst_port) == 443 else "OTHER"
            records.append({
                "time": float(time),
                "src_ip": src_ip,
                "dst_ip": dst_ip,
                "protocol": proto,
                "src_port": int(src_port),
                "dst_port": int(dst_port),
                "length": int(length),
                "application": app
            })

# Create DataFrame
df = pd.DataFrame(records)
print(df.head())
