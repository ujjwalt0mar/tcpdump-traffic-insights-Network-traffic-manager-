"""
sni_extractor.py

tshark's default text output already decodes the TLS SNI for us
(e.g. "Client Hello (SNI=google.com)") - so instead of manually
parsing raw TLS bytes (needed for a live scapy capture), we can
just regex it straight out of the saved capture text file.

This is far simpler and more reliable than the raw-packet SNI
parser in service_identifier.py, and should be the PRIMARY path
for identifying services when working from a saved tshark capture.
The raw-packet parser in service_identifier.py stays useful only
for live scapy-based capture, which doesn't have tshark's decoding.
"""

import re
import pandas as pd

SNI_PATTERN = re.compile(
    r"\s*(\d+\.\d+)\s+([\da-fA-F\.:]+)\s+→\s+([\da-fA-F\.:]+).*Client Hello \(SNI=([^\)]+)\)"
)


def extract_sni_records(filepath="tcpdump.txt"):
    """
    Returns a DataFrame of (time, src_ip, dst_ip, sni) - one row per
    TLS Client Hello line found in the capture file.
    """
    records = []
    with open(filepath, "r", encoding="utf-8") as f:
        for line in f:
            match = SNI_PATTERN.search(line)
            if match:
                time, src_ip, dst_ip, sni = match.groups()
                records.append({
                    "time": float(time),
                    "src_ip": src_ip,
                    "dst_ip": dst_ip,
                    "sni": sni,
                })
    return pd.DataFrame(records)


def build_ip_to_service_map(sni_df):
    """
    Since a Client Hello's dst_ip IS the service being contacted,
    this builds a simple {dst_ip: sni} lookup you can join against
    your main parsed packet DataFrame to label every packet for that
    IP - even ones that aren't the Client Hello line itself.
    """
    return dict(zip(sni_df["dst_ip"], sni_df["sni"]))


if __name__ == "__main__":
    sample = """    8 1.704209800 2401:4900:8843:e74:71e7:e332:48d7:6d57 → 2404:6800:4002:818::200e TLSv1.2 531 Client Hello (SNI=google.com)
   23 1.794686900  192.168.1.7 → 20.207.73.82 TLSv1.2 511 Client Hello (SNI=github.com)
"""
    with open("sni_sample.txt", "w") as f:
        f.write(sample)

    df = extract_sni_records("sni_sample.txt")
    print(df)
    print()
    print("IP -> service map:", build_ip_to_service_map(df))
