"""
run_service_identification.py

Tags every destination IP in your capture with a service/company
name, using SNI (primary, most accurate) and IP-range/reverse-DNS
(fallback for everything SNI didn't catch).

Run from the project root:
    python src/run_service_identification.py
"""

import sys
import os
import pandas as pd

sys.path.insert(0, os.path.dirname(__file__))
from parser import parse_tcpdump
from sni_extractor import extract_sni_records, build_ip_to_service_map
from service_identifier import ServiceIdentifier

DATA_PATH = os.path.join("data", "tcpdump_combined.txt")

if __name__ == "__main__":
    print(f"Parsing {DATA_PATH} ...")
    df = parse_tcpdump(DATA_PATH)
    print(f"Total packets: {len(df)}")
    print(f"Unique destination IPs: {df['dst_ip'].nunique()}\n")

    print("Extracting SNI (primary source)...")
    sni_df = extract_sni_records(DATA_PATH)
    ip_to_sni = build_ip_to_service_map(sni_df)
    print(f"Identified {len(ip_to_sni)} IPs via SNI\n")

    print("Loading IP-range data for fallback lookup (needs internet access)...")
    identifier = ServiceIdentifier()
    identifier.load_ip_ranges()

    all_dst_ips = df["dst_ip"].unique()
    service_map = {}
    for ip in all_dst_ips:
        service_map[ip] = ip_to_sni.get(ip) or identifier.identify_from_ip(ip)

    df["service"] = df["dst_ip"].map(service_map)

    identified = sum(1 for v in service_map.values() if v not in ("Unknown", "Invalid IP"))
    print(f"\nIdentified {identified} of {len(all_dst_ips)} destination IPs "
          f"({identified/len(all_dst_ips)*100:.0f}%)\n")

    print("=== Service breakdown (by packet count) ===")
    print(df["service"].value_counts().head(20))

    os.makedirs("data", exist_ok=True)
    df.to_csv(os.path.join("data", "tagged_with_services.csv"), index=False)
    print("\nSaved full tagged dataset to data/tagged_with_services.csv")
