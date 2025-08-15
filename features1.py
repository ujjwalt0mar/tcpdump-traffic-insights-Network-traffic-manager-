# ===== FEATURE ENGINEERING =====

def add_features(df):
    # Port category encoding
    def port_category(port):
        if pd.isna(port):
            return "unknown"
        port = int(port)
        if port <= 1023:
            return "well_known"
        elif port <= 49151:
            return "registered"
        else:
            return "dynamic"

    for col in ["src_port", "dst_port"]:
        df[f"{col}_cat"] = df[col].apply(port_category)

    # Direction features (simplified: inbound/outbound/external)
    private_prefixes = ("192.168.", "10.", "172.16.")
    def is_private(ip):
        return any(ip.startswith(p) for p in private_prefixes)

    df["direction_inbound"] = df.apply(lambda r: is_private(r["dst"]) and not is_private(r["src"]), axis=1)
    df["direction_outbound"] = df.apply(lambda r: is_private(r["src"]) and not is_private(r["dst"]), axis=1)
    df["direction_external"] = ~(df["direction_inbound"] | df["direction_outbound"])

    # TCP Flag one-hot encoding
    for flag in ["ACK", "FIN", "PSH", "RST", "SYN"]:
        df[flag] = df["flags"].fillna("").str.contains(flag)

    # Time of day feature (night = 0–6 hrs)
    df["timeofday_night"] = (df["time"] % 86400 < 21600)  # assumes 'time' is seconds in capture

    return df

# Example usage
df = parse_tcpdump_file("tcpdump.txt")
df = add_features(df)
print(f"Parsed {len(df)} / 133 lines ({len(df)/133:.1%})")
print(df.head(10))
