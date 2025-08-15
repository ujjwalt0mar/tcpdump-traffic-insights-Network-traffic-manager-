# features.py
import pandas as pd
import numpy as np
from sklearn.preprocessing import LabelEncoder

def enrich_features(df):
    # Encode TCP flag strings
    df['flag_encoded'] = LabelEncoder().fit_transform(df['flags'])

    # Time binning & rounding
    df['time_bin'] = pd.cut(df['time'], bins=5)
    df['time_rounded'] = df['time'].round()

    # One-hot encode key TCP flags
    for flag in ['SYN', 'ACK', 'FIN', 'RST', 'PSH']:
        df[flag] = df['flags'].apply(lambda x: int(flag in x))

    # Port category classification
    df['src_port_cat_unknown'] = df['src_port'].apply(lambda x: not str(x).isdigit())
    df['dst_port'] = pd.to_numeric(df['dst_port'], errors='coerce')
    df['dst_port_cat_dynamic'] = df['dst_port'].apply(lambda x: 1024 <= x <= 49151 if pd.notnull(x) else False)
    df['dst_port_cat_well_known'] = df['dst_port'].apply(lambda x: 0 <= x <= 1023 if pd.notnull(x) else False)
    df['dst_port_cat_unknown'] = df['dst_port'].isnull()

    # Estimate packet direction based on IP
    def is_private(ip):
        return ip.startswith("192.168") or ip.startswith("10.") or ip.startswith("172.")

    df['direction_inbound'] = df.apply(lambda x: is_private(str(x['dst'])) and not is_private(str(x['src'])), axis=1)
    df['direction_outbound'] = df.apply(lambda x: is_private(str(x['src'])) and not is_private(str(x['dst'])), axis=1)
    df['direction_external'] = df.apply(lambda x: not is_private(str(x['src'])) and not is_private(str(x['dst'])), axis=1)

    # Add time-of-day category (e.g., night = before 6 AM or after 8 PM)
    df['timeofday_night'] = df['time'].apply(lambda t: t % 86400 < 21600 or t % 86400 > 72000)

    return df
