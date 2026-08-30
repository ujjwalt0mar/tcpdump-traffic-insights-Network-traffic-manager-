"""
features.py

Engineers features for the TCP flag classifier - vectorized (operates
on the whole parsed DataFrame at once, not row-by-row like the old
version).

IMPORTANT - why this looks different from the previous version:
The earlier pipeline predicted `application` (HTTPS/OTHER) using
`dst_port` as a feature, where `application` was itself DEFINED as
`dst_port == 443`. That's label leakage - the model doesn't learn
anything, it just re-derives a rule already written in the parser.
It's why the old confusion matrix showed a suspicious 100% accuracy.

This version predicts the actual TCP flag combination (SYN, ACK,
SYN-ACK, FIN, RST, PSH-ACK, etc.) using features that don't trivially
encode the answer:
  - protocol (TCP/UDP)
  - packet length
  - port CATEGORY (well-known/registered/dynamic) instead of the
    exact port number - this preserves useful signal (e.g. "talking
    to a well-known port" correlates with SYN on connection open)
    without letting the model just memorize "port 443 = X"
  - direction (outbound/inbound, based on private IP ranges)

Exact port number is deliberately excluded as a feature.
"""

import pandas as pd


FLAG_CLASSES = ["SYN", "SYN-ACK", "ACK", "FIN", "FIN-ACK", "RST", "PSH-ACK", "OTHER"]


def categorize_port(port):
    """Well-known (0-1023) / registered (1024-49151) / dynamic (49152-65535)."""
    if pd.isna(port):
        return "unknown"
    port = int(port)
    if port < 1024:
        return "well_known"
    elif port < 49152:
        return "registered"
    else:
        return "dynamic"


def normalize_flags(flags_str):
    """
    Collapse a raw flags string like 'SYN, ACK' into one of the
    canonical FLAG_CLASSES. This becomes the model's target label.
    """
    if not isinstance(flags_str, str) or flags_str.strip() == "":
        return "OTHER"

    flags_str = flags_str.upper()
    has_syn = "SYN" in flags_str
    has_ack = "ACK" in flags_str
    has_fin = "FIN" in flags_str
    has_rst = "RST" in flags_str
    has_psh = "PSH" in flags_str

    if has_rst:
        return "RST"
    if has_syn and has_ack:
        return "SYN-ACK"
    if has_syn:
        return "SYN"
    if has_fin and has_ack:
        return "FIN-ACK"
    if has_fin:
        return "FIN"
    if has_psh and has_ack:
        return "PSH-ACK"
    if has_ack:
        return "ACK"
    return "OTHER"


def is_private_ip(ip_str):
    """Simple RFC1918 private range check for direction inference."""
    if not isinstance(ip_str, str):
        return False
    return (
        ip_str.startswith("192.168.")
        or ip_str.startswith("10.")
        or any(ip_str.startswith(f"172.{i}.") for i in range(16, 32))
    )


def add_flow_position_features(df, time_col="time", src_ip_col="src_ip",
                                dst_ip_col="dst_ip", src_port_col="src_port",
                                dst_port_col="dst_port"):
    """
    Adds per-flow temporal context: where a packet sits within its TCP
    connection's lifetime. A flow is identified by its unordered
    endpoint pair (so both directions of the same connection group
    together) - src_ip:src_port <-> dst_ip:dst_port, direction-agnostic.

    This targets a specific gap: nothing about a single packet's static
    fields (length, ports, options) says whether it's early or late in
    a connection's life - but FIN-ACK, by definition, happens near the
    END of a flow, while plain ACK happens throughout. Packet position
    and elapsed time within the flow is genuine signal for that.
    """
    df = df.copy()

    # Direction-agnostic flow key: sort the two endpoints so both
    # directions of one connection map to the same flow_id.
    endpoint_a = df[src_ip_col].astype(str) + ":" + df[src_port_col].astype(str)
    endpoint_b = df[dst_ip_col].astype(str) + ":" + df[dst_port_col].astype(str)
    df["_flow_id"] = [
        tuple(sorted([a, b])) for a, b in zip(endpoint_a, endpoint_b)
    ]

    df = df.sort_values(time_col)
    grouped = df.groupby("_flow_id")[time_col]

    df["packet_index_in_flow"] = grouped.cumcount()
    df["time_since_flow_start"] = df[time_col] - grouped.transform("min")
    df["time_since_prev_in_flow"] = grouped.diff().fillna(0)

    return df.drop(columns=["_flow_id"])


def engineer_features(df, src_ip_col="src_ip", dst_ip_col="dst_ip",
                       src_port_col="src_port", dst_port_col="dst_port",
                       protocol_col="protocol", length_col="length",
                       flags_col="flags", time_col="time"):
    """
    Takes parser.py's output DataFrame, returns (X, y):
      X - feature DataFrame, ready for one-hot encoding + model training
      y - target Series (canonical flag class per row)
    """
    # Flow-position features need the full df (grouped by connection)
    # computed BEFORE we subset columns.
    if time_col in df.columns:
        df = add_flow_position_features(df, time_col, src_ip_col,
                                         dst_ip_col, src_port_col, dst_port_col)

    out = pd.DataFrame(index=df.index)

    out["protocol"] = df[protocol_col]
    out["length"] = df[length_col]
    out["src_port_category"] = df[src_port_col].apply(categorize_port)
    out["dst_port_category"] = df[dst_port_col].apply(categorize_port)
    out["direction"] = df[src_ip_col].apply(
        lambda ip: "outbound" if is_private_ip(ip) else "inbound"
    )

    # TCP options - genuine protocol-level signal (not label leakage):
    # these fields exist because SYN/SYN-ACK negotiate connection
    # parameters and plain ACK/PSH-ACK packets don't repeat them.
    if "win_size" in df.columns:
        out["win_size"] = df["win_size"]
        out["has_mss"] = df["has_mss"].astype(int)
        out["has_sack_perm"] = df["has_sack_perm"].astype(int)
        out["has_ws"] = df["has_ws"].astype(int)

    # Flow-position: distinguishes teardown (FIN-ACK, late in flow)
    # from steady-state (ACK, throughout the flow).
    if "packet_index_in_flow" in df.columns:
        out["packet_index_in_flow"] = df["packet_index_in_flow"]
        out["time_since_flow_start"] = df["time_since_flow_start"]
        out["time_since_prev_in_flow"] = df["time_since_prev_in_flow"]

    y = df[flags_col].apply(normalize_flags)

    return out, y


def encode_features(X):
    """One-hot encode categorical columns for sklearn."""
    return pd.get_dummies(X, columns=["protocol", "src_port_category",
                                       "dst_port_category", "direction"])
