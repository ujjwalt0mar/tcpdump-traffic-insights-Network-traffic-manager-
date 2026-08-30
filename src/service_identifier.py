"""
service_identifier.py

Identifies which service/company a TCP connection is talking to
(e.g. "Amazon", "Google", "Cloudflare") without decrypting traffic.

Strategy (in order of preference):
  1. TLS SNI (Server Name Indication) - unencrypted field in the TLS
     ClientHello that contains the domain being connected to. Only
     works if you're capturing live with scapy (needs the actual
     handshake packet, not just a parsed flag summary).
  2. IP range lookup against published cloud/CDN provider ranges.
  3. Reverse DNS lookup on the destination IP.
  4. Falls back to "Unknown" if nothing matches.

Usage:
    from service_identifier import ServiceIdentifier

    identifier = ServiceIdentifier()
    identifier.load_ip_ranges()  # fetches/caches provider IP ranges

    # Option A: from a live scapy packet (best - has SNI)
    service = identifier.identify_from_packet(pkt)

    # Option B: from just an IP (works on your existing parsed data)
    service = identifier.identify_from_ip("142.250.195.100")

    # Option C: batch-tag an existing pandas DataFrame
    df = identifier.tag_dataframe(df, ip_column="dst_ip")
"""

import ipaddress
import socket
import json
import urllib.request
from functools import lru_cache

_LOCAL_HOSTNAME = socket.gethostname().lower()


class ServiceIdentifier:

    # Public, documented IP ranges. These are the "safe to hardcode"
    # ones that rarely change; AWS/Google publish live JSON feeds we
    # fetch separately in load_ip_ranges().
    STATIC_RANGES = {
        "Cloudflare": [
            "173.245.48.0/20", "103.21.244.0/22", "103.22.200.0/22",
            "103.31.4.0/22", "141.101.64.0/18", "108.162.192.0/18",
            "190.93.240.0/20", "188.114.96.0/20", "197.234.240.0/22",
            "198.41.128.0/17", "162.158.0.0/15", "104.16.0.0/13",
            "104.24.0.0/14", "172.64.0.0/13", "131.0.72.0/22",
        ],
        "Meta": ["157.240.0.0/16", "31.13.24.0/21", "31.13.64.0/18"],
        "Akamai": ["23.32.0.0/11", "23.192.0.0/11", "104.64.0.0/10"],
    }

    # Fetched dynamically (kept in memory once loaded)
    DYNAMIC_SOURCES = {
        "Amazon": "https://ip-ranges.amazonaws.com/ip-ranges.json",
        "Google": "https://www.gstatic.com/ipranges/goog.json",
        "Microsoft/Azure": "https://raw.githubusercontent.com/microsoft/AzurePublicDatacenterIPs/master/azure-ip-ranges.json",
    }

    def __init__(self):
        self._ranges = {}  # service_name -> list[ipaddress.ip_network]
        self._loaded = False
        for service, cidrs in self.STATIC_RANGES.items():
            self._ranges[service] = [ipaddress.ip_network(c) for c in cidrs]

    def load_ip_ranges(self, timeout=5):
        """
        Fetch and cache dynamic IP ranges (AWS/Google/Azure).
        Call this once at startup. Safe to call multiple times;
        only refetches on error you explicitly retry.
        Fails gracefully - if network fetch fails, static ranges
        (Cloudflare/Meta/Akamai) still work.
        """
        # Amazon
        try:
            with urllib.request.urlopen(self.DYNAMIC_SOURCES["Amazon"], timeout=timeout) as r:
                data = json.loads(r.read())
            self._ranges["Amazon"] = [
                ipaddress.ip_network(p["ip_prefix"])
                for p in data.get("prefixes", [])
            ]
        except Exception as e:
            print(f"[service_identifier] Amazon range fetch failed: {e}")

        # Google
        try:
            with urllib.request.urlopen(self.DYNAMIC_SOURCES["Google"], timeout=timeout) as r:
                data = json.loads(r.read())
            self._ranges["Google"] = [
                ipaddress.ip_network(p["ipv4Prefix"])
                for p in data.get("prefixes", []) if "ipv4Prefix" in p
            ]
        except Exception as e:
            print(f"[service_identifier] Google range fetch failed: {e}")

        self._loaded = True

    def identify_from_ip(self, ip_str):
        """
        Return the best-guess service/company name for a destination IP.
        Falls back to reverse DNS, then 'Unknown'.
        """
        try:
            ip = ipaddress.ip_address(ip_str)
        except ValueError:
            return "Invalid IP"

        # Local/private network traffic - not "unknown", just not external
        if ip.is_private:
            return "Local Network"
        if ip.is_multicast:
            return "Multicast"
        if ip.is_loopback:
            return "Loopback"

        # 1. Check known provider ranges
        for service, networks in self._ranges.items():
            for net in networks:
                if ip in net:
                    return service

        # 2. Reverse DNS fallback
        rdns = self._reverse_dns(ip_str)
        if rdns:
            return self._name_from_hostname(rdns)

        return "Unknown"

    def identify_from_packet(self, pkt):
        """
        Given a scapy packet (from live capture), try SNI first
        since it's the most accurate, then fall back to IP lookup.
        Requires scapy's TLS layer (scapy-ssl_tls or scapy's raw
        payload parsing) - falls back silently if unavailable.
        """
        sni = self._extract_sni(pkt)
        if sni:
            return self._name_from_hostname(sni)

        # fall back to IP-based lookup on destination
        try:
            dst_ip = pkt["IP"].dst
            return self.identify_from_ip(dst_ip)
        except Exception:
            return "Unknown"

    def tag_dataframe(self, df, ip_column="dst_ip", new_column="service"):
        """
        Batch-tag an existing pandas DataFrame (e.g. your parsed
        tcpdump output) with a service name column, based on IP only.
        Results are cached per-IP so repeated IPs are fast.
        """
        df[new_column] = df[ip_column].apply(self._cached_identify)
        return df

    # ---- internals ----

    @lru_cache(maxsize=4096)
    def _cached_identify(self, ip_str):
        return self.identify_from_ip(ip_str)

    @staticmethod
    def _reverse_dns(ip_str, timeout=1):
        try:
            socket.setdefaulttimeout(timeout)
            hostname, _, _ = socket.gethostbyaddr(ip_str)
            # Guard: on Windows, a failed/timed-out reverse lookup can
            # silently fall back to LLMNR/NetBIOS and return the LOCAL
            # machine's own hostname instead of correctly failing. If
            # that happens, treat it as "no result" rather than
            # mislabeling every such IP as your own computer.
            if _LOCAL_HOSTNAME and _LOCAL_HOSTNAME in hostname.lower():
                return None
            return hostname
        except Exception:
            return None

    @staticmethod
    def _name_from_hostname(hostname):
        """Map a hostname/SNI string to a friendly service name."""
        hostname = hostname.lower()
        known = {
            "amazonaws.com": "Amazon", "amazon.com": "Amazon",
            "google.com": "Google", "googleusercontent.com": "Google",
            "gmail.com": "Gmail", "youtube.com": "YouTube",
            "facebook.com": "Meta", "instagram.com": "Meta",
            "microsoft.com": "Microsoft", "office.com": "Microsoft",
            "azure.com": "Microsoft/Azure", "windows.net": "Microsoft/Azure",
            "cloudflare.com": "Cloudflare", "akamai.net": "Akamai",
            "apple.com": "Apple", "icloud.com": "Apple",
            "netflix.com": "Netflix", "github.com": "GitHub",
            "1e100.net": "Google",  # Google's actual reverse-DNS domain
        }
        for domain, name in known.items():
            if domain in hostname:
                return name
        return hostname  # unrecognized but still informative

    @staticmethod
    def _extract_sni(pkt):
        """
        Extract SNI from a scapy TCP packet's raw payload by scanning
        for the TLS ClientHello SNI extension. Lightweight manual
        parse (avoids extra scapy TLS layer dependency).
        Returns None if this isn't a ClientHello or SNI isn't present.
        """
        try:
            payload = bytes(pkt["TCP"].payload)
        except Exception:
            return None

        if len(payload) < 5 or payload[0] != 0x16:  # TLS Handshake record
            return None

        try:
            # Walk to the SNI extension inside the ClientHello.
            # This is a minimal parser - good enough for capture/logging,
            # not a full TLS implementation.
            idx = 43  # skip fixed handshake header + random
            session_id_len = payload[idx]
            idx += 1 + session_id_len
            cipher_suites_len = int.from_bytes(payload[idx:idx+2], "big")
            idx += 2 + cipher_suites_len
            compression_len = payload[idx]
            idx += 1 + compression_len
            extensions_len = int.from_bytes(payload[idx:idx+2], "big")
            idx += 2
            end = idx + extensions_len

            while idx < end:
                ext_type = int.from_bytes(payload[idx:idx+2], "big")
                ext_len = int.from_bytes(payload[idx+2:idx+4], "big")
                if ext_type == 0x00:  # server_name extension
                    sni_len = int.from_bytes(payload[idx+7:idx+9], "big")
                    sni = payload[idx+9:idx+9+sni_len].decode("utf-8", errors="ignore")
                    return sni
                idx += 4 + ext_len
        except Exception:
            return None
        return None


if __name__ == "__main__":
    # Quick manual test with a few known IPs
    identifier = ServiceIdentifier()
    identifier.load_ip_ranges()

    test_ips = ["8.8.8.8", "142.250.195.100", "13.107.42.14", "1.1.1.1"]
    for ip in test_ips:
        print(f"{ip:20s} -> {identifier.identify_from_ip(ip)}")
