# parser.py
import re
import pandas as pd

# Custom parser for TCPDump-formatted text file
def parse_file(filepath):
    data = []
    with open(filepath, 'r') as f:
        for line in f:
            line = line.strip()
            parts = line.split()
            if len(parts) >= 6:
                try:
                    data.append({
                        'time': float(parts[0]),
                        'src': parts[1],
                        'dst': parts[2],
                        'src_port': parts[3],
                        'dst_port': parts[4],
                        'flags': ' '.join(parts[5:])
                    })
                except ValueError:
                    continue
    return pd.DataFrame(data)
