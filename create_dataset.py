from scapy.all import *
import pandas as pd
import numpy as np
from sklearn.preprocessing import StandardScaler
import joblib
from datetime import datetime

def extract_features(packet):
    features = {}
    if TCP in packet:
        # Basic features
        features['src_port'] = int(packet[TCP].sport)
        features['dst_port'] = int(packet[TCP].dport)
        features['packet_len'] = int(len(packet))
        features['tcp_flags'] = int(packet[TCP].flags)
        features['window_size'] = int(packet[TCP].window)
        
        # TCP Flags
        flags = int(packet[TCP].flags)
        features['rst_flag'] = 1 if flags & 0x04 else 0
        features['ack_flag'] = 1 if flags & 0x10 else 0
        features['syn_flag'] = 1 if flags & 0x02 else 0
        features['rst_ack_flags'] = 1 if flags & 0x14 == 0x14 else 0
        
        # IP info
        if IP in packet:
            features['src_ip'] = packet[IP].src
            features['dst_ip'] = packet[IP].dst
            
        return features
    return None

def create_dataset():
    print("[*] Creating dataset from pcap files...")
    
    # Lists to store all packets
    all_packets = []
    
    # Process attack1.pcap
    print("[*] Processing attack1.pcap...")
    packets = rdpcap("attack1.pcap")
    for packet in packets:
        if TCP in packet:
            features = extract_features(packet)
            if features:
                features['attack_type'] = 'attack1'
                features['label'] = 1
                all_packets.append(features)
    
    # Process attack2.pcap
    print("[*] Processing attack2.pcap...")
    packets = rdpcap("attack2.pcap")
    for packet in packets:
        if TCP in packet:
            features = extract_features(packet)
            if features:
                features['attack_type'] = 'attack2'
                features['label'] = 2
                all_packets.append(features)

    # Create DataFrame
    df = pd.DataFrame(all_packets)
    
    # Reorder columns
    columns_order = [
        'src_ip', 'dst_ip', 'src_port', 'dst_port', 
        'packet_len', 'tcp_flags', 'window_size',
        'rst_flag', 'ack_flag', 'syn_flag', 'rst_ack_flags',
        'attack_type', 'label'
    ]
    df = df[columns_order]
    
    # Save to CSV
    timestamp = datetime.now().strftime("%Y%m%d_%H%M%S")
    csv_filename = f'network_traffic_dataset.csv'
    df.to_csv(csv_filename, index=False)
    
    print("\n[*] Dataset Statistics:")
    print(f"Total samples: {len(df)}")
    print(f"Attack1 samples: len(df[df['label'] == 1])")
    print(f"Attack2 samples: len(df[df['label'] == 2])")
    
    print(f"\n[+] Dataset saved to {csv_filename}")
    
    return df



if __name__ == "__main__":
    # Create and save dataset to CSV
    df = create_dataset()
    
   