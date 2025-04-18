import pandas as pd
from scapy.all import sniff, IP, TCP, wrpcap
from collections import defaultdict
import numpy as np
import time

# Dictionary to store flow features
flows = defaultdict(lambda: {
    'src_ip': None,
    'src_port': None,
    'dst_ip': None,
    'dst_port': None,
    'protocol': None,
    'timestamps': [],
    'pkt_count': 0,
    'fwd_pkt_count': 0,
    'bwd_pkt_count': 0,
    'fwd_pkt_len': [],
    'bwd_pkt_len': [],
    'fwd_flags': {'SYN': 0, 'FIN': 0, 'RST': 0, 'PSH': 0, 'ACK': 0, 'URG': 0},
    'bwd_flags': {'SYN': 0, 'FIN': 0, 'RST': 0, 'PSH': 0, 'ACK': 0, 'URG': 0},
    'fwd_IAT': [],
    'bwd_IAT': [],
    'flow_IAT': [],
    'bytes_sent': 0,
    'bytes_received': 0,
    'pkt_len': []
})

# List to hold captured packets
captured_packets = []

# Process each packet in real-time
def process_packet(packet):
    captured_packets.append(packet)
    if packet.haslayer(IP) and packet.haslayer(TCP):
        ip_src = packet[IP].src
        ip_dst = packet[IP].dst
        src_port = packet[TCP].sport
        dst_port = packet[TCP].dport
        protocol = packet[IP].proto

        # Define flow key as tuple (src_ip, dst_ip, src_port, dst_port, protocol)
        flow_key = (ip_src, ip_dst, src_port, dst_port, protocol)

        # Get the flow object
        flow = flows[flow_key]

        # Set basic IP and port details for first packet in the flow
        if flow['src_ip'] is None:
            flow['src_ip'] = ip_src
            flow['dst_ip'] = ip_dst
            flow['src_port'] = src_port
            flow['dst_port'] = dst_port
            flow['protocol'] = protocol

        # Timestamp and packet length
        flow['timestamps'].append(packet.time)
        flow['pkt_count'] += 1
        flow['pkt_len'].append(len(packet))

        if ip_src == flow['src_ip']:  # Forward packet
            flow['fwd_pkt_count'] += 1
            flow['fwd_pkt_len'].append(len(packet))
        else:  # Backward packet
            flow['bwd_pkt_count'] += 1
            flow['bwd_pkt_len'].append(len(packet))

        # TCP Flags
        if packet.haslayer(TCP):
            tcp_flags = packet[TCP].flags
            for flag in flow['fwd_flags']:
                if flag in tcp_flags:
                    flow['fwd_flags'][flag] += tcp_flags[flag]

        # Calculate Inter-Arrival Times
        if len(flow['timestamps']) > 1:
            last_ts = flow['timestamps'][-2]
            current_ts = flow['timestamps'][-1]
            flow['flow_IAT'].append(current_ts - last_ts)
            if ip_src == flow['src_ip']:  # Forward IAT
                flow['fwd_IAT'].append(current_ts - last_ts)
            else:  # Backward IAT
                flow['bwd_IAT'].append(current_ts - last_ts)

# Convert the flow data to a DataFrame and calculate the features
def extract_features():
    flow_features = []
    for flow_key, flow in flows.items():
        flow_duration = flow['timestamps'][-1] - flow['timestamps'][0] if len(flow['timestamps']) > 1 else 0

        feature = {
            'Flow ID': f"{flow['src_ip']}:{flow['src_port']} -> {flow['dst_ip']}:{flow['dst_port']}",
            'Src IP': flow['src_ip'],
            'Src Port': flow['src_port'],
            'Dst IP': flow['dst_ip'],
            'Dst Port': flow['dst_port'],
            'Protocol': flow['protocol'],
            'Timestamp': flow['timestamps'][0] if flow['timestamps'] else None,
            'Flow Duration': flow_duration,
            'Tot Fwd Pkts': flow['fwd_pkt_count'],
            'Tot Bwd Pkts': flow['bwd_pkt_count'],
            'TotLen Fwd Pkts': sum(flow['fwd_pkt_len']),
            'TotLen Bwd Pkts': sum(flow['bwd_pkt_len']),
            'Fwd Pkt Len Max': max(flow['fwd_pkt_len']) if flow['fwd_pkt_len'] else 0,
            'Fwd Pkt Len Min': min(flow['fwd_pkt_len']) if flow['fwd_pkt_len'] else 0,
            'Fwd Pkt Len Mean': np.mean(flow['fwd_pkt_len']) if flow['fwd_pkt_len'] else 0,
            'Fwd Pkt Len Std': np.std(flow['fwd_pkt_len']) if flow['fwd_pkt_len'] else 0,
            'Bwd Pkt Len Max': max(flow['bwd_pkt_len']) if flow['bwd_pkt_len'] else 0,
            'Bwd Pkt Len Min': min(flow['bwd_pkt_len']) if flow['bwd_pkt_len'] else 0,
            'Bwd Pkt Len Mean': np.mean(flow['bwd_pkt_len']) if flow['bwd_pkt_len'] else 0,
            'Bwd Pkt Len Std': np.std(flow['bwd_pkt_len']) if flow['bwd_pkt_len'] else 0,
            'Flow Byts/s': sum(flow['fwd_pkt_len']) / flow_duration if flow_duration > 0 else 0,
            'Flow Pkts/s': flow['pkt_count'] / flow_duration if flow_duration > 0 else 0,
            'Flow IAT Mean': np.mean(flow['flow_IAT']) if flow['flow_IAT'] else 0,
            'Flow IAT Std': np.std(flow['flow_IAT']) if flow['flow_IAT'] else 0,
            'Flow IAT Max': max(flow['flow_IAT']) if flow['flow_IAT'] else 0,
            'Flow IAT Min': min(flow['flow_IAT']) if flow['flow_IAT'] else 0,
            'Fwd IAT Tot': sum(flow['fwd_IAT']),
            'Fwd IAT Mean': np.mean(flow['fwd_IAT']) if flow['fwd_IAT'] else 0,
            'Fwd IAT Std': np.std(flow['fwd_IAT']) if flow['fwd_IAT'] else 0,
            'Fwd IAT Max': max(flow['fwd_IAT']) if flow['fwd_IAT'] else 0,
            'Fwd IAT Min': min(flow['fwd_IAT']) if flow['fwd_IAT'] else 0,
            'Bwd IAT Tot': sum(flow['bwd_IAT']),
            'Bwd IAT Mean': np.mean(flow['bwd_IAT']) if flow['bwd_IAT'] else 0,
            'Bwd IAT Std': np.std(flow['bwd_IAT']) if flow['bwd_IAT'] else 0,
            'Bwd IAT Max': max(flow['bwd_IAT']) if flow['bwd_IAT'] else 0,
            'Bwd IAT Min': min(flow['bwd_IAT']) if flow['bwd_IAT'] else 0,
            'Fwd PSH Flags': flow['fwd_flags']['PSH'],
            'Bwd PSH Flags': flow['bwd_flags']['PSH'],
            'Fwd URG Flags': flow['fwd_flags']['URG'],
            'Bwd URG Flags': flow['bwd_flags']['URG'],
            'Fwd Header Len': flow['fwd_pkt_len'][0] if flow['fwd_pkt_len'] else 0,
            'Bwd Header Len': flow['bwd_pkt_len'][0] if flow['bwd_pkt_len'] else 0,
            'Fwd Pkts/s': flow['fwd_pkt_count'] / flow_duration if flow_duration > 0 else 0,
            'Bwd Pkts/s': flow['bwd_pkt_count'] / flow_duration if flow_duration > 0 else 0,
            'Pkt Len Min': min(flow['pkt_len']),
            'Pkt Len Max': max(flow['pkt_len']),
            'Pkt Len Mean': np.mean(flow['pkt_len']),
            'Pkt Len Std': np.std(flow['pkt_len']),
            'Pkt Len Var': np.var(flow['pkt_len']),
            'FIN Flag Cnt': flow['fwd_flags']['FIN'],
            'SYN Flag Cnt': flow['fwd_flags']['SYN'],
            'RST Flag Cnt': flow['fwd_flags']['RST'],
            'PSH Flag Cnt': flow['fwd_flags']['PSH'],
            'ACK Flag Cnt': flow['fwd_flags']['ACK'],
            'URG Flag Cnt': flow['fwd_flags']['URG'],
            'Label': 'Unlabeled'  # Optional
        }
        flow_features.append(feature)

    return pd.DataFrame(flow_features)

# Sniff packets in real-time and process them
def sniff_packets(interface, capture_duration):
    print(f"Starting to sniff packets on {interface}...")
    # Capture packets for the given duration
    sniff(iface=interface, prn=process_packet, store=1, timeout=capture_duration)

    # After sniffing, save packets to pcap file
    pcap_path = r"C:\Users\linpa\OneDrive\Documents\pcap_store\captured_packets.pcap"
    wrpcap(pcap_path, captured_packets)

    # Extract features and save to CSV
    feature_df = extract_features()
    csv_path = r"C:\Users\linpa\OneDrive\Documents\output\flow_features.csv"
    feature_df.to_csv(csv_path, index=False)

# Main function to start real-time capture and save
def main():
    # Set the network interface and capture duration
    interface = "Wi-Fi"
    capture_duration = 1000  # seconds

    sniff_packets(interface, capture_duration)

if __name__ == '__main__':
    main()
