import subprocess
import os
from datetime import datetime
from nfstream import NFStreamer
import pandas as pd
import numpy as np

def capture_traffic(interface, output_file, duration):
    """
    Captures network traffic using Tshark.
    :param interface: WiFi interface name (e.g., 'Wi-Fi').
    :param output_file: Path to save the PCAP file.
    :param duration: Duration of capture in seconds.
    """
    try:
        print(f"Capturing traffic on {interface} for {duration} seconds...")
        command = [
            "tshark", "-i", interface,
            "-a", f"duration:{duration}",
            "-w", output_file
        ]
        subprocess.run(command, check=True)
        print(f"Traffic captured to {output_file}")
    except subprocess.CalledProcessError as e:
        print(f"Error capturing traffic: {e}")

def safe_stat(attr, func, default):
    """Utility to safely apply statistical functions."""
    try:
        return func(attr) if attr else default
    except Exception:
        return default

def extract_features_with_nfstream(pcap_path, output_dir):
    """
    Extracts features from a PCAP file using NFStreamer and saves them as a CSV.
    :param pcap_path: Path to the PCAP file.
    :param output_dir: Directory to save the extracted features as a CSV file.
    """
    try:
        # Use NFStreamer to process the PCAP file
        print(f"Processing PCAP file: {pcap_path}...")
        streamer = NFStreamer(source=pcap_path, statistical_analysis=True)

        # Prepare a list to store flow features
        flow_data = []
        for flow in streamer:
            flow_id = f"{flow.src_ip}-{flow.src_port}-{flow.dst_ip}-{flow.dst_port}-{flow.protocol}"

            bidirectional_packet_lengths = getattr(flow, 'bidirectional_packet_lengths', [])
            src2dst_packet_lengths = getattr(flow, 'src2dst_packet_lengths', [])
            dst2src_packet_lengths = getattr(flow, 'dst2src_packet_lengths', [])
            flow_data.append({
                "Flow ID": flow_id,
                "Src IP": getattr(flow, 'src_ip', None),
                "Src Port": getattr(flow, 'src_port', None),
                "Dst IP": getattr(flow, 'dst_ip', None),
                "Dst Port": getattr(flow, 'dst_port', None),
                "Protocol": getattr(flow, 'protocol', None),
                "Timestamp": getattr(flow, 'bidirectional_first_seen_ms', 0),
                "Flow Duration": getattr(flow, 'bidirectional_duration_ms', 0),
                "Tot Fwd Pkts": getattr(flow, 'src2dst_packets', 0),
                "Tot Bwd Pkts": getattr(flow, 'dst2src_packets', 0),
                "TotLen Fwd Pkts": getattr(flow, 'src2dst_bytes', 0),
                "TotLen Bwd Pkts": getattr(flow, 'dst2src_bytes', 0),
                "Fwd Pkt Len Max": safe_stat(src2dst_packet_lengths, max, 0),
                "Fwd Pkt Len Min": safe_stat(src2dst_packet_lengths, min, 0),
                "Fwd Pkt Len Mean": safe_stat(src2dst_packet_lengths, np.mean, 0),
                "Fwd Pkt Len Std": safe_stat(src2dst_packet_lengths, np.std, 0),
                "Bwd Pkt Len Max": safe_stat(dst2src_packet_lengths, max, 0),
                "Bwd Pkt Len Min": safe_stat(dst2src_packet_lengths, min, 0),
                "Bwd Pkt Len Mean": safe_stat(dst2src_packet_lengths, np.mean, 0),
                "Bwd Pkt Len Std": safe_stat(dst2src_packet_lengths, np.std, 0),
                "Flow IAT Mean": getattr(flow, 'bidirectional_mean_interarrival_time_ms', 0),
                "Flow IAT Std": getattr(flow, 'bidirectional_stddev_interarrival_time_ms', 0),
                "Flow IAT Max": getattr(flow, 'bidirectional_max_interarrival_time_ms', 0),
                "Flow IAT Min": getattr(flow, 'bidirectional_min_interarrival_time_ms', 0),
                "Fwd IAT Tot": getattr(flow, 'src2dst_interarrival_time_total_ms', 0),
                "Fwd IAT Mean": getattr(flow, 'src2dst_mean_interarrival_time_ms', 0),
                "Fwd IAT Std": getattr(flow, 'src2dst_stddev_interarrival_time_ms', 0),
                "Fwd IAT Max": getattr(flow, 'src2dst_max_interarrival_time_ms', 0),
                "Fwd IAT Min": getattr(flow, 'src2dst_min_interarrival_time_ms', 0),
                "Bwd IAT Tot": getattr(flow, 'dst2src_interarrival_time_total_ms', 0),
                "Bwd IAT Mean": getattr(flow, 'dst2src_mean_interarrival_time_ms', 0),
                "Bwd IAT Std": getattr(flow, 'dst2src_stddev_interarrival_time_ms', 0),
                "Bwd IAT Max": getattr(flow, 'dst2src_max_interarrival_time_ms', 0),
                "Bwd IAT Min": getattr(flow, 'dst2src_min_interarrival_time_ms', 0),
                "Pkt Len Min": safe_stat(bidirectional_packet_lengths, min, 0),
                "Pkt Len Max": safe_stat(bidirectional_packet_lengths, max, 0),
                "Pkt Len Mean": safe_stat(bidirectional_packet_lengths, np.mean, 0),
                "Pkt Len Std": safe_stat(bidirectional_packet_lengths, np.std, 0),
                "Pkt Len Var": safe_stat(bidirectional_packet_lengths, np.var, 0),
                "FIN Flag Cnt": getattr(flow, 'fin_flags', 0),
                "SYN Flag Cnt": getattr(flow, 'syn_flags', 0),
                "RST Flag Cnt": getattr(flow, 'rst_flags', 0),
                "PSH Flag Cnt": getattr(flow, 'psh_flags', 0),
                "ACK Flag Cnt": getattr(flow, 'ack_flags', 0),
                "URG Flag Cnt": getattr(flow, 'urg_flags', 0),
                "Active Mean": getattr(flow, 'bidirectional_mean_active_time_ms', 0),
                "Active Std": getattr(flow, 'bidirectional_stddev_active_time_ms', 0),
                "Active Max": getattr(flow, 'bidirectional_max_active_time_ms', 0),
                "Active Min": getattr(flow, 'bidirectional_min_active_time_ms', 0),
                "Idle Mean": getattr(flow, 'bidirectional_mean_idle_time_ms', 0),
                "Idle Std": getattr(flow, 'bidirectional_stddev_idle_time_ms', 0),
                "Idle Max": getattr(flow, 'bidirectional_max_idle_time_ms', 0),
                "Idle Min": getattr(flow, 'bidirectional_min_idle_time_ms', 0),
                "Label": "N/A"  # Placeholder for labels, if needed later
            })

        # Convert to a DataFrame and save as CSV
        df = pd.DataFrame(flow_data)
        csv_output_path = os.path.join(output_dir, os.path.basename(pcap_path).replace(".pcap", "_features.csv"))
        df.to_csv(csv_output_path, index=False)
        print(f"Features extracted and saved to {csv_output_path}")
    except Exception as e:
        print(f"Error processing PCAP with NFStreamer: {e}")

# Main workflow
if __name__ == "__main__":
    wifi_interface = "Wi-Fi"  # Replace with your WiFi interface name
    output_folder = "C:\\Users\\linpa\\OneDrive\\Documents\\output"  # Folder to store extracted features
    pcap_store_folder = "C:\\Users\\linpa\\OneDrive\\Documents\\pcap_store"  # Folder to store PCAP files
    os.makedirs(output_folder, exist_ok=True)
    os.makedirs(pcap_store_folder, exist_ok=True)

    # Step 1: Capture traffic
    timestamp = datetime.now().strftime("%Y%m%d_%H%M%S")
    pcap_file = os.path.join(pcap_store_folder, f"traffic_{timestamp}.pcap")
    capture_traffic(wifi_interface, pcap_file, duration=100)

    # Step 2: Extract features
    extract_features_with_nfstream(pcap_file, output_folder)
