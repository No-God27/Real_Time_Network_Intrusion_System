import subprocess
import os
from datetime import datetime
from nfstream import NFStreamer
import pandas as pd

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

def extract_features_with_nfstream(pcap_path, output_dir):
    """
    Extracts features from a PCAP file using NFStreamer and saves them as a CSV.
    :param pcap_path: Path to the PCAP file.
    :param output_dir: Directory to save the extracted features as a CSV file.
    """
    try:
        # Use NFStreamer to process the PCAP file
        print(f"Processing PCAP file: {pcap_path}...")
        streamer = NFStreamer(source=pcap_path)

        # Prepare a list to store flow features
        flow_data = []
        for flow in streamer:
            # Generate a unique Flow ID
            flow_id = f"{flow.src_ip}-{flow.src_port}-{flow.dst_ip}-{flow.dst_port}-{flow.protocol}"

            # Ensure attributes are iterable or fallback to default values
            src2dst_bytes = flow.src2dst_bytes if isinstance(flow.src2dst_bytes, list) else []
            dst2src_bytes = flow.dst2src_bytes if isinstance(flow.dst2src_bytes, list) else []

            flow_data.append({
                "Flow ID": flow_id,
                "Src IP": flow.src_ip,
                "Src Port": flow.src_port,
                "Dst IP": flow.dst_ip,
                "Dst Port": flow.dst_port,
                "Protocol": flow.protocol,
                "Timestamp": flow.bidirectional_first_seen_ms if hasattr(flow, 'bidirectional_first_seen_ms') else 0,
                "Flow Duration": flow.bidirectional_duration_ms if hasattr(flow, 'bidirectional_duration_ms') else 0,
                "Tot Fwd Pkts": flow.bidirectional_packets if hasattr(flow, 'bidirectional_packets') else 0,
                "Tot Bwd Pkts": flow.bidirectional_reverse_packets if hasattr(flow, 'bidirectional_reverse_packets') else 0,
                "TotLen Fwd Pkts": sum(src2dst_bytes),
                "TotLen Bwd Pkts": sum(dst2src_bytes),
                "Fwd Pkt Len Max": max(src2dst_bytes, default=0),
                "Fwd Pkt Len Min": min(src2dst_bytes, default=0),
                "Fwd Pkt Len Mean": (sum(src2dst_bytes) / len(src2dst_bytes)) if src2dst_bytes else 0,
                "Fwd Pkt Len Std": pd.Series(src2dst_bytes).std() if src2dst_bytes else 0,
                "Bwd Pkt Len Max": max(dst2src_bytes, default=0),
                "Bwd Pkt Len Min": min(dst2src_bytes, default=0),
                "Bwd Pkt Len Mean": (sum(dst2src_bytes) / len(dst2src_bytes)) if dst2src_bytes else 0,
                "Bwd Pkt Len Std": pd.Series(dst2src_bytes).std() if dst2src_bytes else 0,
                "Flow Byts/s": flow.bidirectional_bytes / flow.bidirectional_duration_ms if hasattr(flow, 'bidirectional_bytes') and flow.bidirectional_duration_ms else 0,
                "Flow Pkts/s": flow.bidirectional_packets / flow.bidirectional_duration_ms if hasattr(flow, 'bidirectional_packets') and flow.bidirectional_duration_ms else 0,
                "Label": "N/A"  # Placeholder for label if needed
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
    capture_traffic(wifi_interface, pcap_file, duration=10)

    # Step 2: Extract features
    extract_features_with_nfstream(pcap_file, output_folder)
