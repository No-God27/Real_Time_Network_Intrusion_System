import pandas as pd
import numpy as np
import os
import time
from tensorflow.keras.models import load_model
import joblib

# Configuration
CSV_DIR = "C:/Users/linpa/OneDrive/Desktop/Attack_detect/output_csv"
PROCESSED_FILES = set()

required_features = [
    'Dst Port', 'Protocol', 'Flow Duration', 'Tot Fwd Pkts', 'Tot Bwd Pkts',
    'TotLen Fwd Pkts', 'TotLen Bwd Pkts', 'Fwd Pkt Len Max', 'Fwd Pkt Len Min',
    'Fwd Pkt Len Mean', 'Fwd Pkt Len Std', 'Bwd Pkt Len Max', 'Bwd Pkt Len Min',
    'Bwd Pkt Len Mean', 'Bwd Pkt Len Std', 'Flow Byts/s', 'Flow Pkts/s',
    'Flow IAT Mean', 'Flow IAT Std', 'Flow IAT Max', 'Flow IAT Min',
    'Fwd IAT Tot', 'Fwd IAT Mean', 'Fwd IAT Std', 'Fwd IAT Max', 'Fwd IAT Min',
    'Bwd IAT Tot', 'Bwd IAT Mean', 'Bwd IAT Std', 'Bwd IAT Max', 'Bwd IAT Min',
    'Fwd PSH Flags', 'Bwd PSH Flags', 'Fwd URG Flags', 'Bwd URG Flags',
    'Fwd Header Len', 'Bwd Header Len', 'Fwd Pkts/s', 'Bwd Pkts/s',
    'Pkt Len Min', 'Pkt Len Max', 'Pkt Len Mean', 'Pkt Len Std', 'Pkt Len Var',
    'FIN Flag Cnt', 'SYN Flag Cnt', 'RST Flag Cnt', 'PSH Flag Cnt',
    'ACK Flag Cnt', 'URG Flag Cnt', 'CWE Flag Count', 'ECE Flag Cnt',
    'Down/Up Ratio', 'Pkt Size Avg', 'Fwd Seg Size Avg', 'Bwd Seg Size Avg',
    'Fwd Byts/b Avg', 'Fwd Pkts/b Avg', 'Fwd Blk Rate Avg', 'Bwd Byts/b Avg',
    'Bwd Pkts/b Avg', 'Bwd Blk Rate Avg', 'Subflow Fwd Pkts', 'Subflow Fwd Byts',
    'Subflow Bwd Pkts', 'Subflow Bwd Byts', 'Init Fwd Win Byts', 'Init Bwd Win Byts',
    'Fwd Act Data Pkts', 'Fwd Seg Size Min', 'Active Mean', 'Active Std',
    'Active Max', 'Active Min', 'Idle Mean', 'Idle Std', 'Idle Max', 'Idle Min'
]

class_labels = ['Normal', 'Scan', 'DOS', 'Bruteforce', 'Malware']


def get_csv_files():
    """Get CSV files in chronological order"""
    files = []
    try:
        for f in os.listdir(CSV_DIR):
            if f.endswith('.csv'):
                path = os.path.join(CSV_DIR, f)
                if path not in PROCESSED_FILES:
                    files.append((os.path.getctime(path), path))
        files.sort(key=lambda x: x[0])  # Sort by creation time
        return [path for (_, path) in files]
    except Exception as e:
        print(f"Error scanning directory: {str(e)}")
        return []


def analyze_file(filepath):
    """Analyze a single CSV file"""
    print(f"\n🔍 Analyzing {os.path.basename(filepath)}...")
    try:
        df = pd.read_csv(filepath)
        print(f"📄 Loaded {len(df)} network flows")

        # Validate columns
        missing = [f for f in required_features if f not in df.columns]
        if missing:
            print(f"⚠️ Missing columns: {missing}")
            return False
        if 'Src IP' not in df.columns:
            print("⚠️ Missing 'Src IP' column")
            return False

        # Preprocess data
        scaler = joblib.load("scaler.save")
        new_data_scaled = scaler.transform(df[required_features])

        # Predict
        model = load_model("Rids-model.hdf5")
        predictions = model.predict(new_data_scaled)
        classes = np.argmax(predictions, axis=1)

        # Display results
        attacks = 0
        for ip, prob, cls in zip(df['Src IP'], predictions, classes):
            if class_labels[cls] != 'Normal':
                attacks += 1
                print(f"\n🚨 ATTACK DETECTED 🚨")
                print(f"Source IP: {ip}")
                print(f"Attack Type: {class_labels[cls]}")
                print("Confidence Levels:")
                for label, p in zip(class_labels, prob):
                    print(f"  {label}: {p:.4f}")

        if attacks == 0:
            print("✅ All activities normal")
        else:
            print(f"\n🔥 Total attacks detected: {attacks}")

        PROCESSED_FILES.add(filepath)
        return True

    except Exception as e:
        print(f"❌ Error processing file: {str(e)}")
        return False


if __name__ == "__main__":
    print("🛡️ Starting Network Traffic Analyzer 🛡️")
    print("--------------------------------------")

    while True:
        files = get_csv_files()

        if not files:
            print("\n⏳ No new CSV files detected...", end='')
            for _ in range(5):
                time.sleep(1)
                print(".", end='', flush=True)
            continue

        for filepath in files:
            if analyze_file(filepath):
                print(f"\n✔️ Completed analysis of {os.path.basename(filepath)}")
            else:
                print(f"\n❌ Failed to process {os.path.basename(filepath)}")
            time.sleep(1)  # Pause between files

        print("\n🔄 Checking for new files...")