import pandas as pd
import numpy as np
import os
import time
import smtplib
from email.mime.text import MIMEText
from email.mime.multipart import MIMEMultipart
from tensorflow.keras.models import load_model
import joblib

# Configuration
CSV_DIR = "C:/Users/linpa/OneDrive/Desktop/Attack_detect/output_csv"
PROCESSED_FILES = set()
CHECK_INTERVAL = 5  # Seconds between directory checks

# Email configuration (update with your credentials)
SMTP_SERVER = "smtp.gmail.com"
SMTP_PORT = 587
EMAIL_ADDRESS = "xxxxxxxxxxxxx"
EMAIL_PASSWORD = "xxxxxxxxxxxxxxxxxxxxxxxxxxx"
ADMIN_EMAIL = "xxxxxxxxxxxxxxx"

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


def wait_for_file_stability(filepath):
    """Wait for file to stop changing"""
    print(f"⏳ Waiting for {os.path.basename(filepath)} to stabilize...")
    stable_time = 2  # Seconds of stability required
    last_size = -1
    start_time = time.time()

    while True:
        try:
            current_size = os.path.getsize(filepath)
            if current_size == last_size:
                if time.time() - start_time > stable_time:
                    return True
            else:
                last_size = current_size
                start_time = time.time()
            time.sleep(0.5)
        except FileNotFoundError:
            return False


def get_csv_files():
    """Get new CSV files in chronological order"""
    try:
        # Get all CSV files (case-insensitive)
        all_files = [f for f in os.listdir(CSV_DIR) if f.lower().endswith('.csv')]

        # Filter new files and get creation times
        new_files = []
        for f in all_files:
            full_path = os.path.join(CSV_DIR, f)
            if full_path not in PROCESSED_FILES:
                try:
                    ctime = os.path.getctime(full_path)
                    new_files.append((ctime, full_path))
                except FileNotFoundError:
                    continue  # File disappeared before processing

        # Sort by creation time
        new_files.sort()
        return [path for (_, path) in new_files]

    except Exception as e:
        print(f"Error scanning directory: {str(e)}")
        return []


def analyze_file(filepath):
    """Analyze a single CSV file"""
    print(f"\n🔍 Checking {os.path.basename(filepath)}...")

    # Wait for file to be fully written
    if not wait_for_file_stability(filepath):
        print(f"❌ File {os.path.basename(filepath)} unavailable")
        return False, []

    try:
        df = pd.read_csv(filepath)
        print(f"📄 Loaded {len(df)} network flows from {os.path.basename(filepath)}")

        # Validate columns
        missing = [f for f in required_features if f not in df.columns]
        if missing:
            print(f"⚠️ Missing columns: {missing[:3]}...")
            return False, []

        if 'Src IP' not in df.columns or 'Timestamp' not in df.columns:
            print("⚠️ Missing essential columns")
            return False, []

        # Preprocess data
        scaler = joblib.load("scaler.save")
        new_data_scaled = scaler.transform(df[required_features])

        # Predict
        model = load_model("Rids-model.hdf5")
        predictions = model.predict(new_data_scaled)
        classes = np.argmax(predictions, axis=1)

        # Collect attack details
        attack_details = []
        for ip, timestamp, prob, cls in zip(df['Src IP'], df['Timestamp'], predictions, classes):
            if class_labels[cls] != 'Normal':
                attack_details.append({
                    'timestamp': timestamp,
                    'source_ip': ip,
                    'type': class_labels[cls],
                    'confidence': f"{np.max(prob):.4f}"
                })

        # Mark as processed only if successful
        PROCESSED_FILES.add(filepath)
        return True, attack_details

    except Exception as e:
        print(f"❌ Processing error: {str(e)}")
        return False, []


# ... (keep the existing send_alert_email and main loop code)

if __name__ == "__main__":
    print("🛡️ Starting Network Traffic Analyzer 🛡️")
    print("--------------------------------------")
    print(f"Watching directory: {CSV_DIR}")

    try:
        while True:
            files = get_csv_files()

            if not files:
                print(f"\n⏳ No new CSV files detected (checked at {time.ctime()})")
                time.sleep(CHECK_INTERVAL)
                continue

            print(f"\n📂 Found {len(files)} new files to process")

            for filepath in files:
                print(f"\n➡️ Processing {os.path.basename(filepath)}...")
                success, attacks = analyze_file(filepath)

                if attacks:
                    alert_msg = "\n".join(
                        f"[{a['timestamp']}] {a['source_ip']} - {a['type']} ({a['confidence']})"
                        for a in attacks
                    )
                    print(f"🔥 CRITICAL: Detected {len(attacks)} attacks!")
                    send_alert_email(alert_msg)
                    print("🛑 Emergency shutdown initiated")
                    exit(1)

                elif success:
                    print(f"✅ Completed {os.path.basename(filepath)}")

            time.sleep(1)

    except KeyboardInterrupt:
        print("\n🔴 Manual shutdown requested")
        exit(0)