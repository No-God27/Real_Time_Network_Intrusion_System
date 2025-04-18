import pandas as pd
import numpy as np
import os
import time
import smtplib
import requests
from email.mime.text import MIMEText
from email.mime.multipart import MIMEMultipart
from tensorflow.keras.models import load_model
import joblib
from datetime import datetime

CSV_DIR = "C:/Users/linpa/OneDrive/Desktop/Attack_detect/output_csv"
PROCESSED_FILES = set()

ADMIN_EMAIL = "xxxxxxxxxxxxxxx"
SENDER_EMAIL = "xxxxxxxxxxxxxxxxxxxx"
SENDER_PASSWORD = "xxxxxxxxxxxxxxxxxxxxxxxxx"

# Telegram Bot Configuration
TELEGRAM_BOT_TOKEN = "xxxxxxxxxxxxxxxxxxxxxxxxx"
TELEGRAM_CHAT_ID = "xxxxxxxxxxxxxxxxxxxxxxxxxxx"

required_features = ['Dst Port', 'Protocol', 'Flow Duration', 'Tot Fwd Pkts', 'Tot Bwd Pkts',
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
    'Active Max', 'Active Min', 'Idle Mean', 'Idle Std', 'Idle Max', 'Idle Min']
class_labels = ['Normal', 'Scan', 'DOS', 'Bruteforce', 'Malware']


def send_alert_email(attack_details):
    """Send an email alert to the admin when an attack is detected."""
    try:
        msg = MIMEMultipart()
        msg['From'] = SENDER_EMAIL
        msg['To'] = ADMIN_EMAIL
        msg['Subject'] = "🚨 Network Intrusion Alert!"

        body = """
        🚨 ATTACK DETECTED 🚨

        Timestamp: {}

        Concurrent Source IPs Involved:
        {}

        Please take immediate action.
        """.format(datetime.now().strftime('%Y-%m-%d %H:%M:%S'), "\n".join(attack_details))

        msg.attach(MIMEText(body, 'plain'))

        server = smtplib.SMTP('smtp.gmail.com', 587)  # Change SMTP server if needed
        server.starttls()
        server.login(SENDER_EMAIL, SENDER_PASSWORD)
        server.sendmail(SENDER_EMAIL, ADMIN_EMAIL, msg.as_string())
        server.quit()

        print("📧 Alert email sent to admin.")
    except Exception as e:
        print(f"❌ Failed to send email: {str(e)}")


def send_telegram_alert(attack_ips, attack_type):
    """Send an alert to Telegram with attack details."""
    try:
        timestamp = datetime.now().strftime('%Y-%m-%d %H:%M:%S')
        message = f"""
🚨 *Network Intrusion Alert!* 🚨

*Timestamp:* {timestamp}
*Attack Type:* {attack_type}
*Source IPs:* {', '.join(attack_ips)}

Please take immediate action.
        """
        url = f"https://api.telegram.org/bot{TELEGRAM_BOT_TOKEN}/sendMessage"
        payload = {
            "chat_id": TELEGRAM_CHAT_ID,
            "text": message,
            "parse_mode": "Markdown"
        }
        response = requests.post(url, json=payload)
        if response.status_code == 200:
            print("📱 Alert sent to Telegram.")
        else:
            print(f"❌ Failed to send Telegram alert: {response.text}")
    except Exception as e:
        print(f"❌ Failed to send Telegram alert: {str(e)}")


def get_csv_files():
    try:
        all_files = [f for f in os.listdir(CSV_DIR) if f.lower().endswith('.csv')]
        new_files = []
        for f in all_files:
            full_path = os.path.join(CSV_DIR, f)
            if full_path not in PROCESSED_FILES:
                try:
                    ctime = os.path.getctime(full_path)
                    new_files.append((ctime, full_path))
                except FileNotFoundError:
                    continue
        new_files.sort()
        return [path for (_, path) in new_files]
    except Exception as e:
        print(f"Error scanning directory: {str(e)}")
        return []


def analyze_file(filepath):
    print(f"\n🔍 Analyzing {os.path.basename(filepath)}...")
    try:
        df = pd.read_csv(filepath)
        print(f"📄 Loaded {len(df)} network flows")

        missing = [f for f in required_features if f not in df.columns]
        if missing or 'Src IP' not in df.columns:
            print("⚠️ Missing required columns")
            return False

        scaler = joblib.load("scaler.save")
        model = load_model("Rids-model.hdf5")

        new_data_scaled = scaler.transform(df[required_features])
        predictions = model.predict(new_data_scaled)
        classes = np.argmax(predictions, axis=1)

        attack_ips = set()
        attack_types = set()
        for ip, cls in zip(df['Src IP'], classes):
            if class_labels[cls] != 'Normal':
                attack_ips.add(ip)
                attack_types.add(class_labels[cls])

        if attack_ips:
            print(f"\n🔥 Attack detected from IPs: {attack_ips}")
            send_alert_email(attack_ips)
            send_telegram_alert(attack_ips, ", ".join(attack_types))
            exit(0)  # Terminate script
        else:
            print("✅ All activities normal")

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
            time.sleep(1)

        print("\n🔄 Checking for new files...")