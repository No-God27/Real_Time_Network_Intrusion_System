import pandas as pd
import numpy as np
from tensorflow.keras.models import load_model
import joblib
import smtplib
from email.message import EmailMessage

# ==============================
# CONFIGURATION (REPLACE WITH YOUR CREDENTIALS)
# ==============================

# Email Configuration (Gmail example)
EMAIL_ADDRESS = 'climacrop@gmail.com'  # Replace with your Gmail address
EMAIL_PASSWORD = 'ClimaCrop@123'  # Replace with your Gmail app password
RECIPIENT_EMAIL = 'swapunil27@gmail.com'  # Replace with recipient's email


# ==============================
# NOTIFICATION FUNCTION
# ==============================

def send_email_alert(subject, body):
    """Send email alert using SMTP"""
    try:
        msg = EmailMessage()
        msg.set_content(body)
        msg['Subject'] = subject
        msg['From'] = EMAIL_ADDRESS
        msg['To'] = RECIPIENT_EMAIL

        with smtplib.SMTP_SSL('smtp.gmail.com', 465) as smtp:
            smtp.login(EMAIL_ADDRESS, EMAIL_PASSWORD)
            smtp.send_message(msg)
        print("Email alert sent successfully")
    except Exception as e:
        print(f"Failed to send email: {str(e)}")


# ==============================
# MAIN DETECTION CODE
# ==============================

# List of required features (must match exactly with what the model expects)
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
csv_path = "C:/Users/linpa/OneDrive/Desktop/Final_/test_dataset/test_d.csv"  # Replace with your CSV path

# Load dataset
try:
    df = pd.read_csv(csv_path)
except FileNotFoundError:
    print(f"Error: File not found at {csv_path}")
    exit()

# Check for required columns
missing_features = [feat for feat in required_features if feat not in df.columns]
if missing_features:
    print(f"Missing required features: {missing_features}")
    exit()

if 'Src IP' not in df.columns:
    print("Error: CSV file is missing 'Src IP' column")
    exit()

src_ips = df['Src IP']
new_data = df[required_features]

# Preprocess data
try:
    scaler = joblib.load("../model/scaler.save")
    new_data_scaled = scaler.transform(new_data)
except Exception as e:
    print(f"Error in scaling: {str(e)}")
    exit()

# Load model and make predictions
try:
    model = load_model("../model/Rids-model.hdf5")
    predicted_probabilities = model.predict(new_data_scaled)
    predicted_classes = np.argmax(predicted_probabilities, axis=1)
except Exception as e:
    print(f"Error in prediction: {str(e)}")
    exit()

# Display results with source IPs and send email for the first attack
attack_found = False
for src_ip, prob, cls in zip(src_ips, predicted_probabilities, predicted_classes):
    if class_labels[cls] != 'Normal':
        attack_found = True
        attack_type = class_labels[cls]

        # Construct alert message
        alert_subject = f"🚨 Network Attack Detected: {attack_type}"
        alert_body = f"""
        Network Security Alert!

        Source IP: {src_ip}
        Attack Type: {attack_type}
        Confidence: {prob[cls]:.2%}

        Timestamp: {pd.Timestamp.now()}
        """

        # Print to console
        print(f"\n{'-' * 40}")
        print(alert_body)
        print(f"{'-' * 40}")

        # Send email for the first attack only
        send_email_alert(alert_subject, alert_body)
        break  # Exit after the first attack is detected

if not attack_found:
    print("\n✅ No attacks detected in any of the analyzed network flows")

print("\nAnalysis complete. Processed", len(df), "network flows.")