import pandas as pd
import numpy as np
import io
import pika
from tensorflow.keras.models import load_model
import joblib

# List of required features (must exactly match what your model expects)
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

# Load the scaler and model once (adjust paths as needed)
try:
    scaler = joblib.load("../model/scaler.save")
except Exception as e:
    print("Error loading scaler:", e)
    exit()

try:
    model = load_model("../model/Rids-model.hdf5")
except Exception as e:
    print("Error loading model:", e)
    exit()


def detect_attacks(df):
    # Ensure the DataFrame contains the required 'Timestamp' column
    if 'Timestamp' not in df.columns:
        print("Error: CSV data is missing 'Timestamp' column.")
        return

    timestamps = df['Timestamp']
    new_data = df[required_features]

    try:
        new_data_scaled = scaler.transform(new_data)
    except Exception as e:
        print("Error in data scaling:", e)
        return

    try:
        predicted_probabilities = model.predict(new_data_scaled)
        predicted_classes = np.argmax(predicted_probabilities, axis=1)
    except Exception as e:
        print("Error in model prediction:", e)
        return

    attack_found = False
    for ts, prob, cls in zip(timestamps, predicted_probabilities, predicted_classes):
        if class_labels[cls] != 'Normal':
            attack_found = True
            print("\n🚨 Attack Detected 🚨")
            print("Timestamp:", ts)
            print("Attack Type:", class_labels[cls])
            print("Class Probabilities:")
            for label, p in zip(class_labels, prob):
                print(f"  {label}: {p:.4f}")
    if not attack_found:
        print("\n✅ No attacks detected in the analyzed network flows")
    print("\n[Detector] Analysis complete. Processed", len(df), "network flows.")


def callback(ch, method, properties, body):
    csv_data = body.decode('utf-8')
    try:
        df = pd.read_csv(io.StringIO(csv_data))
        print("[Detector] Received CSV data. Starting analysis...")
        # Check for required features
        missing = [feat for feat in required_features if feat not in df.columns]
        if missing:
            print("[Detector] Missing required features:", missing)
            return
        detect_attacks(df)
    except Exception as e:
        print("[Detector] Error processing CSV data:", e)


def main():
    connection = pika.BlockingConnection(pika.ConnectionParameters('localhost'))
    channel = connection.channel()
    queue_name = 'cicflowmeter_queue'
    channel.queue_declare(queue=queue_name)

    channel.basic_consume(queue=queue_name, on_message_callback=callback, auto_ack=True)
    print("[Detector] Waiting for CSV data from RabbitMQ. To exit press CTRL+C")
    channel.start_consuming()


if __name__ == "__main__":
    main()
