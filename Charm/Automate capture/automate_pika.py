import subprocess
import os
import time
from datetime import datetime
import pyshark
import glob
import pika


def capture_pcap(interface, capture_duration, output_pcap):
    try:
        print(f"[Publisher] Capturing network traffic for {capture_duration} seconds on {interface}...")
        capture = pyshark.LiveCapture(interface=interface, output_file=output_pcap)
        capture.sniff(timeout=capture_duration)
        print(f"[Publisher] Packet capture completed: {output_pcap}")
    except Exception as e:
        print(f"[Publisher] Error during packet capture: {e}")


def run_cfm(cfm_path, input_file, output_folder):
    try:
        print(f"[Publisher] Running CICFlowMeter on {input_file}...")
        # Save current directory and switch to the CICFlowMeter bin folder
        original_dir = os.getcwd()
        bin_directory = os.path.dirname(cfm_path)
        os.chdir(bin_directory)

        command = f"cfm.bat {input_file} {output_folder}"
        print(f"[Publisher] Executing command: {command}")
        process = subprocess.Popen(
            command,
            stdout=subprocess.PIPE,
            stderr=subprocess.PIPE,
            text=True,
            shell=True
        )
        stdout, stderr = process.communicate()
        if process.returncode != 0:
            print(f"[Publisher] Error running CICFlowMeter:\n{stderr}")
        else:
            print(f"[Publisher] CICFlowMeter output:\n{stdout}")

        os.chdir(original_dir)
    except Exception as e:
        print(f"[Publisher] Exception while running CICFlowMeter: {e}")


def get_latest_csv(folder):
    """Return the most recently created CSV file in the given folder."""
    list_of_files = glob.glob(os.path.join(folder, "*.csv"))
    if not list_of_files:
        return None
    return max(list_of_files, key=os.path.getctime)


def publish_csv_to_rabbitmq(csv_file, channel, queue_name):
    try:
        with open(csv_file, 'r') as f:
            csv_data = f.read()
        channel.basic_publish(exchange='', routing_key=queue_name, body=csv_data.encode('utf-8'))
        print(f"[Publisher] Published CSV {csv_file} to queue '{queue_name}'")
    except Exception as e:
        print(f"[Publisher] Error publishing CSV to RabbitMQ: {e}")


def main():
    # RabbitMQ connection setup
    connection = pika.BlockingConnection(pika.ConnectionParameters('localhost'))
    channel = connection.channel()
    queue_name = 'cicflowmeter_queue'
    channel.queue_declare(queue=queue_name)

    # Paths and settings (modify as needed)
    cfm_path = r"C:\Users\linpa\OneDrive\Desktop\charm\CICFlowMeter-4.0\bin\cfm.bat"
    input_folder = r"C:\Users\linpa\OneDrive\Desktop\Attack_detect\pcap_store"
    output_folder = r"C:\Users\linpa\OneDrive\Desktop\Attack_detect\output_csv"
    interface = "Wi-Fi"  # Use your system’s correct interface name
    capture_duration = 10  # seconds

    while True:
        # Generate a timestamped filename for the pcap
        timestamp = datetime.now().strftime("%Y%m%d_%H%M%S")
        output_pcap = os.path.join(input_folder, f"traffic_{timestamp}.pcap")

        capture_pcap(interface, capture_duration, output_pcap)
        run_cfm(cfm_path, output_pcap, output_folder)

        # Wait a few seconds to ensure the CSV file is fully written
        time.sleep(5)
        latest_csv = get_latest_csv(output_folder)
        if latest_csv:
            publish_csv_to_rabbitmq(latest_csv, channel, queue_name)
        else:
            print("[Publisher] No CSV file found in output folder.")

        # Pause before starting the next capture cycle
        time.sleep(5)

    connection.close()


if __name__ == "__main__":
    main()
