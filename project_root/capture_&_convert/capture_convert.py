import pika
import json
import pyshark
import subprocess
import os
import time
from datetime import datetime
import threading


class CaptureSystem:
    def __init__(self):
        self.connection = pika.BlockingConnection(
            pika.ConnectionParameters('localhost')
        )
        self.channel = self.connection.channel()

        # Set up queues
        self.channel.queue_declare(queue='csv_tasks', durable=True)
        self.channel.queue_declare(queue='alerts', durable=True)

        # Configuration
        self.config = {
            'cfm_path': r"C:\Users\linpa\OneDrive\Desktop\charm\CICFlowMeter-4.0\bin\cfm.bat",
            'pcap_dir': r"C:\Users\linpa\OneDrive\Desktop\Attack_detect\pcap_store",
            'output_dir': r"C:\Users\linpa\OneDrive\Desktop\Attack_detect\output_csv",
            'interface': "Wi-Fi",
            'capture_interval': 10,
            'emergency_interval': 2
        }

        os.makedirs(self.config['pcap_dir'], exist_ok=True)
        os.makedirs(self.config['output_dir'], exist_ok=True)

    def start_alert_listener(self):
        self.channel.basic_consume(
            queue='alerts',
            on_message_callback=self.handle_alert,
            auto_ack=True
        )
        threading.Thread(target=self.channel.start_consuming).start()

    def handle_alert(self, ch, method, properties, body):
        alert = json.loads(body)
        print(f"EMERGENCY: Detected {alert['attack_type']} at {alert['timestamp']}")
        self.activate_emergency_mode()

    def activate_emergency_mode(self):
        print("Entering emergency capture mode!")
        self.config['capture_interval'] = self.config['emergency_interval']

    def capture_cycle(self):
        while True:
            try:
                timestamp = datetime.now().strftime("%Y%m%d_%H%M%S")
                pcap_file = os.path.join(self.config['pcap_dir'], f"capture_{timestamp}.pcap")

                # Capture packets
                capture = pyshark.LiveCapture(
                    interface=self.config['interface'],
                    output_file=pcap_file
                )
                capture.sniff(timeout=self.config['capture_interval'])

                # Convert to CSV
                csv_path = self.convert_to_csv(pcap_file)

                # Send to analysis queue
                self.channel.basic_publish(
                    exchange='',
                    routing_key='csv_tasks',
                    body=json.dumps({'csv_path': csv_path}),
                    properties=pika.BasicProperties(
                        delivery_mode=2  # Make message persistent
                    )
                )

                print(f"Captured and sent {csv_path}")

            except Exception as e:
                print(f"Capture error: {str(e)}")
                time.sleep(5)

    def convert_to_csv(self, pcap_path):
        original_dir = os.getcwd()
        try:
            bin_dir = os.path.dirname(self.config['cfm_path'])
            os.chdir(bin_dir)

            output_file = os.path.join(
                self.config['output_dir'],
                f"analysis_{os.path.basename(pcap_path).split('.')[0]}.csv"
            )

            subprocess.run(
                f"cfm.bat {pcap_path} {self.config['output_dir']}",
                shell=True,
                check=True,
                capture_output=True
            )

            return output_file
        finally:
            os.chdir(original_dir)

    def run(self):
        self.start_alert_listener()
        self.capture_cycle()


if __name__ == "__main__":
    cs = CaptureSystem()
    cs.run()