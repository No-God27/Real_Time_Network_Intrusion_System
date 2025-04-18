import os
import time
import subprocess

class PcapCapture:
    def __init__(self, interface_name, output_file):
        self.capture = None
        self.interface = interface_name
        self.output_file = output_file

    def start(self, packet_count=100):
        print("*** Starting packet capture *** ")
        import pyshark
        self.capture = pyshark.LiveCapture(interface=self.interface, output_file=self.output_file)
        self.capture.sniff(packet_count=packet_count)

    def stop(self):
        print("*** Stopping packet capture *** ")
        self.capture.close()


class PcapToNetFlow:
    def __init__(self, pcap_file_name):
        self.pcap_file_name = pcap_file_name

    def convert(self):
        output_dir = "C:\\Users\\linpa\\OneDrive\\Documents\\output"
        os.makedirs(output_dir, exist_ok=True)  # Ensure output directory exists
        cfm_path = "C:\\Users\\linpa\\OneDrive\\Desktop\\charm\\CICFlowMeter-4.0\\bin\\cfm.bat"

        # Properly format command arguments
        cmd = [
            os.path.normpath(cfm_path),
            os.path.normpath(self.pcap_file_name),
            os.path.normpath(output_dir)
        ]

        try:
            print(f"Running conversion command: {' '.join(cmd)}")
            result = subprocess.run(cmd, check=True, capture_output=True, text=True)
            print(f"Conversion succeeded:\n{result.stdout}")
        except subprocess.CalledProcessError as e:
            print(f"Conversion failed with error:\n{e.stderr}")

        # Return the expected CSV file path
        return os.path.join(output_dir, f"{os.path.basename(self.pcap_file_name)}_Flow.csv")


if __name__ == "__main__":
    # Measure starting time
    start = time.process_time()

    # Set up directories and filenames
    pcap_store_folder = "C:\\Users\\linpa\\OneDrive\\Documents\\pcap_store"
    os.makedirs(pcap_store_folder, exist_ok=True)
    timestamp = time.strftime("%Y%m%d_%H%M%S")
    filename = os.path.join(pcap_store_folder, f"traffic_{timestamp}.pcap")
    interface = "Wi-Fi"  # Correct interface name for Windows

    # Capture live packets
    cap = PcapCapture(interface_name=interface, output_file=filename)
    cap.start(packet_count=100)  # Capture 100 packets
    cap.stop()

    # Convert to NetFlow CSV
    nc = PcapToNetFlow(pcap_file_name=filename)
    csv = nc.convert()

    # Print results and execution time
    print(f"NetFlow CSV file generated: {csv}")
    print(f"Execution time: {time.process_time() - start:.2f} seconds")
