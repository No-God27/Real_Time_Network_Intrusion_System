import os
import time
import pyshark

class PcapCapture:
    def __init__(self, interface_name, output_file):
        self.capture = None
        self.interface = interface_name
        self.output_file = output_file

    def start(self, packet_count=100):
        print("*** Starting packet capture *** ")
        self.capture = pyshark.LiveCapture(interface=self.interface, output_file=self.output_file)
        self.capture.sniff(packet_count=packet_count)

    def stop(self):
        print("*** Stopping packet capture *** ")
        self.capture.close()

class PcapToNetFlow():
    def __init__(self, pcap_file_name):
        self.pcap_file_name = pcap_file_name

    def convert(self):
        output_dir = "C:\\Users\\linpa\\OneDrive\\Documents\\output"
        os.makedirs(output_dir, exist_ok=True)
        cfm_path = "C:\\Users\\linpa\\OneDrive\\Desktop\\charm\\CICFlowMeter-4.0\\bin\\cfm.bat"
        cmd = f"\"{os.path.normpath(cfm_path)}\" \"{os.path.normpath(self.pcap_file_name)}\" \"{os.path.normpath(output_dir)}\""
        print(f"Running conversion command: {cmd}")
        result = os.system(cmd)
        print(f"Conversion result: {result}")
        return os.path.join(output_dir, f"{os.path.basename(self.pcap_file_name)}_Flow.csv")

if __name__ == "__main__":
    # check starting time
    start = time.process_time()

    # sniff live packet
    pcap_store_folder = "C:\\Users\\linpa\\OneDrive\\Documents\\pcap_store"
    os.makedirs(pcap_store_folder, exist_ok=True)
    timestamp = time.strftime("%Y%m%d_%H%M%S")
    filename = os.path.join(pcap_store_folder, f"traffic_{timestamp}.pcap")
    interface = "Wi-Fi"  # Corrected interface name for Windows

    cap = PcapCapture(interface_name=interface, output_file=filename)
    cap.start(packet_count=100)  # Capture 100 packets
    cap.stop()

    # convert to netflow csv
    nc = PcapToNetFlow(pcap_file_name=filename)
    csv = nc.convert()

    # your code here
    print(f"NetFlow CSV file generated: {csv}")
    print(time.process_time() - start)
