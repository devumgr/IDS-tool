from utils.packet_capture import PacketCapture
from detectors.signature_based import SignatureDetector
from collections import deque

class MainIDS:
    def __init__(self):
        self.sniffer = PacketCapture(interface="Wi-Fi")
        self.signature_detector = SignatureDetector(rule_file="rules/snort.rules")
        self.packet_buffer = deque(maxlen=1000)
    
    def process_packet(self, packet):
        alerts = self.signature_detector.analyze(packet)
        if alerts:
            for alert in alerts:
                print(f"Alert: {alert['description']} | Severity: {alert['severity']} | Timestamp: {alert['timestamp']}")
                self.packet_buffer.append(packet)
    def run(self):
        try:
            print("Starting packet capture...")
            self.sniffer.start(filter="ip")
            while True:
                packet = self.sniffer.buffer.popleft()
                if packet:
                    self.process_packet(packet)
        except KeyboardInterrupt:
            print("Stopping packet capture...")

if __name__ == '__main__':
    main = MainIDS()
    main.run()