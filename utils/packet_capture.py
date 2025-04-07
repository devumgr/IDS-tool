import time
import os
from scapy.all import sniff, IP, TCP, get_if_list, UDP, ICMP # Importing necessary modules from scapy library
from collections import deque


class PacketCapture:
    def __init__ (self, interface="Wi-Fi", buffer_size=1000):
        self.interface = interface
        self.buffer = deque(maxlen=buffer_size)
        self.running = False
    
    def _packet_handler(self, packet):
        parsed = self.parse_packet(packet)
        if parsed:
            self.buffer.append(parsed)
            return parsed
    
    def parse_packet(self, packet):
        if not packet.haslayer(IP):
            return None

        layers = []
        current_layer = packet
        while current_layer:
            layers.append(current_layer.name)
            current_layer = current_layer.payload

        return {
            'timestamp': time.strftime('%Y-%m-%d %H:%M:%S', time.localtime(packet.time)),
            'src_ip': packet[IP].src,
            'dst_ip': packet[IP].dst,
            'protocol': layers[1] if len(layers) > 1 else 'N/A',
            'src_port': packet.sport if hasattr(packet, 'sport') else None,
            'dst_port': packet.dport if hasattr(packet, 'dport') else None,
            'length': len(packet),
            'flags': self._get_flags(packet),
            'payload': str(packet.payload) if hasattr(packet, 'payload') else None
        }
    
    def _get_flags(self, packet):

        if packet.haslayer(TCP):
            return {
                'SYN': packet[TCP].flags.S,
                'ACK': packet[TCP].flags.A,
                'FIN': packet[TCP].flags.F,
                'RST': packet[TCP].flags.R,
                'URG': packet[TCP].flags.U,
                'PSH': packet[TCP].flags.P
            }
        return {}
    
    def start(self, filter=None):
        self.running = True
        sniff(iface=self.interface,
              prn=self._packet_handler,
              filter=filter)
        
    def stop(self):
        self.running = False