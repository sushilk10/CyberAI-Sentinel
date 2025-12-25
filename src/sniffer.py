import threading
import queue
import time
import numpy as np

# Global pointer to scapy modules
scapy_all = None

class PacketSniffer:
    def __init__(self):
        self.packet_queue = queue.Queue(maxsize=100)
        self.running = False
        self.sniffer_thread = None
        self.connection_history = [] 

    def start(self):
        if self.running: return
        self.running = True
        self.sniffer_thread = threading.Thread(target=self._sniff_loop, daemon=True)
        self.sniffer_thread.start()
        print("🕵️ Packet Sniffer Started (Background)...")

    def _sniff_loop(self):
        global scapy_all
        print("⏳ Loading Scapy... (This may take a few seconds)")
        try:
            # Lazy Import to prevent startup freeze
            import scapy.all as sa
            scapy_all = sa
            
            print("✅ Scapy Loaded. Starting Capture.")
            # Filter for IP traffic, verify L3Socket usage if needed for Windows
            sa.sniff(filter="ip", prn=self._process_packet, store=0)
        except Exception as e:
            print(f"❌ Sniffer Error: {e}")
            self.running = False

    def _process_packet(self, packet):
        if not self.running: return False
        
        # Use local reference to avoid global lookup issues
        IP = scapy_all.IP
        TCP = scapy_all.TCP
        UDP = scapy_all.UDP
        
        if IP in packet:
            src_ip = packet[IP].src
            dst_ip = packet[IP].dst
            length = len(packet)
            
            # Protocol
            protocol_type = "other"
            if TCP in packet: protocol_type = "tcp"
            elif UDP in packet: protocol_type = "udp"
            
            # Create a "Feature Vector" for the AI Model
            # Note: Real ML models need 41 precise features. We will calculate real ones where possible
            # and approximate complex time-based stats to keep the demo responsive.
            
            features = self._extract_features(packet, protocol_type, length)
            
            packet_data = {
                "ip": src_ip,
                "dst": dst_ip,
                "proto": protocol_type,
                "len": length,
                "features": features
            }
            
            if self.packet_queue.full():
                try: self.packet_queue.get_nowait() # Drop oldest
                except: pass
                
            self.packet_queue.put(packet_data)

    def _extract_features(self, packet, proto, length):
        # Approximating KDDCup99 features from live packet
        # [duration, protocol_type_int, service_int, flag_int, src_bytes, dst_bytes, ...]
        
        # 1. Basic Transformation
        proto_map = {"tcp": 0, "udp": 1, "icmp": 2, "other": 3}
        p_int = proto_map.get(proto, 3)
        
        # 2. Add to history for temporal features
        now = time.time()
        self.connection_history.append(now)
        # Keep only last 2 seconds
        self.connection_history = [t for t in self.connection_history if now - t < 2]
        
        # count (collisions in last 2 sec)
        count = len(self.connection_history)
        
        # 3. Construct Feature Vector (41 dimensions)
        # We fill unknown values with averages/zeros to satisfy the model input shape
        features = [
            0,              # duration (0 for single packet view)
            p_int,          # protocol_type
            0,              # service (http/ftp etc - complex to parse, default to 0)
            0,              # flag (SF/S0 etc - default to Normal)
            length,         # src_bytes
            0,              # dst_bytes (unknown in single sniffer direction usually)
            0,              # land
            0,              # wrong_fragment
            0,              # urgent
        ]
        
        # Fill remaining 32 features with reasonable defaults or calculated temporal stats
        # Indices 22 (count) and 23 (srv_count) are important
        remaining = [0] * 32
        remaining[13] = count # 'count' feature (index 22 in total list roughly)
        
        return features + remaining

    def get_packet(self):
        if not self.packet_queue.empty():
            return self.packet_queue.get()
        return None

if __name__ == "__main__":
    # Test
    sniffer = PacketSniffer()
    sniffer.start()
    while True:
        pkt = sniffer.get_packet()
        if pkt:
            print(f"Captured: {pkt['ip']} -> {pkt['dst']} [{pkt['proto']}]")
        time.sleep(0.1)
