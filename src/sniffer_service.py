import socket
import json
import time
import threading
import sys

# Configuration
DASHBOARD_IP = "127.0.0.1"
DASHBOARD_PORT = 5005

# Ensure Npcap is in PATH
import os
os.environ["PATH"] += os.pathsep + r"C:\Program Files\Npcap"

print("🕵️ CyberAI Sniffer Service Starting...")
print("Please wait while loading Network Drivers (Scapy/Npcap)...")

try:
    from scapy.all import sniff, IP, TCP, UDP
    print("✅ Drivers Loaded Successfully!")
except ImportError:
    print("❌ Error: Scapy not installed. Run 'pip install scapy'")
    sys.exit(1)
except Exception as e:
    print(f"❌ Error loading Scapy: {e}")
    sys.exit(1)

# UDP Socket for sending data
sock = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
sock.bind(('0.0.0.0', 0)) # Bind to ephemeral port explicitly for Windows compatibility

def process_packet(packet):
    """Extract features and send to Dashboard"""
    if IP in packet:
        try:
            src_ip = packet[IP].src
            dst_ip = packet[IP].dst
            length = len(packet)
            
            protocol = "other"
            if TCP in packet: protocol = "tcp"
            elif UDP in packet: protocol = "udp"
            
            # Simplified feature extraction for JSON transport
            # The complex feature vector construction will happen in app.py or here
            # For now, we send raw attributes and let app.py map it for the AI model
            
            packet_data = {
                "ip": src_ip,
                "dst": dst_ip,
                "proto": protocol,
                "len": length,
                "timestamp": time.time()
            }
            
            print(f"📡 Sending: {src_ip} -> {dst_ip} [{protocol}]")
            
            # Send to Dashboard
            message = json.dumps(packet_data).encode('utf-8')
            sock.sendto(message, (DASHBOARD_IP, DASHBOARD_PORT))
            
        except Exception as e:
            print(f"⚠️ Packet Error: {e}")

def start_sniffing():
    print(f"🚀 Sniffer Active! Forwarding to {DASHBOARD_IP}:{DASHBOARD_PORT}")
    try:
        # Filter for IP traffic
        sniff(filter="ip", prn=process_packet, store=0)
    except KeyboardInterrupt:
        print("\n🛑 Sniffer Stopped.")
        sys.exit(0)
    except Exception as e:
        print(f"❌ Capture Error: {e}")
        print("💡 Hint: Ensure Npcap is installed and you are running as Admin.")

if __name__ == "__main__":
    start_sniffing()
