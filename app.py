from flask import Flask, render_template, jsonify
from flask_cors import CORS
import sys
import os
import numpy as np
import random
import time
import threading

# Add src to path to import detector and sniffer
sys.path.append(os.path.abspath(os.path.join(os.path.dirname(__file__), 'src')))
from detector import CyberAI_Detector
import requests
import socket
import json

# UDP Sniffer Configuration
UDP_IP = "0.0.0.0" # Bind to all interfaces
UDP_PORT = 5005
packet_queue = [] 

# GeoIP Cache to avoid API rate limits
GEO_CACHE = {}
SYSTEM_LOCATION = None

def fetch_system_location():
    """Fetch the public location of this system to use as 'Home Base'"""
    try:
        response = requests.get("http://ip-api.com/json/", timeout=5)
        if response.status_code == 200:
            data = response.json()
            if data['status'] == 'success':
                loc = {
                    "country": data.get('country', 'Unknown'),
                    "region": data.get('regionName', ''),
                    "city": data.get('city', 'Unknown'),
                    "isp": data.get('isp', 'Local Network'),
                    "lat": data.get('lat', 0),
                    "lon": data.get('lon', 0)
                }
                print(f"🌍 System Location Resolved: {loc['city']}, {loc['country']}")
                return loc
    except Exception as e:
        print(f"⚠️ Could not resolve system location: {e}")
    
    # Fallback to a visible location (e.g., NYC) if resolution fails
    return {"country": "United States", "city": "New York", "lat": 40.7128, "lon": -74.0060}

# Initialize System Location on Startup
SYSTEM_LOCATION = fetch_system_location()

def get_geoip(ip):
    """Resolve IP to Location using ip-api.com"""
    # Handle Local/Private IPs
    if ip.startswith("192.168.") or ip.startswith("10.") or ip.startswith("127."):
        # Use System Location but add "Jitter" so dots don't stack perfectly
        base = SYSTEM_LOCATION.copy()
        
        # Add random jitter (~5km variance)
        start_lat = base['lat']
        start_lon = base['lon']
        
        # Consistent jitter based on IP hash would be better, but random is fine for "live" feel
        # actually, let's just do random to make it look like activity in the area
        jitter_lat = random.uniform(-0.05, 0.05)
        jitter_lon = random.uniform(-0.05, 0.05)
        
        base['lat'] = start_lat + jitter_lat
        base['lon'] = start_lon + jitter_lon
        base['city'] = f"{base['city']} (Local)"
        
        return base
        
    if ip in GEO_CACHE:
        return GEO_CACHE[ip]
        
    try:
        response = requests.get(f"http://ip-api.com/json/{ip}", timeout=2)
        if response.status_code == 200:
            data = response.json()
            if data['status'] == 'success':
                geo_data = {
                    "country": data.get('country', 'Unknown'),
                    "region": data.get('regionName', ''),
                    "city": data.get('city', 'Unknown'),
                    "isp": data.get('isp', 'Unknown ISP'),
                    "lat": data.get('lat', 0),
                    "lon": data.get('lon', 0)
                }
                GEO_CACHE[ip] = geo_data
                print(f"🌍 GeoIP Resolved: {ip} -> {geo_data['city']}, {geo_data['country']}")
                return geo_data
    except Exception as e:
        print(f"⚠️ GeoIP Error: {e}")
        pass
    
    return {"country": "Unknown", "city": "Unknown", "lat": 0, "lon": 0}

app = Flask(__name__)
CORS(app)

# Initialize Detector
print("⚡ Initializing CyberAI System...")
detector = CyberAI_Detector(threshold=0.35)

# Global stats
stats = {
    "total_requests": 0,
    "attacks_blocked": 0,
    "current_threat_level": "LOW",
    "last_update": time.time(),
    "attack_types": {"DDoS": 0, "Brute Force": 0, "Malware": 0, "Other": 0},
    "webhook_url": None # Store Discord Webhook URL
}

# Recent traffic log (keep last 50)
traffic_log = []

from flask import request

# Global simulation state
sim_state = {
    "scenario": "NORMAL", # NORMAL, DDOS, BRUTE_FORCE, MIXED
    "threshold": 0.35
}

@app.route('/api/control/scenario', methods=['POST'])
def set_scenario():
    data = request.json
    sim_state["scenario"] = data.get('scenario', 'NORMAL')
    print(f"🔄 Scenario switched to: {sim_state['scenario']}")
    return jsonify({"status": "ok", "scenario": sim_state["scenario"]})

@app.route('/api/control/threshold', methods=['POST'])
def set_threshold():
    data = request.json
    new_threshold = float(data.get('threshold', 0.35))
    sim_state["threshold"] = new_threshold
    detector.threshold = new_threshold
    print(f"🎚️ Threshold adjusted to: {new_threshold}")
    return jsonify({"status": "ok", "threshold": new_threshold})

@app.route('/api/rules', methods=['GET'])
def get_rules():
    return jsonify(detector.get_rules())

@app.route('/api/rules/update', methods=['POST'])
def update_rules():
    data = request.json
    action = data.get('action') # "add" or "remove"
    ip = data.get('ip')
    rule_type = data.get('type') # "whitelist" or "blacklist"
    
    if detector.update_rules(action, ip, rule_type):
        print(f"🛡️ Rule Updated: {action} {ip} to {rule_type}")
        return jsonify({"status": "ok", "rules": detector.get_rules()})
    else:
        return jsonify({"status": "error", "message": "Failed to update rule"})

@app.route('/api/control/webhook', methods=['POST'])
def set_webhook():
    data = request.json
    url = data.get('url')
    if url and url.startswith("https://discord"):
        stats['webhook_url'] = url
        print(f"🔔 Webhook set: {url[:30]}...")
        # Send a test message
        send_discord_alert("✅ CyberAI Alert System Connected!", "INFO")
        return jsonify({"status": "ok", "message": "Webhook Saved & Tested"})
    return jsonify({"status": "error", "message": "Invalid Discord URL"})

def send_discord_alert(message, level="CRITICAL"):
    """Send alert to Discord Webhook (Background Task)"""
    url = stats.get('webhook_url')
    if not url: return

    def _send():
        try:
            color = 16711680 if level == "CRITICAL" else 16753920 # Red or Orange
            payload = {
                "username": "CyberAI Sentinel",
                "embeds": [{
                    "title": f"⚠️ {level} THREAT DETECTED",
                    "description": message,
                    "color": color,
                    "footer": {"text": f"Time: {time.strftime('%H:%M:%S')}"}
                }]
            }
            requests.post(url, json=payload, timeout=5)
        except Exception as e:
            print(f"❌ Webhook Error: {e}")

    # Run in thread to not block the dashboard
    threading.Thread(target=_send, daemon=True).start()

@app.route('/')
def index():
    return render_template('index.html')

import psutil

# Global System State (Updated by background thread)
curr_system_stats = {
    "cpu": 0.0,
    "ram": 0.0,
    "net": 0.0
}

def udp_listener():
    """Receive packets from standalone sniffer_service.py"""
    print(f"📡 UDP Listener active on port {UDP_PORT}")
    sock = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
    sock.bind((UDP_IP, UDP_PORT))
    
    while True:
        try:
            data, addr = sock.recvfrom(4096) # Increase buffer
            packet = json.loads(data.decode())
            packet_queue.append(packet)
            # print(f"🔹 Rx Packet from {addr}: {packet.get('ip')} (Q: {len(packet_queue)})") # Reduce logs
            
            # Keep queue size small
            if len(packet_queue) > 50:
                packet_queue.pop(0)
        except Exception as e:
            print(f"UDP Error: {e}")

def monitor_system():
    """Background thread to monitor system stats efficiently"""
    global curr_system_stats
    last_net = psutil.net_io_counters()
    last_time = time.time()
    
    print("🖥️ System Monitor Thread Started")
    
    # Also start UDP Listener here
    threading.Thread(target=udp_listener, daemon=True).start()
    
    while True:
        try:
            # 1. CPU (Blocking call 1 second = Perfect accuracy)
            cpu = psutil.cpu_percent(interval=1)
            
            # 2. RAM
            ram = psutil.virtual_memory().percent
            
            # 3. Network
            curr_net = psutil.net_io_counters()
            curr_time = time.time()
            
            # Calculate Mb/s
            bytes_sent = curr_net.bytes_sent - last_net.bytes_sent
            bytes_recv = curr_net.bytes_recv - last_net.bytes_recv
            total_bits = (bytes_sent + bytes_recv) * 8
            time_diff = curr_time - last_time
            
            mbps = (total_bits / time_diff) / 1_000_000
            
            # Update Global State
            curr_system_stats = {
                "cpu": cpu,
                "ram": ram,
                "net": round(mbps, 2)
            }
            
            # Reset counters
            last_net = curr_net
            last_time = curr_time
            
        except Exception as e:
            print(f"⚠️ Monitor Error: {e}")
            time.sleep(1)

# Start Monitor Thread
# ONLY start threads if we are in the reloader process (to avoid double execution)
if os.environ.get('WERKZEUG_RUN_MAIN') == 'true':
    print("🖥️ Starting Background Threads...")
    
    # 1. System Monitor
    monitor_thread = threading.Thread(target=monitor_system, daemon=True)
    monitor_thread.start()
    
    # 2. Packet Sniffer
    # DEPRECATED: Direct Sniffer caused freeze. Now using UDP Listener (see monitor_system)
    sniffer = None
else:
    # Dummy sniffer for the main process (to avoid undefined errors if accessed)
    # The main process doesn't handle requests anyway in debug mode
    sniffer = None

@app.route('/api/stats')
def get_stats():
    return jsonify({
        "stats": stats,
        "recent_logs": traffic_log[-10:], 
        "system": curr_system_stats
    })

@app.route('/api/simulate')
def simulate_traffic():
    """Simulate a single request analysis OR use real packet"""
    
    # 1. Try to get REAL packet from UDP Queue
    real_packet = None
    # print(f"DEBUG: Checking Queue. Size: {len(packet_queue)}")
    if len(packet_queue) > 0:
        real_packet = packet_queue.pop(0)
    
    if real_packet:
        # Use Real Data
        proto_map = {"tcp": 1, "udp": 2, "other": 0}
        p_val = proto_map.get(real_packet.get('proto', 'other'), 0)
        bytes_val = real_packet.get('len', 0)
        
        features = [
             0.01,           # duration
             p_val,          # protocol_type 
             0,              # service
             0,              # flag
             bytes_val,      # src_bytes
             0               # dst_bytes
        ] + [0]*35 # Fill rest with zeros
        
        ip = real_packet.get('ip', '0.0.0.0')
        attack_type = "Real Traffic"
        current_scenario = "REAL"
        source_label = "REAL"
    else:
        # GENERATE SIMULATED DATA
        current_scenario = sim_state["scenario"]
        source_label = "SIM"
        
        # Default Features (Normal)
        features = [0.01, 1, 2, 3, random.randint(100, 500), random.randint(500, 1000)] + [0]*35
        ip = f"192.168.1.{random.randint(2, 254)}"
        attack_type = "Normal"

        if current_scenario == "DDOS":
            # DDoS characteristics: High freq, same service, small packets or huge volume
            features[4] = random.randint(1000, 5000) # src_bytes
            features[10] = 255 # count
            attack_type = "DDoS"
            ip = f"{random.randint(1,255)}.{random.randint(1,255)}.{random.randint(1,255)}.{random.randint(1,255)}"
        elif current_scenario == "BRUTE_FORCE":
            # Brute Force: High duration, specific service
            features[0] = 5.0 # duration
            features[30] = 1.0 # srv_diff_host_rate
            attack_type = "Brute Force"
            ip = f"10.0.0.{random.randint(2, 20)}"
        
    result = detector.analyze(features, ip_address=ip)
    
    # 🌟 VISUAL FLAIR: Add "jitter" to probability so graph is never perfectly flat
    # This makes the dashboard look "alive" even during normal traffic
    base_prob = result['attack_probability']
    if not result['is_attack']:
        # Add random noise between 0% and 15% for normal traffic
        noise = random.uniform(0.01, 0.15)
        noise = random.uniform(0.01, 0.15)
        result['attack_probability'] = min(0.99, base_prob + noise)
        
    # 🔔 Remote Alert Logic
    if result['alert_level'] == "CRITICAL" and result['is_attack']:
        # Rate limit alerts (simple check logic could be improved)
        if random.random() < 0.2: # Don't spam, only alert on 20% of criticals for demo
            msg = f"**Attack Blocked!**\nIP: `{ip}`\nType: `{attack_type}`\nConf: `{result['attack_probability']:.2f}`"
            send_discord_alert(msg, "CRITICAL")
    
    # Update global stats
    stats["total_requests"] += 1
    if result['is_attack']:
        stats["attacks_blocked"] += 1
        # Increment specific attack type
        if attack_type in stats["attack_types"]:
            stats["attack_types"][attack_type] += 1
        else:
            stats["attack_types"]["Other"] += 1
    
    # Simple logic to determine overall threat level based on recent history
    if result['alert_level'] in ['HIGH', 'CRITICAL']:
         stats["current_threat_level"] = "HIGH"
    elif result['alert_level'] == 'MEDIUM' and stats["current_threat_level"] != "HIGH":
         stats["current_threat_level"] = "MEDIUM"
    elif stats["total_requests"] % 20 == 0: # Decay threat level occasionally
         stats["current_threat_level"] = "LOW"
         
    
    # Log entry
    log_entry = {
        "id": stats["total_requests"],
        "timestamp": time.strftime("%H:%M:%S"),
        "ip": ip,
        "result": result,
        "geo": get_geoip(ip),
        "source": source_label
    }
    
    traffic_log.append(log_entry)
    if len(traffic_log) > 50:
        traffic_log.pop(0)
        
    return jsonify(log_entry)

if __name__ == '__main__':
    print("🚀 CyberAI Dashboard Remote Link: http://localhost:5000")
    app.run(debug=True, port=5000)
