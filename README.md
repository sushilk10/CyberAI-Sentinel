# CyberAI Defense System

## Project Overview

This project is a network monitoring and threat detection system that combines real-time packet sniffing with machine learning analysis. It is designed to capture local network traffic, analyze connection patterns, and visualize potential security threats on a web-based dashboard.

---

## 📋 System Requirements

Before running the project, ensure your system meets the following requirements:

### 1. Software Requirements
* **Python 3.8+**: The core backend is built with Python.
* **Npcap (Windows Only)**: Required for the `sniffer_service.py` to capture live network packets. 
    * *Note: During installation, ensure the "Install Npcap in WinPcap API-compatible Mode" option is checked.*
    * Download: [https://npcap.com/#download](https://npcap.com/#download)
* **Web Browser**: Chrome, Firefox, or Edge recommended for the dashboard.

### 2. Main Dependencies
* **Flask**: Web server and API management.
* **Scapy**: Live packet sniffing and header extraction.
* **Scikit-Learn**: Machine learning inference for threat detection.
* **Psutil**: System resource monitoring (CPU/RAM).
* **Requests**: GeoIP resolution and Discord webhook integration.

---

## 🚀 Step-by-Step Setup Guide

Follow these steps exactly to get the system running in an isolated environment.

### Step 1: Clone and Prepare
Open your terminal in the project root directory (`CyberAI-Sentinel`).

### Step 2: Create a Virtual Environment (Recommended)
This keeps the project dependencies separate from your system Python.
```bash
# Create the environment
python -m venv env

# Activate the environment
# On Windows:
.\env\Scripts\activate

# On Linux/Mac:
source env/bin/activate
```

### Step 3: Install Python Dependencies
```bash
pip install -r requirements.txt
```

### Step 4: Install Network Drivers (For Sniffing)
If you are on Windows, download and install **Npcap**. This is essential for the AI to see "Real Traffic". If you skip this, the dashboard will only show simulated traffic.

### Step 5: Launch the System
You need **two separate terminals** running at the same time:

#### **Terminal 1: The AI Dashboard (Main Server)**
```bash
python app.py
```
*   Wait for the message: `🚀 CyberAI Dashboard Remote Link: http://localhost:5000`
*   Open your browser and go to `http://localhost:5000`.

#### **Terminal 2: The Network Sniffer (Real-time Feed)**
```bash
# This must be run as Administrator (Windows) or Sudo (Linux)
python src/sniffer_service.py
```

---

## 🎮 How to Use the Dashboard

1. **Monitor Real-Time Traffic**: Once the Sniffer is running, "LIVE" badges will appear in the log.
2. **Switch Scenarios**: Use the **Command Center** buttons (NORMAL, DDoS, BRUTE FORCE) to test the AI's detection patterns.
3. **Adjust Threshold**: Move the slider to change how strict the AI is.
4. **Discord Integration**: Paste a Discord Webhook URL in the settings to get mobile alerts for critical threats.

---

## Technical Stack & Logic

* **Backend**: Python 3.x, Flask.
* **Network Processing**: Scapy, Npcap.
* **Machine Learning**: Scikit-Learn (Random Forest model).
* **Frontend**: HTML5, CSS3 (Glassmorphism), JavaScript (Chart.js).
* **Data Source**: Model trained on the **NSL-KDD** network security dataset.
