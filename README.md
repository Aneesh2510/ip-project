# Intelligent IP Tracking & Automated Blocking System

A real-time network security project designed to capture, analyze, and automatically block malicious IP traffic using a combination of heuristic rules and Machine Learning (Random Forest/XGBoost).

## 🚀 Features

- **Real-Time Packet Capture**: Asynchronous sniffer built with Scapy.
- **Dual Detection Engine**:
  - **Rule-Based**: Thresholds for request rates, port scanning, and SYN floods.
  - **ML-Based**: Anomaly detection model trained on CICIDS2017 feature vectors.
- **Automated Firewall**: Automatically applies `iptables` drop rules to malicious IPs (Linux only). Windows degrades to mock logs safely.
- **Firebase Integration**: Real-time logging and IP blocklist synchronization via Firestore.
- **Premium Dashboard**: Glassmorphism UI displaying real-time threat charts, live packet feeds via WebSockets, and active blocks.

## 🛠️ Architecture

1. **Packet Capture (`capture/`)**: Extracts raw IP/TCP/UDP packets.
2. **Feature Extractor (`capture/`)**: Translates raw packets into stateful flow features (matching CICIDS2017).
3. **Detection Engine (`detection/`)**: Evaluates features and determines block necessity.
4. **Firewall Manager (`services/`)**: Executes subprocess `iptables`.
5. **API & WebSockets (`api/`, `main.py`)**: Powers the frontend dashboard.
6. **ML Pipeline (`ml/`)**: Trains and evaluates models on massive cyber datasets.

## ⚙️ Prerequisites

- Python 3.10+
- `firebase-adminsdk.json` service account key from your Firebase project.

## 📥 Installation

1. Clone or copy the project directory.
2. Install dependencies:
   ```bash
   pip install -r requirements.txt
   ```
3. Copy the environment variables:
   ```bash
   cp .env.example .env
   ```
4. Configure your `.env` file containing your thresholds and DB path.
5. Place your `firebase-adminsdk.json` in the root folder.

## 🧠 Machine Learning Setup

The system is configured to auto-generate synthetic CICIDS2017-style data if you do not have the 2GB dataset downloaded, so it works out-of-the-box for demonstration.

1. Preprocess data and train the model:
   ```bash
   python ml/train_model.py
   ```
   *This outputs `ids_model.joblib` inside `ml/models/` which the engine automatically uses on boot.*

## 🏃 Running the Application

Start the FastAPI and Sniffer server:
```bash
python main.py
# Server will be live at http://localhost:8000
```

## 🧪 Running Tests
```bash
python -m pytest tests/ -v
```

## 🔥 Firebase Setup Guide
1. Go to [Firebase Console](https://console.firebase.google.com).
2. Create a new project.
3. Access **Firestore Database** and create it in test mode.
4. Go to **Project Settings > Service Accounts**.
5. Click **Generate New Private Key** and save it as `firebase-adminsdk.json` in your project root.
6. The system will automatically construct the following collections:
   - `ip_logs`
   - `blocked_ips`
