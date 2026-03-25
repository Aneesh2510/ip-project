# Deployment Guide (Ubuntu / Debian Server)

For academic or demo production setups without using Docker.

## 1. System Preparation

SSH into your Linux server and update packages:
```bash
sudo apt update && sudo apt upgrade -y
sudo apt install python3-pip python3-venv git iptables -y
```

## 2. Setup Application

1. Clone the repository:
```bash
git clone <your-repo-url> /opt/ip-tracker
cd /opt/ip-tracker
```

2. Create a virtual environment and install dependencies:
```bash
python3 -m venv venv
source venv/bin/activate
pip install -r requirements.txt
```

3. Configure Environment + Firebase:
```bash
cp .env.example .env
nano .env # Set your configuration limits
```
*Ensure you upload `firebase-adminsdk.json` to the server root via `scp` or SFTP.*

## 3. Train the ML Model
Generate the model locally on the server before starting:
```bash
python ml/train_model.py
```

## 4. Run as a Systemd Service

To keep the application running continuously and automatically restart on failure, create a Service:

```bash
sudo nano /etc/systemd/system/iptracker.service
```

Paste the following:
```ini
[Unit]
Description=Intelligent IP Tracking & Firewall Service
After=network.target

[Service]
User=root
WorkingDirectory=/opt/ip-tracker
Environment="PATH=/opt/ip-tracker/venv/bin"
ExecStart=/opt/ip-tracker/venv/bin/python main.py
Restart=always
RestartSec=3

[Install]
WantedBy=multi-user.target
```

*Note: The app runs as `root` because modifying `iptables` and capturing low-level packets requires Sudo privileges.*

## 5. Start the Service

Enable and start the service:
```bash
sudo systemctl daemon-reload
sudo systemctl start iptracker
sudo systemctl enable iptracker
```

Check logs to ensure it's functioning:
```bash
sudo journalctl -u iptracker -f
```

## 6. Security Note
- Access the dashboard at `http://<YOUR_SERVER_IP>:8000`
- To secure the dashboard, it is recommended to set up Nginx as a Reverse Proxy and generate SSL certs using `certbot` and `Let's Encrypt`.
