import os
from datetime import datetime
import firebase_admin
from firebase_admin import credentials, firestore
from config import settings
from utils.logger import system_logger

class FirebaseService:
    def __init__(self):
        self.db = None
        self.is_connected = False
        self._initialize()

    def _initialize(self):
        cred_path = settings.FIREBASE_CREDENTIALS_PATH
        if not os.path.exists(cred_path):
            system_logger.warning(f"Firebase credentials not found at {cred_path}. Database writes will be mocked.")
            return

        try:
            # Prevent double initialization if module is reloaded
            if not firebase_admin._apps:
                cred = credentials.Certificate(cred_path)
                firebase_admin.initialize_app(cred)
            
            self.db = firestore.client()
            self.is_connected = True
            system_logger.info("Firebase Firestore connected successfully.")
        except Exception as e:
            system_logger.error(f"Failed to initialize Firebase: {e}")

    def log_traffic(self, ip: str, request_count: int, is_malicious: bool):
        """Log a traffic summary packet to ip_logs"""
        if not self.is_connected:
            return
            
        try:
            doc_ref = self.db.collection('ip_logs').document()
            doc_ref.set({
                "ip": ip,
                "timestamp": firestore.SERVER_TIMESTAMP,
                "request_count": request_count,
                "status": "blocked" if is_malicious else "allowed"
            })
        except Exception as e:
            system_logger.error(f"Firebase logging error (ip_logs): {e}")

    def add_blocked_ip(self, ip: str, reason: str, confidence: float):
        """Add IP to the blocked_ips collection"""
        if not self.is_connected:
            return

        try:
            doc_ref = self.db.collection('blocked_ips').document(ip)
            doc_ref.set({
                "ip": ip,
                "reason": reason,
                "confidence": confidence,
                "blocked_at": firestore.SERVER_TIMESTAMP,
                "active": True
            })
            system_logger.info(f"Firebase: Successfully synced blocked IP {ip}")
        except Exception as e:
            system_logger.error(f"Firebase sync error (blocked_ips): {e}")

    def remove_blocked_ip(self, ip: str):
        """Mark a blocked IP as inactive (unblocked)"""
        if not self.is_connected:
            return

        try:
            doc_ref = self.db.collection('blocked_ips').document(ip)
            doc_ref.update({
                "active": False,
                "unblocked_at": firestore.SERVER_TIMESTAMP
            })
            system_logger.info(f"Firebase: Marked IP {ip} as unblocked")
        except Exception as e:
            system_logger.error(f"Firebase update error for unblock: {e}")

    def get_all_blocked_ips(self) -> list[str]:
        """Fetch all currently active blocked IPs (for startup sync)"""
        if not self.is_connected:
            return []
            
        try:
            ips = []
            docs = self.db.collection('blocked_ips').where('active', '==', True).stream()
            for doc in docs:
                ips.append(doc.to_dict().get('ip'))
            return ips
        except Exception as e:
            system_logger.error(f"Firebase read error (blocked_ips): {e}")
            return []

# Thread-safe global instance
firebase_db = FirebaseService()
