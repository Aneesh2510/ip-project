import threading
from detection.rule_engine import RuleEngine
from detection.ml_engine import MLEngine
from utils.logger import system_logger
from services.firebase_service import firebase_db
from services.firewall_manager import firewall

class DecisionEngine:
    def __init__(self):
        self.rule_engine = RuleEngine()
        self.ml_engine = MLEngine()
        # Keep track of already blocked IPs in-memory to prevent duplicate actions
        self.blocked_ips = set()
        self._lock = threading.Lock()

    def evaluate_traffic(self, ip: str, features: dict, stats: dict):
        """
        Takes raw features and stats, passes them to Rule & ML engines,
        and makes a final blocking decision.
        """
        # Skip evaluation if already blocked
        with self._lock:
            if ip in self.blocked_ips:
                return

        # 1. Rule-Based Evaluation
        rule_result = self.rule_engine.evaluate(ip, stats)
        
        # 2. ML-Based Evaluation
        ml_result = self.ml_engine.evaluate(ip, features)
        
        # 3. Decision Logic
        is_malicious = rule_result["triggered"] or ml_result["is_malicious"]
        
        # Log all traffic to Firebase asynchronously
        firebase_db.log_traffic(ip, stats.get("req_count", 1), is_malicious)

        # 4. Action
        if is_malicious:
            reasons = rule_result.get("reasons", [])
            if ml_result["is_malicious"]:
                reasons.append(f"ML Anomaly (Conf: {ml_result['confidence']:.2f})")
                
            reason_str = " | ".join(reasons)
            
            self._block_ip(ip, reason_str, ml_result["confidence"])

    def _block_ip(self, ip: str, reason: str, confidence: float):
        """Handles the actual blocking mechanism and state updates"""
        with self._lock:
            if ip in self.blocked_ips:
                return
            self.blocked_ips.add(ip)

        system_logger.error(f"DECISION ENGINE: Blocking IP {ip}! Reason: {reason}")
        
        # Apply Firewall Rule
        success = firewall.block_ip(ip)
        
        if success:
            # Sync to Firebase
            firebase_db.add_blocked_ip(ip, reason, confidence)
        else:
            system_logger.error(f"Failed to implement block for {ip} at the firewall level.")
        
    def sync_blocked_list(self, ips: list[str]):
        """Sync in-memory blocked list with Database at startup"""
        with self._lock:
            for ip in ips:
                self.blocked_ips.add(ip)

# Global singleton instance
decision_engine = DecisionEngine()
