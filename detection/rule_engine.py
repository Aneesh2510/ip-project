from config import settings
from utils.logger import system_logger

class RuleEngine:
    """
    Evaluates basic threshold-based heuristics to detect malicious IP behavior.
    """
    def __init__(self):
        self.max_req = settings.MAX_REQUESTS_PER_MINUTE
        self.max_ports = settings.MAX_PORTS_SCANNED

    def evaluate(self, ip: str, stats: dict) -> dict:
        """
        Evaluate traffic stats against predefined rules.
        Returns a dict with 'triggered' (bool) and 'reasons' (list).
        
        Expected stats structure:
        {
            "req_count": int,
            "unique_ports": int,
            "syn_count": int,
            "duration_sec": float
        }
        """
        reasons = []
        
        # 1. High request rate (DDoS / Brute force indication)
        duration = stats.get("duration_sec", 1.0)
        # Avoid division by zero
        duration = max(duration, 0.1) 
        
        req_count = stats.get("req_count", 0)
        req_per_min = (req_count / duration) * 60
        
        if req_per_min > self.max_req:
            reasons.append(f"High request rate: {req_per_min:.1f} req/min (> {self.max_req})")

        # 2. Port scanning detection
        unique_ports = stats.get("unique_ports", 0)
        if unique_ports > self.max_ports:
            reasons.append(f"Port scanning detected: {unique_ports} ports accessed (> {self.max_ports})")

        # 3. SYN Flood detection
        syn_count = stats.get("syn_count", 0)
        # If more than 50% of packets are SYN packets and total count is significant
        if req_count > 20 and (syn_count / req_count) > 0.5:
            reasons.append(f"Potential SYN flood: {syn_count}/{req_count} SYN packets")

        is_triggered = len(reasons) > 0
        
        if is_triggered:
            system_logger.warning(f"[RuleEngine] IP {ip} flagged. Reasons: {', '.join(reasons)}")

        return {
            "triggered": is_triggered,
            "reasons": reasons
        }
