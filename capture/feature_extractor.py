import time
from collections import defaultdict
from scapy.all import Packet, IP, TCP, UDP, ICMP
from utils.logger import system_logger

class FeatureExtractor:
    """
    Extracts CICIDS2017-style features from raw packets per IP.
    Groups packets into "flows" (bidirectional or unidirectional) based on src IP.
    """
    def __init__(self, time_window: int = 60):
        # Dictionary to store features per IP. Key = IP address
        self.flows = defaultdict(lambda: self._default_features())
        self.time_window = time_window # Reset features every X seconds

    def _default_features(self):
        return {
            "Total Fwd Packets": 0,
            "Total Length of Fwd Packets": 0,
            "Fwd Packet Length Max": 0,
            "Fwd Packet Length Min": 0,
            "Fwd Packet Length Mean": 0,
            "Flow Duration": 0,
            "Fwd PSH Flags": 0,
            "Fwd URG Flags": 0,
            "Bwd PSH Flags": 0,
            "Bwd URG Flags": 0,
            "FIN Flag Count": 0,
            "SYN Flag Count": 0,
            "RST Flag Count": 0,
            "PSH Flag Count": 0,
            "ACK Flag Count": 0,
            "URG Flag Count": 0,
            "CWE Flag Count": 0,
            "ECE Flag Count": 0,
            "Down/Up Ratio": 0.0,
            "Average Packet Size": 0.0,
            "Active Mean": 0.0,
            "Active Std": 0.0,
            "Active Max": 0.0,
            "Active Min": 0.0,
            "Idle Mean": 0.0,
            "Idle Std": 0.0,
            "Idle Max": 0.0,
            "Idle Min": 0.0,
            # Custom internal trackers
            "_start_time": time.time(),
            "_last_time": time.time(),
            "_unique_ports": set(),
            "_syn_count": 0,
            "_ack_count": 0
        }

    def process_packet(self, packet: Packet) -> tuple[str, dict] | None:
        """
        Process a single packet and update the flow features for the source IP.
        Returns the (src_ip, feature_dict) if valid IP packet.
        """
        if not IP in packet:
            return None

        src_ip = packet[IP].src
        pkt_len = len(packet)
        current_time = time.time()
        
        flow = self.flows[src_ip]
        
        # Reset if window expired
        if current_time - flow["_start_time"] > self.time_window:
            self.flows[src_ip] = self._default_features()
            flow = self.flows[src_ip]

        # Update base stats
        flow["Total Fwd Packets"] += 1
        flow["Total Length of Fwd Packets"] += pkt_len
        flow["Fwd Packet Length Max"] = max(flow["Fwd Packet Length Max"], pkt_len)
        flow["Fwd Packet Length Min"] = min(flow["Fwd Packet Length Min"], pkt_len) if flow["Total Fwd Packets"] > 1 else pkt_len
        flow["Fwd Packet Length Mean"] = flow["Total Length of Fwd Packets"] / flow["Total Fwd Packets"]
        
        flow["_last_time"] = current_time
        flow["Flow Duration"] = int((flow["_last_time"] - flow["_start_time"]) * 1e6) # microseconds
        
        flow["Average Packet Size"] = flow["Total Length of Fwd Packets"] / flow["Total Fwd Packets"]

        # Protocol specific extraction
        if TCP in packet:
            tcp = packet[TCP]
            flow["_unique_ports"].add(tcp.dport)
            
            # Extract flags safely
            flags = tcp.flags
            if 'S' in flags: flow["SYN Flag Count"] += 1
            if 'A' in flags: flow["ACK Flag Count"] += 1
            if 'F' in flags: flow["FIN Flag Count"] += 1
            if 'R' in flags: flow["RST Flag Count"] += 1
            if 'P' in flags: flow["PSH Flag Count"] += 1
            if 'U' in flags: flow["URG Flag Count"] += 1
            if 'E' in flags: flow["ECE Flag Count"] += 1
            if 'C' in flags: flow["CWE Flag Count"] += 1
            
        elif UDP in packet:
            flow["_unique_ports"].add(packet[UDP].dport)

        # Return a copy of standardized features ready for ML ingestion
        return src_ip, self._format_feature_vector(flow)

    def _format_feature_vector(self, flow: dict) -> dict:
        """Format the internal state into a clean ML-ready dictionary"""
        vector = {k: v for k, v in flow.items() if not k.startswith('_')}
        # Ensure correct types
        return {k: float(v) for k, v in vector.items()}

    def get_flow_stats(self, ip: str) -> dict:
        """Get summarized stats for rule engine"""
        if ip not in self.flows:
            return {}
        flow = self.flows[ip]
        return {
            "req_count": flow["Total Fwd Packets"],
            "unique_ports": len(flow["_unique_ports"]),
            "syn_count": flow["SYN Flag Count"],
            "duration_sec": flow["_last_time"] - flow["_start_time"]
        }
