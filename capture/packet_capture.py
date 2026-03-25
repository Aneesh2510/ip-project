import threading
import time
from queue import Queue
from scapy.all import AsyncSniffer, IP
from config import settings
from utils.logger import system_logger
from capture.feature_extractor import FeatureExtractor

class PacketCaptureModule:
    def __init__(self, processing_queue: Queue):
        self.queue = processing_queue
        self.sniffer = None
        self.is_running = False
        self.feature_extractor = FeatureExtractor()

    def start(self):
        """Starts asynchronous packet capture."""
        if self.is_running:
            return

        system_logger.info(f"Starting Packet Capture on interface: {settings.CAPTURE_INTERFACE or 'default'}")
        
        kwargs = {
            "prn": self._packet_handler,
            "filter": "ip", # only capture IP packets
            "store": False  # Don't keep all packets in memory
        }
        
        if settings.CAPTURE_INTERFACE:
            kwargs["iface"] = settings.CAPTURE_INTERFACE

        try:
            self.sniffer = AsyncSniffer(**kwargs)
            self.sniffer.start()
            self.is_running = True
            system_logger.info("Packet capture started successfully.")
        except Exception as e:
            system_logger.error(f"Failed to start packet capture: {e}")
            self.is_running = False

    def stop(self):
        """Stops the packet capture."""
        if self.sniffer and self.is_running:
            system_logger.info("Stopping packet capture...")
            self.sniffer.stop()
            self.is_running = False
            system_logger.info("Packet capture stopped.")

    def _packet_handler(self, packet):
        """
        Callback for each captured packet. Extracts features and routes to queue.
        """
        try:
            # Process packet to extract ML features and aggregated stats
            result = self.feature_extractor.process_packet(packet)
            
            if result:
                src_ip, feature_vector = result
                stats = self.feature_extractor.get_flow_stats(src_ip)
                
                # Push object to queue for detection engines to pick up
                packet_data = {
                    "ip": src_ip,
                    "timestamp": time.time(),
                    "features": feature_vector,
                    "stats": stats
                }
                
                # Use non-blocking queue put to avoid halting capture
                if not self.queue.full():
                    self.queue.put_nowait(packet_data)
                    
        except Exception as e:
            system_logger.error(f"Error processing packet: {e}")

# Singleton/Instance for easier import
packet_queue = Queue(maxsize=10000)
capture_service = PacketCaptureModule(packet_queue)
