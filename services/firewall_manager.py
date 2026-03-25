import subprocess
import platform
import re
from utils.logger import system_logger

class FirewallManager:
    """
    Manages IP blocking via iptables on Linux.
    Gracefully degrades/mocks on Windows for local testing.
    """
    def __init__(self):
        self.is_linux = platform.system() == "Linux"
        if not self.is_linux:
            system_logger.warning("Non-Linux OS detected. Firewall actions will be mocked.")

    def _is_valid_ipv4(self, ip: str) -> bool:
        """Strict validation for IPv4 format to prevent command injection"""
        pattern = r"^(?:(?:25[0-5]|2[0-4][0-9]|[01]?[0-9][0-9]?)\.){3}(?:25[0-5]|2[0-4][0-9]|[01]?[0-9][0-9]?)$"
        return bool(re.match(pattern, ip))

    def block_ip(self, ip: str) -> bool:
        """Executes iptables block command"""
        if not self._is_valid_ipv4(ip):
            system_logger.error(f"Firewall block failed: Invalid IP address format -> {ip}")
            return False

        if not self.is_linux:
            system_logger.info(f"[MOCK FIREWALL] Blocked IP: {ip}")
            return True

        # Ensure no duplicate rule exists first (prevent rule bloat)
        check_cmd = ["iptables", "-C", "INPUT", "-s", ip, "-j", "DROP"]
        
        try:
            # Check if rule exists; if it exits with 0, rule exists.
            result = subprocess.run(check_cmd, capture_output=True)
            if result.returncode == 0:
                system_logger.debug(f"Iptables rule already exists for {ip}. Skipping.")
                return True
                
            # Rule doesn't exist, proceed to add
            add_cmd = ["iptables", "-A", "INPUT", "-s", ip, "-j", "DROP"]
            subprocess.run(add_cmd, check=True, capture_output=True)
            system_logger.info(f"Firewall: Hard Block successfully applied via iptables for {ip}")
            return True
        except subprocess.CalledProcessError as e:
            system_logger.error(f"Firewall block failed for {ip}. Requires sudo/root? Error: {e.stderr.decode('utf-8')}")
            return False
        except Exception as e:
            system_logger.error(f"Unexpected firewall error: {e}")
            return False

    def unblock_ip(self, ip: str) -> bool:
        """Removes iptables block command"""
        if not self._is_valid_ipv4(ip):
            return False

        if not self.is_linux:
            system_logger.info(f"[MOCK FIREWALL] Unblocked IP: {ip}")
            return True

        cmd = ["iptables", "-D", "INPUT", "-s", ip, "-j", "DROP"]
        try:
            subprocess.run(cmd, check=True, capture_output=True)
            system_logger.info(f"Firewall: Block removed successfully for {ip}")
            return True
        except subprocess.CalledProcessError as e:
            system_logger.error(f"Firewall unblock failed for {ip}. Error: {e.stderr.decode('utf-8')}")
            return False

firewall = FirewallManager()
