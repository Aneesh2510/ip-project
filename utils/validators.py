import re

def is_valid_ipv4(ip: str) -> bool:
    """Strictly validates IPv4 strings to prevent injection."""
    pattern = r"^(?:(?:25[0-5]|2[0-4][0-9]|[01]?[0-9][0-9]?)\.){3}(?:25[0-5]|2[0-4][0-9]|[01]?[0-9][0-9]?)$"
    return bool(re.match(pattern, ip))

def sanitize_input(text: str) -> str:
    """Basic XSS prevention / sanitization for strings."""
    # Remove HTML tags or script elements
    clean = re.sub(r'<[^>]*?>', '', text)
    # Remove semi-colons to prevent basic SQL/Command injection risks
    clean = clean.replace(';', '')
    return clean[:200]  # Enforce length limit
