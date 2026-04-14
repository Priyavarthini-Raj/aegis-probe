# alert_parser.py
# This file reads a security alert and extracts key information

def parse_alert(alert_text):
    """
    Takes a raw security alert text and returns structured data
    """
    print("\n[*] Parsing Alert...")
    
    # Store the parsed alert info
    parsed = {
        "raw_alert": alert_text,
        "length": len(alert_text),
        "keywords": []
    }
    
    # Check for common attack keywords
    attack_keywords = [
        "failed", "login", "ssh", "brute", "force",
        "port scan", "malware", "unauthorized", "blocked",
        "denied", "suspicious", "attack", "exploit"
    ]
    
    # Find which keywords are in the alert
    alert_lower = alert_text.lower()
    for keyword in attack_keywords:
        if keyword in alert_lower:
            parsed["keywords"].append(keyword)
    
    # Try to find IP addresses in the alert
    import re
    ip_pattern = r'\b(?:\d{1,3}\.){3}\d{1,3}\b'
    ips_found = re.findall(ip_pattern, alert_text)
    parsed["ips"] = ips_found
    
    print(f"[+] Keywords found: {parsed['keywords']}")
    print(f"[+] IPs found: {parsed['ips']}")
    
    return parsed


# Test it
if __name__ == "__main__":
    # Sample alert to test
    test_alert = "Failed SSH login attempts: 500 tries in 2 mins from IP 192.168.1.105"
    
    result = parse_alert(test_alert)
    print("\n--- Parsed Result ---")
    print(result)