# realtime_monitor.py
# Real-time Windows Event Log Monitor for Aegis Probe
# Monitors critical security events and triggers investigations

import win32evtlog
import win32evtlogutil
import win32security
import win32con
import threading
import time
import json
from datetime import datetime
from alert_parser import parse_alert
from hypothesis_engine import generate_hypotheses
from probe_engine import run_probes
from evidence_ledger import init_database, save_investigation
from email_alert import send_danger_alert

# ── Event IDs to Monitor ──
MONITORED_EVENTS = {
    4625: {
        "name": "Failed Login",
        "severity": "High",
        "category": "Brute Force",
        "description": "Failed login attempt detected"
    },
    4720: {
        "name": "New User Created",
        "severity": "Critical",
        "category": "Backdoor",
        "description": "New user account created — possible backdoor"
    },
    4732: {
        "name": "Added to Admin Group",
        "severity": "Critical",
        "category": "Privilege Escalation",
        "description": "User added to administrators group"
    },
    4698: {
        "name": "Scheduled Task Created",
        "severity": "High",
        "category": "Persistence",
        "description": "New scheduled task created — possible persistence"
    },
    4688: {
        "name": "New Process Created",
        "severity": "Medium",
        "category": "Process Execution",
        "description": "New process created — check for malware"
    },
    1116: {
        "name": "Malware Detected",
        "severity": "Critical",
        "category": "Malware",
        "description": "Windows Defender detected malware!"
    },
    4740: {
        "name": "Account Locked Out",
        "severity": "High",
        "category": "Brute Force",
        "description": "Account locked due to failed attempts"
    },
    4719: {
        "name": "Audit Policy Changed",
        "severity": "Critical",
        "category": "Covering Tracks",
        "description": "Security audit policy was changed"
    },
    7045: {
        "name": "New Service Installed",
        "severity": "High",
        "category": "Persistence",
        "description": "New service installed — possible rootkit"
    },
    5157: {
        "name": "Connection Blocked",
        "severity": "Medium",
        "category": "Network",
        "description": "Firewall blocked suspicious connection"
    }
}

# ── Suspicious Process Names ──
SUSPICIOUS_PROCESSES = [
    "mimikatz", "meterpreter", "beacon",
    "cobaltstrike", "nc.exe", "netcat",
    "psexec", "wce.exe", "fgdump",
    "pwdump", "xmrig", "cryptominer"
]

# ── Failed Login Tracker (for brute force detection) ──
failed_login_tracker = {}
BRUTE_FORCE_THRESHOLD = 5
BRUTE_FORCE_WINDOW = 60  # seconds

# Store for real-time events (shared with dashboard)
realtime_events = []
import os
_MONITOR_FLAG_FILE = "D:\\aegis_probe\\monitor_active.flag"

def is_monitoring_active():
    return os.path.exists(_MONITOR_FLAG_FILE)

monitoring_active = False


def extract_event_details(event, event_id):
    """
    Extracts useful details from a Windows Event Log entry
    """
    details = {
        "event_id": event_id,
        "event_name": MONITORED_EVENTS.get(event_id, {}).get("name", "Unknown"),
        "severity": MONITORED_EVENTS.get(event_id, {}).get("severity", "Medium"),
        "category": MONITORED_EVENTS.get(event_id, {}).get("category", "Unknown"),
        "timestamp": datetime.now().strftime("%Y-%m-%d %H:%M:%S"),
        "computer": event.ComputerName,
        "username": "Unknown",
        "ip_address": "Unknown",
        "process_name": "Unknown",
        "raw_message": ""
    }

    try:
        # Get event message
        msg = win32evtlogutil.SafeFormatMessage(event, "Security")
        details["raw_message"] = msg[:500] if msg else ""

        # Extract username
        if event.StringInserts:
            inserts = list(event.StringInserts)

            # Different events store username in different positions
            if event_id == 4625 and len(inserts) > 5:
                details["username"] = inserts[5] or "Unknown"
                details["ip_address"] = inserts[19] if len(inserts) > 19 else "Unknown"

            elif event_id == 4720 and len(inserts) > 0:
                details["username"] = inserts[0] or "Unknown"

            elif event_id == 4732 and len(inserts) > 0:
                details["username"] = inserts[0] or "Unknown"

            elif event_id == 4688 and len(inserts) > 5:
                details["process_name"] = inserts[5] or "Unknown"
                details["username"] = inserts[1] or "Unknown"

            elif event_id == 4698 and len(inserts) > 0:
                details["username"] = inserts[0] or "Unknown"

    except Exception as e:
        print(f"[!] Error extracting event details: {e}")

    return details


def check_brute_force(details):
    """
    Detects brute force attacks by counting failed logins
    """
    if details["event_id"] != 4625:
        return False

    ip = details.get("ip_address", "Unknown")
    now = time.time()

    if ip not in failed_login_tracker:
        failed_login_tracker[ip] = []

    # Add current attempt
    failed_login_tracker[ip].append(now)

    # Remove old attempts outside window
    failed_login_tracker[ip] = [
        t for t in failed_login_tracker[ip]
        if now - t < BRUTE_FORCE_WINDOW
    ]

    count = len(failed_login_tracker[ip])
    print(f"[*] Failed logins from {ip}: {count}")

    return count >= BRUTE_FORCE_THRESHOLD


def check_suspicious_process(details):
    """
    Checks if a new process is suspicious
    """
    if details["event_id"] != 4688:
        return False

    process = details.get("process_name", "").lower()
    return any(sus in process for sus in SUSPICIOUS_PROCESSES)


def build_alert_text(details):
    """
    Builds a security alert text from event details
    """
    event_id = details["event_id"]
    timestamp = details["timestamp"]
    computer = details["computer"]
    username = details["username"]
    ip = details["ip_address"]
    process = details["process_name"]
    category = details["category"]
    severity = details["severity"]

    if event_id == 4625:
        if check_brute_force(details):
            return (
                f"BRUTE FORCE ATTACK DETECTED on {computer}! "
                f"Multiple failed login attempts for user {username} "
                f"from IP {ip} at {timestamp}. "
                f"Exceeded {BRUTE_FORCE_THRESHOLD} attempts in "
                f"{BRUTE_FORCE_WINDOW} seconds."
            )
        return (
            f"Failed login attempt on {computer} "
            f"for user {username} from IP {ip} at {timestamp}"
        )

    elif event_id == 4720:
        return (
            f"SUSPICIOUS: New user account created on {computer}! "
            f"New username: {username} at {timestamp}. "
            f"Possible backdoor account creation by attacker."
        )

    elif event_id == 4732:
        return (
            f"PRIVILEGE ESCALATION DETECTED on {computer}! "
            f"User {username} was added to Administrators group "
            f"at {timestamp}. Immediate investigation required."
        )

    elif event_id == 4698:
        return (
            f"PERSISTENCE MECHANISM DETECTED on {computer}! "
            f"New scheduled task created by {username} "
            f"at {timestamp}. Possible attacker persistence."
        )

    elif event_id == 4688:
        if check_suspicious_process(details):
            return (
                f"MALICIOUS PROCESS DETECTED on {computer}! "
                f"Suspicious process {process} started by "
                f"{username} at {timestamp}. Possible malware execution."
            )
        return (
            f"New process created on {computer}: "
            f"{process} by {username} at {timestamp}"
        )

    elif event_id == 1116:
        return (
            f"MALWARE DETECTED by Windows Defender on {computer}! "
            f"Immediate isolation and investigation required. "
            f"Detected at {timestamp}."
        )

    elif event_id == 4740:
        return (
            f"Account lockout on {computer}! "
            f"User {username} locked out at {timestamp}. "
            f"Possible brute force attack in progress."
        )

    elif event_id == 4719:
        return (
            f"CRITICAL: Security audit policy changed on {computer} "
            f"by {username} at {timestamp}. "
            f"Attacker may be covering their tracks!"
        )

    elif event_id == 7045:
        return (
            f"SUSPICIOUS: New service installed on {computer} "
            f"at {timestamp}. Possible rootkit or malware persistence."
        )

    elif event_id == 5157:
        return (
            f"Firewall blocked suspicious connection on {computer} "
            f"from IP {ip} at {timestamp}."
        )

    return (
        f"Security event {event_id} detected on {computer} "
        f"at {timestamp}: {details['raw_message'][:100]}"
    )


def investigate_event(details, alert_text):
    """
    Runs full Aegis Probe investigation on detected event
    """
    print(f"\n{'='*50}")
    print(f"[!] SECURITY EVENT DETECTED: {details['event_name']}")
    print(f"[!] Severity: {details['severity']}")
    print(f"[!] Alert: {alert_text}")
    print(f"{'='*50}")

    try:
        # Parse alert
        parsed = parse_alert(alert_text)

        # AI Analysis
        print("[*] Running AI analysis...")
        analysis = generate_hypotheses(parsed)

        # Probe IPs if found
        probes = []
        if parsed["ips"]:
            print(f"[*] Probing {len(parsed['ips'])} IPs...")
            probes = run_probes(parsed)

        # Save to Evidence Ledger
        inv_id = save_investigation(parsed, analysis, probes)
        print(f"[+] Saved as Case #{inv_id}")

        # Send email if dangerous
        final_check = any(
            "DANGEROUS" in p.get("verdict", "") for p in probes
        )
        if final_check or details["severity"] == "Critical":
            try:
                send_danger_alert(inv_id, parsed, probes, analysis)
                print(f"[+] Danger alert email sent!")
            except Exception as e:
                print(f"[!] Email failed: {e}")

        # Store event for dashboard
        event_record = {
            "case_id": inv_id,
            "event_id": details["event_id"],
            "event_name": details["event_name"],
            "severity": details["severity"],
            "category": details["category"],
            "timestamp": details["timestamp"],
            "computer": details["computer"],
            "alert_text": alert_text,
            "analysis": analysis,
            "probes": probes,
            "verdict": "DANGEROUS" if final_check else "SUSPICIOUS"
        }
        realtime_events.insert(0, event_record)

        # Keep only last 50 events
        if len(realtime_events) > 50:
            realtime_events.pop()

        return inv_id

    except Exception as e:
        print(f"[!] Investigation failed: {e}")
        return None


def monitor_security_log():
    """
    Continuously monitors Windows Security Event Log
    """
    global monitoring_active
    print("\n[*] Starting Windows Security Event Log Monitor...")
    print(f"[*] Monitoring {len(MONITORED_EVENTS)} event types")
    print("[*] Press Ctrl+C to stop\n")

    # Initialize database
    init_database()

    try:
        # Open Security log
        hand = win32evtlog.OpenEventLog(None, "Security")
        flags = (
            win32evtlog.EVENTLOG_BACKWARDS_READ |
            win32evtlog.EVENTLOG_SEQUENTIAL_READ
        )

        # Get current last record to only process new events
        last_record = win32evtlog.GetNumberOfEventLogRecords(hand)
        print(f"[+] Security log has {last_record} existing records")
        print(f"[+] Monitoring for NEW events only...\n")

        monitoring_active = True

        while monitoring_active:
            try:
                # Read new events
                events = win32evtlog.ReadEventLog(hand, flags, 0)

                if events:
                    for event in events:
                        event_id = event.EventID & 0xFFFF

                        # Only process monitored events
                        if event_id in MONITORED_EVENTS:
                            # Only process new events
                            if event.RecordNumber > last_record:
                                print(
                                    f"[!] New Event: {event_id} — "
                                    f"{MONITORED_EVENTS[event_id]['name']}"
                                )

                                # Extract details
                                details = extract_event_details(
                                    event, event_id
                                )

                                # Skip non-suspicious process events
                                if (event_id == 4688 and
                                        not check_suspicious_process(details)):
                                    continue

                                # Build alert text
                                alert_text = build_alert_text(details)

                                # Run investigation in background thread
                                thread = threading.Thread(
                                    target=investigate_event,
                                    args=(details, alert_text),
                                    daemon=True
                                )
                                thread.start()

                                last_record = max(
                                    last_record,
                                    event.RecordNumber
                                )

            except Exception as e:
                print(f"[!] Error reading events: {e}")

            # Check every 5 seconds
            time.sleep(5)

    except Exception as e:
        print(f"[!] Monitor failed: {e}")
        print("[!] Make sure to run as Administrator!")

    finally:
        monitoring_active = False
        print("\n[*] Monitor stopped")


def monitor_application_log():
    """
    Monitors Windows Defender / Application log for malware
    """
    print("[*] Starting Application Event Log Monitor (Defender)...")

    try:
        hand = win32evtlog.OpenEventLog(None, "System")
        flags = (
            win32evtlog.EVENTLOG_BACKWARDS_READ |
            win32evtlog.EVENTLOG_SEQUENTIAL_READ
        )
        last_record = win32evtlog.GetNumberOfEventLogRecords(hand)

        while monitoring_active:
            try:
                events = win32evtlog.ReadEventLog(hand, flags, 0)
                if events:
                    for event in events:
                        event_id = event.EventID & 0xFFFF
                        if event_id in [7045, 7040]:
                            if event.RecordNumber > last_record:
                                details = extract_event_details(
                                    event, event_id
                                )
                                alert_text = build_alert_text(details)
                                thread = threading.Thread(
                                    target=investigate_event,
                                    args=(details, alert_text),
                                    daemon=True
                                )
                                thread.start()
                                last_record = max(
                                    last_record,
                                    event.RecordNumber
                                )
            except:
                pass
            time.sleep(5)

    except Exception as e:
        print(f"[!] Application log monitor failed: {e}")


def start_monitoring():
    global monitoring_active
    monitoring_active = True

    # Write flag file so Streamlit can detect status
    with open(_MONITOR_FLAG_FILE, "w") as f:
        f.write("active")

    # Security log thread
    security_thread = threading.Thread(
        target=monitor_security_log,
        daemon=True
    )
    security_thread.start()

    # Application log thread
    app_thread = threading.Thread(
        target=monitor_application_log,
        daemon=True
    )
    app_thread.start()

    print("[+] All monitors started!")
    return security_thread, app_thread

def stop_monitoring():
    global monitoring_active
    monitoring_active = False

    # Remove flag file
    if os.path.exists(_MONITOR_FLAG_FILE):
        os.remove(_MONITOR_FLAG_FILE)
    print("[*] Stopping all monitors...")

def get_realtime_events():
    """
    Returns list of real-time events for dashboard
    """
    return realtime_events


# Test run
if __name__ == "__main__":
    print("=" * 50)
    print("  AEGIS PROBE — REAL-TIME EVENT MONITOR")
    print("=" * 50)
    print("\n⚠️  Run as Administrator for best results!\n")

    try:
        monitor_security_log()
    except KeyboardInterrupt:
        print("\n[*] Monitor stopped by user")