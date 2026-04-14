# evidence_ledger.py
# Saves all investigation results into a secure SQLite database

import sqlite3
import json
from datetime import datetime

DB_NAME = "D:\\aegis_probe\\aegis_evidence.db"

def init_database():
    """
    Creates the database and tables if they don't exist
    """
    print("\n[*] Initializing Evidence Ledger...")
    conn = sqlite3.connect(DB_NAME)
    cursor = conn.cursor()

    cursor.execute('''
        CREATE TABLE IF NOT EXISTS investigations (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            timestamp TEXT NOT NULL,
            raw_alert TEXT NOT NULL,
            keywords TEXT,
            ips_found TEXT,
            mistral_analysis TEXT,
            probe_results TEXT,
            final_verdict TEXT
        )
    ''')

    conn.commit()
    conn.close()
    print("[+] Evidence Ledger ready!")


def save_investigation(parsed_alert, analysis, probe_results):
    """
    Saves a complete investigation to the database
    """
    print("\n[*] Saving investigation to Evidence Ledger...")

    conn = sqlite3.connect(DB_NAME)
    cursor = conn.cursor()

    # Determine final verdict from probe results
    final_verdict = "🟡 SUSPICIOUS - MONITOR"
    for probe in probe_results:
        if "DANGEROUS" in probe.get("verdict", ""):
            final_verdict = "🔴 DANGEROUS"
            break

    cursor.execute('''
        INSERT INTO investigations 
        (timestamp, raw_alert, keywords, ips_found, 
         mistral_analysis, probe_results, final_verdict)
        VALUES (?, ?, ?, ?, ?, ?, ?)
    ''', (
        datetime.now().strftime("%Y-%m-%d %H:%M:%S"),
        parsed_alert["raw_alert"],
        json.dumps(parsed_alert["keywords"]),
        json.dumps(parsed_alert["ips"]),
        analysis,
        json.dumps(probe_results, default=str),
        final_verdict
    ))

    conn.commit()
    investigation_id = cursor.lastrowid
    conn.close()

    print(f"[+] Investigation saved! ID: #{investigation_id}")
    return investigation_id


def get_all_investigations():
    """
    Retrieves all past investigations from the database
    """
    conn = sqlite3.connect(DB_NAME)
    cursor = conn.cursor()

    cursor.execute("SELECT * FROM investigations ORDER BY timestamp DESC")
    rows = cursor.fetchall()
    conn.close()
    return rows


def get_investigation_by_id(inv_id):
    """
    Retrieves a specific investigation by ID
    """
    conn = sqlite3.connect(DB_NAME)
    cursor = conn.cursor()

    cursor.execute("SELECT * FROM investigations WHERE id=?", (inv_id,))
    row = cursor.fetchone()
    conn.close()
    return row


# Test it
if __name__ == "__main__":
    # Initialize database
    init_database()

    # Simulate saving a test investigation
    test_parsed = {
        "raw_alert": "Failed SSH login attempts: 500 tries in 2 mins from IP 192.168.1.105",
        "keywords": ["failed", "login", "ssh"],
        "ips": ["192.168.1.105"]
    }

    test_analysis = "ATTACK TYPE: Brute Force SSH\nSEVERITY: Medium"

    test_probes = [{
        "ip": "192.168.1.105",
        "verdict": "🟡 SUSPICIOUS - MONITOR"
    }]

    # Save it
    inv_id = save_investigation(test_parsed, test_analysis, test_probes)

    # Retrieve and display it
    print("\n[*] Retrieving saved investigation...")
    rows = get_all_investigations()
    print(f"[+] Total investigations in ledger: {len(rows)}")
    print(f"[+] Latest investigation ID: #{rows[0][0]}")
    print(f"[+] Timestamp: {rows[0][1]}")
    print(f"[+] Alert: {rows[0][2]}")
    print(f"[+] Final Verdict: {rows[0][7]}")