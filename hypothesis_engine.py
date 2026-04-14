# hypothesis_engine.py
# This file sends the alert to Phi3 Mini and generates investigative hypotheses

import requests
import json

def generate_hypotheses(parsed_alert):
    """
    Sends parsed alert to local Phi3 Mini model via Ollama
    and gets back investigative hypotheses
    """
    print("\n[*] Sending alert to Phi3 Mini for analysis...")

    # Clean structured prompt
    prompt = f"""You are Aegis Probe, an expert SOC analyst. Analyze this security alert and respond ONLY with the following 6 points. Do not add anything else after point 6.

ALERT: {parsed_alert['raw_alert']}
KEYWORDS: {parsed_alert['keywords']}
IPS: {parsed_alert['ips']}

Respond in exactly this format and stop after point 6:

1. ATTACK TYPE: (one sentence)
2. SEVERITY: Low / Medium / High / Critical
3. HYPOTHESIS 1: (one sentence)
4. HYPOTHESIS 2: (one sentence)
5. EVIDENCE TO COLLECT: (one sentence)
6. RECOMMENDED ACTION: (one sentence)"""

    try:
        response = requests.post(
            "http://localhost:11434/api/generate",
            json={
                "model": "phi3:mini",
                "prompt": prompt,
                "stream": False,
                "options": {
                    "temperature": 0.3,
                    "stop": ["7.", "Your ", "Note:", "Additional", "---"]
                }
            },
            timeout=1200
        )

        if response.status_code == 200:
            result = response.json()
            analysis = result.get("response", "").strip()

            # Clean any extra text after point 6
            lines = analysis.split("\n")
            clean_lines = []
            for line in lines:
                line = line.strip()
                if not line:
                    continue
                # Stop if we hit anything after point 6
                if any(line.startswith(x) for x in ["7.", "8.", "9.", "Your ", "Note:", "Additional", "---", "Please"]):
                    break
                clean_lines.append(line)

            analysis = "\n".join(clean_lines)

            if not analysis:
                return "Model returned empty response. Please try again."

            print("\n[+] Analysis Complete!")
            return analysis

        else:
            print(f"[!] Error from Ollama: {response.status_code}")
            return f"Ollama error: {response.status_code}"

    except requests.exceptions.Timeout:
        print("[!] Model took too long to respond!")
        return "Analysis timed out. Please try again."

    except Exception as e:
        print(f"[!] Could not connect to Ollama: {e}")
        return f"Connection error: {str(e)}"


# Test it
if __name__ == "__main__":
    test_parsed = {
        "raw_alert": "Failed SSH login attempts: 500 tries in 2 mins from IP 192.168.1.105",
        "keywords": ["failed", "login", "ssh"],
        "ips": ["192.168.1.105"]
    }

    result = generate_hypotheses(test_parsed)

    if result:
        print("\n========== AEGIS PROBE ANALYSIS ==========")
        print(result)
        print("==========================================")