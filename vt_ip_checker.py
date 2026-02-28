import requests
import json
import argparse
import os

# SOC Automation: Automated VirusTotal IP Checker
# Objective: Reduce Tier 1 triage time by automating IP reputation checks.

def check_ip_reputation(ip_address, api_key):
    """Queries the VirusTotal API v3 for IP address reputation."""
    
    url = f"https://www.virustotal.com/api/v3/ip_addresses/{ip_address}"
    headers = {
        "accept": "application/json",
        "x-apikey": api_key
    }
    
    try:
        response = requests.get(url, headers=headers)
        if response.status_code == 200:
            data = response.json()
            stats = data['data']['attributes']['last_analysis_stats']
            
            print(f"\n[*] OSINT Results for IP: {ip_address}")
            print(f"[-] Malicious:  {stats['malicious']}")
            print(f"[-] Suspicious: {stats['suspicious']}")
            print(f"[-] Harmless:   {stats['harmless']}")
            print(f"[-] Undetected: {stats['undetected']}")
            
            if stats['malicious'] > 0:
                print("\n[!] VERDICT: High Probability of Malicious Activity.")
            else:
                print("\n[+] VERDICT: No immediate malicious indicators found.")
                
        elif response.status_code == 401:
            print("[!] Error: Invalid API Key.")
        else:
            print(f"[!] Error: {response.status_code}")
            
    except Exception as e:
        print(f"[!] Network Error: {e}")

if __name__ == "__main__":
    parser = argparse.ArgumentParser(description="Automated OSINT IP Triage Tool")
    parser.add_argument("-i", "--ip", required=True, help="Target IP address to investigate")
    args = parser.parse_args()

    # Get API key from environment variable for security best practices
    API_KEY = os.getenv("VT_API_KEY")
    
    if not API_KEY:
        print("[!] Missing API Key. Please set the VT_API_KEY environment variable.")
        print("Example: export VT_API_KEY='your_api_key_here'")
    else:
        check_ip_reputation(args.ip, API_KEY)
