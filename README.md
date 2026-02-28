# Automated OSINT IP Triage Tool

### Overview
In a Security Operations Center (SOC), analysts spend countless hours manually querying IP addresses from SIEM alerts. This Python tool automates the initial OSINT triage process by interfacing with the VirusTotal API v3. 

### Core Capabilities
* **API Integration:** Utilizes the `requests` library to fetch JSON data from VirusTotal.
* **Data Parsing:** Extracts exact malicious and suspicious detection ratios.
* **Sanitized Execution:** Uses environment variables for API keys to maintain OPSEC and prevent credential leaks on GitHub.

### Installation & Usage
1. Clone the repository.
2. Install required libraries: `pip install requests`
3. Get a free API key from VirusTotal and set it in your terminal:
   ```bash
   export VT_API_KEY="your_api_key_here"
