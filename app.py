from flask import Flask, render_template, request, jsonify
import re
from urllib.parse import urlparse
import requests

app = Flask(__name__)

# 🔑 Replace these with your actual API keys
VIRUSTOTAL_API_KEY = "AIzaSyCo9D7hxIuaz0wHSGtDNsWQkbEZE19zRok"  # Replace with your VirusTotal API Key
GOOGLE_SAFE_BROWSING_API_KEY = "AIzaSyCo9D7hxIuaz0wHSGtDNsWQkbEZE19zRok"  # Replace with your Google Safe Browsing API Key

# API URLs
VIRUSTOTAL_URL = "https://www.virustotal.com/api/v3/urls"
SAFE_BROWSING_URL = f"https://safebrowsing.googleapis.com/v4/threatMatches:find?key={GOOGLE_SAFE_BROWSING_API_KEY}"

# 🛑 Sample blacklist of domains
BLACKLISTED_DOMAINS = ["malicious.com", "phishingsite.net", "badlink.org"]

def check_with_virustotal(url):
    """Check the URL using VirusTotal API."""
    headers = {"x-apikey": VIRUSTOTAL_API_KEY}

    # Step 1: Submit the URL for analysis
    response = requests.post(VIRUSTOTAL_URL, headers=headers, data={"url": url})
    if response.status_code != 200:
        return False, "⚠️ VirusTotal check failed."

    analysis_id = response.json().get("data", {}).get("id", "")
    if not analysis_id:
        return False, "⚠️ VirusTotal analysis ID not found."

    # Step 2: Retrieve analysis results
    analysis_url = f"{VIRUSTOTAL_URL}/{analysis_id}"
    analysis_response = requests.get(analysis_url, headers=headers).json()

    malicious_count = analysis_response.get("data", {}).get("attributes", {}).get("last_analysis_stats", {}).get("malicious", 0)
    if malicious_count > 0:
        return True, f"🚨 VirusTotal: {malicious_count} engines flagged this URL."
    return False, "✅ VirusTotal: No engines flagged this URL."

def check_with_google_safe_browsing(url):
    """Check the URL using Google Safe Browsing API."""
    payload = {
        "client": {"clientId": "your-app-name", "clientVersion": "1.0"},
        "threatInfo": {
            "threatTypes": ["MALWARE", "SOCIAL_ENGINEERING", "UNWANTED_SOFTWARE", "POTENTIALLY_HARMFUL_APPLICATION"],
            "platformTypes": ["ANY_PLATFORM"],
            "threatEntryTypes": ["URL"],
            "threatEntries": [{"url": url}]
        }
    }

    response = requests.post(SAFE_BROWSING_URL, json=payload)
    if response.status_code != 200:
        return False, "⚠️ Google Safe Browsing check failed."

    if response.json().get("matches"):
        return True, "🚨 Google Safe Browsing: Malicious URL detected."
    return False, "✅ Google Safe Browsing: URL is safe."

def is_malicious(url):
    """Run heuristic checks, VirusTotal, and Google Safe Browsing scans."""

    # 🔍 Heuristic checks
    parsed_url = urlparse(url)
    domain = parsed_url.netloc.lower()

    # Blacklist check
    if any(blacklisted in domain for blacklisted in BLACKLISTED_DOMAINS):
        return True, "🚩 Blacklisted domain detected."

    # Suspicious pattern checks
    suspicious_patterns = [
        r"(free|bonus|login|update|verify|hidden|bin|bot|worm|mal|queue)",  # suspicious keywords
        r"[0-9]{4,}",                        # long numbers in URL
        r"%[0-9a-fA-F]{2}",                  # URL encoding patterns
        r"(?:\\.ru|\\.cn|\\.tk|\\.ml|\\.ga)$"  # suspicious TLDs
    ]

    for pattern in suspicious_patterns:
        if re.search(pattern, url):
            return True, " Suspicious pattern detected."

    # 🛡️ VirusTotal check
    vt_malicious, vt_message = check_with_virustotal(url)
    if vt_malicious:
        return True, vt_message

    # 🛡️ Google Safe Browsing check
    gsb_malicious, gsb_message = check_with_google_safe_browsing(url)
    if gsb_malicious:
        return True, gsb_message

    return False, " No issues detected."  # Safe if no checks flag the URL

@app.route('/')
def index():
    return render_template('index.html')

@app.route('/check', methods=['POST'])
def check_url():
    data = request.get_json()
    url = data.get("url", "")

    if not url:
        return jsonify({"error": "No URL provided."}), 400

    malicious, message = is_malicious(url)
    return jsonify({"malicious": malicious, "message": message})

if __name__ == '__main__':
    app.run(debug=True)
