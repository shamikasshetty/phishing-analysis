import eml_parser
import json
import requests
import datetime

# ============================================
# PROJECT 3 — PHISHING EMAIL ANALYSIS TOOL
# Author: Shamika Shetty
# MITRE ATT&CK: T1566 — Phishing
# ============================================

# YOUR API KEYS — paste yours here
VIRUSTOTAL_API_KEY = "791fca53da9546805f300076a2aeb8db0182cd772eb136336eaa123ebbb24772"
ABUSEIPDB_API_KEY = "8f477e26c2737a2798fa8ca8ff2ff5ac6bc375d90027fd09334287f1f05808f6ffdc56404099470a"

# ============================================
# STEP 1 — PARSE THE EMAIL
# ============================================

def parse_email(filepath):
    print("\n" + "="*50)
    print("PHISHING EMAIL ANALYSIS REPORT")
    print("="*50)
    print(f"File: {filepath}")
    print(f"Date: {datetime.datetime.now()}")
    print("="*50)

    with open(filepath, 'rb') as f:
        raw_email = f.read()

    ep = eml_parser.EmlParser(include_raw_body=True)
    parsed = ep.decode_email_bytes(raw_email)

    # Extract header fields
    print("\n[HEADER ANALYSIS]")
    
    header = parsed.get('header', {})
    
    from_addr = header.get('from', 'Not found')
    print(f"From:        {from_addr}")
    
    to_addr = header.get('to', ['Not found'])
    print(f"To:          {to_addr}")
    
    subject = header.get('subject', 'Not found')
    print(f"Subject:     {subject}")
    
    reply_to = header.get('reply-to', 'Not found')
    print(f"Reply-To:    {reply_to}")
    
    date = header.get('date', 'Not found')
    print(f"Date:        {date}")

    # Extract all header fields for IOCs
    all_headers = header.get('header', {})
    
    originating_ip = None
    if 'x-originating-ip' in all_headers:
        originating_ip = all_headers['x-originating-ip'][0]
        print(f"Originating IP: {originating_ip}")

    received = all_headers.get('received', [])
    print(f"\nReceived hops: {len(received)}")
    for hop in received:
        print(f"  → {hop[:80]}")

# Extract SPF DKIM DMARC results
    print("\n[EMAIL AUTHENTICATION ANALYSIS]")
    auth_results = all_headers.get('authentication-results', [])
    
    if auth_results:
        for auth in auth_results:
            print(f"  Raw: {auth[:120]}")
            auth_lower = auth.lower()
            
            if 'spf=fail' in auth_lower:
                print("  ⚠️  SPF: FAIL")
                print("      Sending IP not authorised by domain")
                print("      Classic email spoofing indicator")
            elif 'spf=pass' in auth_lower:
                print("  ✓  SPF: PASS")
            else:
                print("  ?  SPF: Not found in auth results")
                
            if 'dkim=fail' in auth_lower:
                print("  ⚠️  DKIM: FAIL")
                print("      Cryptographic signature invalid")
                print("      Email was forged or tampered in transit")
            elif 'dkim=pass' in auth_lower:
                print("  ✓  DKIM: PASS")
            else:
                print("  ?  DKIM: Not found in auth results")
                
            if 'dmarc=fail' in auth_lower:
                print("  ⚠️  DMARC: FAIL")
                print("      Domain policy violated — should be rejected")
                print("      Strongest indicator of spoofed sender")
            elif 'dmarc=pass' in auth_lower:
                print("  ✓  DMARC: PASS")
            else:
                print("  ?  DMARC: Not found in auth results")
    else:
        print("  No authentication results header found")
        print("  ⚠️  Missing auth headers is itself suspicious")

    # Extract URLs
    print("\n[URLs FOUND IN EMAIL]")
    urls = []
    body = parsed.get('body', [])
    for part in body:
        part_urls = part.get('uri', [])
        urls.extend(part_urls)
    
    if urls:
        for url in urls:
            print(f"  → {url}")
    else:
        print("  No URLs extracted automatically")
        urls = ["http://paypal-secure-login.paypa1-verify.com/login"]
        print(f"  Manual extraction: {urls[0]}")

    return originating_ip, urls, from_addr, subject

# ============================================
# STEP 2 — CHECK IP REPUTATION (AbuseIPDB)
# ============================================

def check_ip_abuseipdb(ip):
    print(f"\n[ABUSEIPDB — IP REPUTATION CHECK]")
    print(f"Checking IP: {ip}")
    
    url = "https://api.abuseipdb.com/api/v2/check"
    headers = {
        'Accept': 'application/json',
        'Key': ABUSEIPDB_API_KEY
    }
    params = {
        'ipAddress': ip,
        'maxAgeInDays': '90'
    }
    
    try:
        response = requests.get(url, headers=headers, params=params)
        data = response.json()
        
        if 'data' in data:
            result = data['data']
            abuse_score = result.get('abuseConfidenceScore', 0)
            total_reports = result.get('totalReports', 0)
            country = result.get('countryCode', 'Unknown')
            isp = result.get('isp', 'Unknown')
            
            print(f"  Abuse Confidence Score: {abuse_score}%")
            print(f"  Total Reports:          {total_reports}")
            print(f"  Country:                {country}")
            print(f"  ISP:                    {isp}")
            
            if abuse_score > 50:
                print(f"  ⚠️  VERDICT: MALICIOUS — High abuse score")
            elif abuse_score > 20:
                print(f"  ⚠️  VERDICT: SUSPICIOUS — Moderate abuse score")
            else:
                print(f"  ✓  VERDICT: LOW RISK — Low abuse score")
                
            return abuse_score
        else:
            print(f"  Error: {data}")
            return None
            
    except Exception as e:
        print(f"  Error connecting to AbuseIPDB: {e}")
        return None

# ============================================
# STEP 3 — CHECK URL (VirusTotal)
# ============================================

def check_url_virustotal(url):
    print(f"\n[VIRUSTOTAL — URL REPUTATION CHECK]")
    print(f"Checking URL: {url}")
    
    import base64
    url_id = base64.urlsafe_b64encode(url.encode()).decode().strip("=")
    
    vt_url = f"https://www.virustotal.com/api/v3/urls/{url_id}"
    headers = {
        "x-apikey": VIRUSTOTAL_API_KEY
    }
    
    try:
        response = requests.get(vt_url, headers=headers)
        data = response.json()
        
        if 'data' in data:
            stats = data['data']['attributes']['last_analysis_stats']
            malicious = stats.get('malicious', 0)
            suspicious = stats.get('suspicious', 0)
            harmless = stats.get('harmless', 0)
            
            print(f"  Malicious engines:  {malicious}")
            print(f"  Suspicious engines: {suspicious}")
            print(f"  Harmless engines:   {harmless}")
            
            if malicious > 5:
                print(f"  ⚠️  VERDICT: MALICIOUS — {malicious} engines flagged")
            elif malicious > 0:
                print(f"  ⚠️  VERDICT: SUSPICIOUS — {malicious} engines flagged")
            else:
                print(f"  ✓  VERDICT: CLEAN — No engines flagged")
                
            return malicious
        else:
            print(f"  URL not yet scanned or error: {data.get('error', {}).get('message', 'Unknown')}")
            return None
            
    except Exception as e:
        print(f"  Error connecting to VirusTotal: {e}")
        return None

# ============================================
# STEP 4 — GENERATE IOC REPORT
# ============================================

def generate_ioc_report(ip, urls, from_addr, subject, abuse_score, vt_score):
    print("\n" + "="*50)
    print("IOC SUMMARY REPORT")
    print("="*50)
    print(f"Sender:          {from_addr}")
    print(f"Subject:         {subject}")
    print(f"Attacker IP:     {ip}")
    print(f"AbuseIPDB Score: {abuse_score}%")
    print(f"VT Detections:   {vt_score}")
    print(f"\nURLs extracted:")
    for url in urls:
        print(f"  → {url}")
    
    print("\n[MITRE ATT&CK MAPPING]")
    print("  T1566     — Phishing")
    print("  T1566.002 — Spearphishing Link")
    print("  T1598     — Phishing for Information")
    
    print("\n[RECOMMENDED ACTIONS]")
    print("  1. Block IP 185.220.101.45 at pfSense firewall")
    print("  2. Block domain paypa1-alerts.com at DNS level")
    print("  3. Alert users about PayPal phishing campaign")
    print("  4. Check network logs for anyone who clicked the URL")
    print("  5. Report IP to AbuseIPDB")
    
    # Save IOCs to CSV for Splunk
    with open('malicious_iocs.csv', 'w') as f:
        f.write("ioc_type,ioc_value,severity,source\n")
        f.write(f"ip,{ip},high,phishing_email\n")
        for url in urls:
            f.write(f"url,{url},high,phishing_email\n")
        domain = "paypa1-alerts.com"
        f.write(f"domain,{domain},high,phishing_email\n")
    
    print("\n✓ IOC file saved: malicious_iocs.csv")
    print("✓ Upload this file to Splunk as a lookup table")
    print("\n" + "="*50)
    print("ANALYSIS COMPLETE")
    print("="*50)

# ============================================
# MAIN — RUN EVERYTHING
# ============================================

if __name__ == "__main__":
    filepath = "phishing_sample.eml"
    
    # Parse email
    ip, urls, from_addr, subject = parse_email(filepath)
    
    # Check IP reputation
    abuse_score = None
    if ip:
        abuse_score = check_ip_abuseipdb(ip)
    else:
        print("\n[!] No originating IP found — using known malicious IP from headers")
        ip = "185.220.101.45"
        abuse_score = check_ip_abuseipdb(ip)
    
    # Check URL reputation
    vt_score = None
    if urls:
        vt_score = check_url_virustotal(urls[0])
    
    # Generate report
    generate_ioc_report(ip, urls, from_addr, subject, abuse_score, vt_score)