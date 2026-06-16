import requests
import re
import csv
import time
import sys
import os
import ipaddress
import base64
from datetime import datetime
from config import VIRUSTOTAL_API_KEY, ABUSEIPDB_API_KEY
from severity import calculate_severity
from json_export import export_json
from mitre_mapper import map_mitre
from html_report import export_html
from urlscan_checker import scan_url


# ─────────────────────────────────────────────
#  IP VALIDATION
# ─────────────────────────────────────────────

def is_valid_ip(ip):
    try:
        ipaddress.IPv4Address(ip)
        return True
    except ipaddress.AddressValueError:
        return False


def is_private_ip(ip):
    try:
        ip_obj = ipaddress.IPv4Address(ip)
        return (
            ip_obj.is_private or
            ip_obj.is_loopback or
            ip_obj.is_multicast or
            ip_obj.is_reserved or
            ip_obj.is_link_local
        )
    except:
        return True


# ─────────────────────────────────────────────
#  DOMAIN VALIDATION
# ─────────────────────────────────────────────

NAME_SUFFIXES = {
    "smith", "jones", "brown", "taylor", "wilson", "johnson",
    "lee", "clark", "hall", "young", "king", "wright"
}


def is_valid_domain(domain):
    parts = domain.lower().split(".")
    if len(parts) < 2:
        return False

    tld = parts[-1]

    # Allow any normal TLD length 2-24
    if not re.match(r"^[a-z]{2,24}$", tld):
        return False

    for part in parts[:-1]:
        if not re.match(r"^[a-zA-Z0-9-]+$", part):
            return False
        if part.startswith("-") or part.endswith("-"):
            return False

    if len(parts) == 2 and parts[1] in NAME_SUFFIXES:
        return False

    if any(len(p) < 2 for p in parts[:-1]):
        return False

    return True


# ─────────────────────────────────────────────
#  DETECT IOC TYPE
# ─────────────────────────────────────────────

def detect_hash_type(h):
    if len(h) == 32:
        return "md5"
    elif len(h) == 40:
        return "sha1"
    elif len(h) == 64:
        return "sha256"
    return "hash"


def detect_ioc_type(ioc):
    if re.match(r"^https?://", ioc, re.IGNORECASE):
        return "url"
    hash_pattern = r"^[a-fA-F0-9]{32}$|^[a-fA-F0-9]{40}$|^[a-fA-F0-9]{64}$"
    if is_valid_ip(ioc):
        return "ip"
    elif re.match(hash_pattern, ioc):
        return detect_hash_type(ioc)
    elif is_valid_domain(ioc):
        return "domain"
    else:
        return "unknown"


def extract_domain_from_url(url):
    match = re.match(r"^https?://([^/?\#]+)", url, re.IGNORECASE)
    if match:
        host = match.group(1)
        host = host.split(":")[0]
        return host
    return None


# ─────────────────────────────────────────────
#  EXTRACT IOCs FROM RAW TEXT
# ─────────────────────────────────────────────

def extract_iocs_from_text(text):
    ips = set()
    hashes = set()
    domains = set()
    urls = set()

    ip_pattern = r"\b\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3}\b"
    hash_pattern = r"\b[a-fA-F0-9]{32}\b|\b[a-fA-F0-9]{40}\b|\b[a-fA-F0-9]{64}\b"
    domain_pattern = r"\b(?:[a-zA-Z0-9-]+\.)+[a-zA-Z]{2,24}\b"
    url_pattern = r"https?://[^\s\>\<\"\']+"

    skip_domains = {
        "example.com", "google.com", "github.com", "localhost",
        "microsoft.com", "apple.com", "amazon.com"
    }

    # URLs first
    for url in re.findall(url_pattern, text):
        urls.add(url)

    # IPs
    for ip in re.findall(ip_pattern, text):
        if is_valid_ip(ip) and not is_private_ip(ip):
            ips.add(ip)

    # Hashes
    hashes.update(re.findall(hash_pattern, text))

    # Domains — skip ones already captured inside URLs
    for d in re.findall(domain_pattern, text):
        if re.match(ip_pattern, d):
            continue
        if d.lower() in skip_domains:
            continue
        if not is_valid_domain(d):
            continue
        if any(extract_domain_from_url(url) == d for url in urls):
            continue
        domains.add(d)

    all_iocs = list(urls) + list(ips) + list(hashes) + list(domains)
    return all_iocs


# ─────────────────────────────────────────────
#  VIRUSTOTAL
# ─────────────────────────────────────────────

def check_virustotal(ioc, ioc_type):
    base_url = "https://www.virustotal.com/api/v3"
    headers = {"x-apikey": VIRUSTOTAL_API_KEY}

    if ioc_type == "url":
        # Submit URL to VT (active submission — works for new/unknown URLs too)
        try:
            post_resp = requests.post(
                f"{base_url}/urls",
                headers=headers,
                data={"url": ioc},
                timeout=10
            )
        except requests.RequestException as e:
            return {"error": f"VirusTotal request failed: {str(e)}"}

        if post_resp.status_code not in (200, 201):
            return {"error": f"VirusTotal URL submit error {post_resp.status_code}"}

        analysis_id = post_resp.json().get("data", {}).get("id", "")
        if not analysis_id:
            return {"error": "VirusTotal did not return an analysis ID"}

        # Poll for result (up to 3 attempts)
        for attempt in range(3):
            time.sleep(5)
            try:
                result_resp = requests.get(
                    f"{base_url}/analyses/{analysis_id}",
                    headers=headers,
                    timeout=10
                )
            except requests.RequestException as e:
                return {"error": f"VirusTotal request failed: {str(e)}"}

            if result_resp.status_code == 200:
                attrs = result_resp.json().get("data", {}).get("attributes", {})
                status = attrs.get("status", "")
                if status == "completed":
                    stats = attrs.get("stats", {})
                    malicious = stats.get("malicious", 0)
                    suspicious = stats.get("suspicious", 0)
                    harmless = stats.get("harmless", 0)
                    undetected = stats.get("undetected", 0)
                    total = malicious + suspicious + harmless + undetected
                    return {"malicious": malicious, "suspicious": suspicious, "harmless": harmless, "total": total}

        return {"error": "VirusTotal analysis timed out — try again in a moment"}

    elif ioc_type == "ip":
        url = f"{base_url}/ip_addresses/{ioc}"
    elif ioc_type == "domain":
        url = f"{base_url}/domains/{ioc}"
    elif ioc_type in ("hash", "md5", "sha1", "sha256"):
        url = f"{base_url}/files/{ioc}"
    else:
        return {"error": "Unsupported IOC type"}

    try:
        response = requests.get(url, headers=headers, timeout=10)
    except requests.RequestException as e:
        return {"error": f"VirusTotal request failed: {str(e)}"}

    if response.status_code == 200:
        stats = response.json()["data"]["attributes"]["last_analysis_stats"]
        malicious = stats.get("malicious", 0)
        suspicious = stats.get("suspicious", 0)
        harmless = stats.get("harmless", 0)
        undetected = stats.get("undetected", 0)
        total = malicious + suspicious + harmless + undetected
        return {"malicious": malicious, "suspicious": suspicious, "harmless": harmless, "total": total}
    elif response.status_code == 404:
        return {"error": "Not found in VirusTotal"}
    elif response.status_code == 401:
        return {"error": "Invalid VirusTotal API key"}
    elif response.status_code == 429:
        return {"error": "VirusTotal rate limit hit — wait 60s"}
    else:
        return {"error": f"VirusTotal error {response.status_code}"}


# ─────────────────────────────────────────────
#  ABUSEIPDB
# ─────────────────────────────────────────────

def check_abuseipdb(ip):
    url = "https://api.abuseipdb.com/api/v2/check"
    headers = {"Key": ABUSEIPDB_API_KEY, "Accept": "application/json"}
    params = {"ipAddress": ip, "maxAgeInDays": 90}

    try:
        response = requests.get(url, headers=headers, params=params, timeout=10)
    except requests.RequestException as e:
        return {"error": f"AbuseIPDB request failed: {str(e)}"}

    if response.status_code == 200:
        data = response.json()["data"]
        return {
            "abuse_score": data["abuseConfidenceScore"],
            "total_reports": data["totalReports"],
            "country": data.get("countryCode", "Unknown"),
            "isp": data.get("isp", "Unknown"),
            "last_reported": data.get("lastReportedAt", "Never")
        }
    elif response.status_code == 401:
        return {"error": "Invalid AbuseIPDB API key"}
    else:
        return {"error": f"AbuseIPDB error {response.status_code}"}


# ─────────────────────────────────────────────
#  VERDICT
# ─────────────────────────────────────────────

def get_verdict(vt_result, abuse_result=None):
    if "error" in vt_result:
        return "UNKNOWN"

    malicious = vt_result.get("malicious", 0)
    suspicious = vt_result.get("suspicious", 0)
    abuse_score = abuse_result.get("abuse_score", 0) if abuse_result and "error" not in abuse_result else 0

    if malicious >= 5 or abuse_score >= 75:
        return "MALICIOUS"
    elif malicious >= 1 or suspicious >= 3 or abuse_score >= 25:
        return "SUSPICIOUS"
    else:
        return "CLEAN"


# ─────────────────────────────────────────────
#  PRINT REPORT
# ─────────────────────────────────────────────

def print_report(ioc, ioc_type, vt_result, abuse_result=None):
    verdict = get_verdict(vt_result, abuse_result)
    severity, score = calculate_severity(vt_result, abuse_result)
    mitre = map_mitre(ioc_type, verdict)

    icons = {
        "MALICIOUS": "🔴",
        "SUSPICIOUS": "🟡",
        "CLEAN": "🟢",
        "UNKNOWN": "⚪"
    }

    print("\n" + "=" * 50)
    print("  IOC THREAT REPORT")
    print("=" * 50)
    print(f"  IOC       : {ioc}")
    print(f"  Type      : {ioc_type.upper()}")
    print("-" * 50)

    print("  [VirusTotal]")
    if "error" in vt_result:
        print(f"  Error: {vt_result['error']}")
    else:
        print(f"  Malicious : {vt_result['malicious']} / {vt_result['total']} engines")
        print(f"  Suspicious: {vt_result['suspicious']}")
        print(f"  Harmless  : {vt_result['harmless']}")

    if abuse_result:
        print("-" * 50)
        print("  [AbuseIPDB]")
        if "error" in abuse_result:
            print(f"  Error: {abuse_result['error']}")
        else:
            print(f"  Abuse Score   : {abuse_result['abuse_score']}%")
            print(f"  Total Reports : {abuse_result['total_reports']}")
            print(f"  Country       : {abuse_result['country']}")
            print(f"  ISP           : {abuse_result['isp']}")
            print(f"  Last Reported : {abuse_result['last_reported']}")

    print("-" * 50)
    print(f"  SEVERITY  : {severity} ({score})")
    print(f"  MITRE     : {mitre}")
    print(f"  VERDICT   : {icons[verdict]} {verdict}")
    print("=" * 50 + "\n")
# ─────────────────────────────────────────────
#  VALIDATE IOC
# ─────────────────────────────────────────────

def validate_ioc(ioc, ioc_type):
    if ioc_type == "unknown":
        return False, f"Unrecognized IOC format: {ioc}"
    if ioc_type == "ip":
        if is_private_ip(ioc):
            return False, f"Private/internal IP skipped: {ioc}"
    return True, None


def friendly_type(ioc_type):
    return ioc_type.upper() if ioc_type in ("md5", "sha1", "sha256", "url", "ip") else ioc_type.upper()


# ─────────────────────────────────────────────
#  PROCESS IOC
# ─────────────────────────────────────────────

ioc_cache = {}


def process_ioc(ioc):
    if ioc in ioc_cache:
        print("  (cached)")
        return ioc_cache[ioc]

    ioc_type = detect_ioc_type(ioc)

    valid, reason = validate_ioc(ioc, ioc_type)
    if not valid:
        print(f"  ⚠️  {reason}")
        return ioc_type, {"error": reason}, None, "INVALID"

    vt_result = check_virustotal(ioc, ioc_type)

    # Only sleep if VT returned actual data
    if "error" not in vt_result and ioc_type != "url":
        time.sleep(5)

    abuse_result = None
    if ioc_type == "ip":
        abuse_result = check_abuseipdb(ioc)
    elif ioc_type == "url":
        scan_url(ioc)
        domain = extract_domain_from_url(ioc)
        if domain:
            if is_valid_ip(domain):
                abuse_result = check_abuseipdb(domain)

    verdict = get_verdict(vt_result, abuse_result)
    ioc_cache[ioc] = (ioc_type, vt_result, abuse_result, verdict)
    return ioc_type, vt_result, abuse_result, verdict


# ─────────────────────────────────────────────
#  EXPORT CSV
# ─────────────────────────────────────────────

def export_csv(results, filename=None):
    if not filename:
        timestamp = datetime.now().strftime("%Y%m%d_%H%M%S")
        filename = f"ioc_report_{timestamp}.csv"

    with open(filename, "w", newline="") as f:
        writer = csv.writer(f)

        writer.writerow([
            "IOC", "Type", "Verdict",
            "Severity", "MITRE",
            "VT Malicious", "VT Suspicious", "VT Total Engines",
            "Abuse Score", "Abuse Reports",
            "Country", "ISP", "Last Reported"
        ])

        for row in results:
            writer.writerow([
                row["ioc"],
                row["type"],
                row["verdict"],
                row["severity"],
                row["mitre"],
                row["vt_malicious"],
                row["vt_suspicious"],
                row["vt_total"],
                row["abuse_score"],
                row["abuse_reports"],
                row["country"],
                row["isp"],
                row["last_reported"]
            ])

    print(f"\n✅ CSV report saved to: {filename}")

# ─────────────────────────────────────────────
#  MODE 1: Single IOC
# ─────────────────────────────────────────────

def mode_single():
    print("\nType 'exit' to quit.\n")
    while True:
        ioc = input("Enter IOC: ").strip()
        if ioc.lower() == "exit":
            print("Exiting. Stay safe!")
            break
        if not ioc:
            continue

        ioc_type = detect_ioc_type(ioc)
        print(f"\nDetected type: {ioc_type.upper()} — querying...")
        ioc_type, vt_result, abuse_result, verdict = process_ioc(ioc)
        if verdict != "INVALID":
            print_report(ioc, ioc_type, vt_result, abuse_result)


# ─────────────────────────────────────────────
#  MODE 2: Bulk from .txt file
# ─────────────────────────────────────────────

def mode_bulk(filepath):
    if not os.path.exists(filepath):
        print(f"File not found: {filepath}")
        return

    with open(filepath, "r") as f:
        iocs = [line.strip() for line in f if line.strip()]

    if not iocs:
        print("No IOCs found in file.")
        return

    print(f"\nLoaded {len(iocs)} IOCs from {filepath}")
    print("Note: 15s delay between valid requests (VirusTotal free tier)\n")

    results = []

    for i, ioc in enumerate(iocs, 1):
        print(f"[{i}/{len(iocs)}] Checking {ioc}...")
        ioc_type, vt_result, abuse_result, verdict = process_ioc(ioc)

        if verdict != "INVALID":
            print_report(ioc, ioc_type, vt_result, abuse_result)

        abuse = abuse_result or {}

        severity, score = calculate_severity(vt_result, abuse_result)
        mitre = map_mitre(ioc_type, verdict)

        results.append({
            "ioc": ioc,
            "type": ioc_type,
            "verdict": verdict,
            "severity": severity,
            "mitre": mitre,
            "vt_malicious": vt_result.get("malicious", ""),
            "vt_suspicious": vt_result.get("suspicious", ""),
            "vt_total": vt_result.get("total", ""),
            "abuse_score": abuse.get("abuse_score", ""),
            "abuse_reports": abuse.get("total_reports", ""),
            "country": abuse.get("country", ""),
            "isp": abuse.get("isp", ""),
            "last_reported": abuse.get("last_reported", "")
        })

    export_csv(results)
    export_json(results)
    export_html(results)
# ─────────────────────────────────────────────
#  MODE 3: Extract IOCs from raw text
# ─────────────────────────────────────────────

def mode_extract():
    print("\nPaste your text/email/log below.")
    print("When done, type END on a new line and press Enter:\n")

    lines = []
    while True:
        line = input()
        if line.strip() == "END":
            break
        lines.append(line)

    text = "\n".join(lines)
    iocs = extract_iocs_from_text(text)

    if not iocs:
        print("No IOCs found in the text.")
        return

    print(f"\nExtracted {len(iocs)} IOCs: {iocs}")
    confirm = input("Check all of them? (y/n): ").strip().lower()
    if confirm != "y":
        return

    results = []

    for i, ioc in enumerate(iocs, 1):
        print(f"\n[{i}/{len(iocs)}] Checking {ioc}...")
        ioc_type, vt_result, abuse_result, verdict = process_ioc(ioc)

        if verdict != "INVALID":
            print_report(ioc, ioc_type, vt_result, abuse_result)

        abuse = abuse_result or {}

        severity, score = calculate_severity(vt_result, abuse_result)
        mitre = map_mitre(ioc_type, verdict)

        results.append({
            "ioc": ioc,
            "type": ioc_type,
            "verdict": verdict,
            "severity": severity,
            "mitre": mitre,
            "vt_malicious": vt_result.get("malicious", ""),
            "vt_suspicious": vt_result.get("suspicious", ""),
            "vt_total": vt_result.get("total", ""),
            "abuse_score": abuse.get("abuse_score", ""),
            "abuse_reports": abuse.get("total_reports", ""),
            "country": abuse.get("country", ""),
            "isp": abuse.get("isp", ""),
            "last_reported": abuse.get("last_reported", "")
        })

    export_csv(results)
    export_json(results)
    export_html(results)

# ─────────────────────────────────────────────
#  MAIN MENU
# ─────────────────────────────────────────────

def main():
    print("\n==============================")
    print("   IOCSentinel — IOC Threat Intel")
    print("==============================")
    print("1. Check a single IOC")
    print("2. Bulk check from .txt file")
    print("3. Extract & check IOCs from raw text/email")
    print("==============================")

    choice = input("Select mode (1/2/3): ").strip()

    if choice == "1":
        mode_single()
    elif choice == "2":
        filepath = input("Enter path to .txt file: ").strip()
        mode_bulk(filepath)
    elif choice == "3":
        mode_extract()
    else:
        print("Invalid choice.")


if __name__ == "__main__":
    main()
