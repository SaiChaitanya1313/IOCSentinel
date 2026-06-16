# IOCSentinel — Threat Intelligence Automation Tool

IOCSentinel is a Python-based command-line threat intelligence tool designed to automate the validation, enrichment, and classification of Indicators of Compromise (IOCs).

It supports IPs, domains, URLs, and file hashes by integrating multiple threat intelligence sources such as VirusTotal, AbuseIPDB, and URLScan to simplify IOC triage and reporting.

---

## Features

* **Single IOC Lookup**
  Check an individual IOC interactively.

* **Bulk IOC Analysis**
  Process multiple IOCs from a `.txt` file.

* **Raw IOC Extraction**
  Automatically extract IOCs from emails, logs, or threat reports.

* **Multi-Source Threat Intelligence Enrichment**

  * VirusTotal
  * AbuseIPDB
  * URLScan

* **Severity Scoring**
  Classifies threats as:

  * Low
  * Medium
  * High
  * Critical

* **MITRE ATT&CK Mapping**
  Maps malicious IOCs to related ATT&CK techniques.

* **Caching Support**
  Prevents duplicate API calls for repeated IOCs.

* **Multi-format Reporting**
  Export reports in:

  * CSV
  * JSON
  * HTML

---

## Supported IOC Types

| IOC Type   | Supported Sources     |
| ---------- | --------------------- |
| IP Address | VirusTotal, AbuseIPDB |
| Domain     | VirusTotal            |
| URL        | VirusTotal, URLScan   |
| MD5        | VirusTotal            |
| SHA1       | VirusTotal            |
| SHA256     | VirusTotal            |

---

## Project Structure

```text
IOCSentinel/
│── iocsentinel.py
│── severity.py
│── mitre_mapper.py
│── json_export.py
│── html_report.py
│── urlscan_checker.py
│── config.example.py
│── requirements.txt
│── README.md
│── .gitignore
```

---

## Installation

Clone the repository:

```bash
git clone https://github.com/SaiChaitanya1313/IOCSentinel.git
cd IOCSentinel
```

Install dependencies:

```bash
pip install -r requirements.txt
```

---

## Configuration

Create a `config.py` file:

```python
VIRUSTOTAL_API_KEY = "your_key_here"
ABUSEIPDB_API_KEY = "your_key_here"
URLSCAN_API_KEY = "your_key_here"
```

---

## Usage

Run the tool:

```bash
python iocsentinel.py
```

Select mode:

### Mode 1 — Single IOC Check

Analyze one IOC interactively.

### Mode 2 — Bulk IOC Check

Analyze multiple IOCs from a `.txt` file.

Example:

```text
185.220.101.45
malware-domain.com
44d88612fea8a8f36de82e1278abb02f
```

### Mode 3 — Raw IOC Extraction

Paste logs, phishing emails, or reports to auto-extract IOCs.

---

## Example Output

```text
IOC: 185.220.101.45
Type: IP
VirusTotal: 17 malicious detections
AbuseIPDB Score: 100%
Severity: CRITICAL
MITRE: T1071 - Application Layer Protocol
Verdict: MALICIOUS
```

---

## Use Cases

* Threat hunting
* Phishing analysis
* IOC triage
* Malware analysis
* Incident response
* Security automation

---

## API Rate Limits

VirusTotal free API allows **4 requests per minute**.

The tool automatically enforces delays during bulk scans to avoid rate limiting.

---

## Future Improvements

* Shodan integration
* GeoIP enrichment
* PDF reporting
* Threat feed ingestion
* IOC reputation history tracking

---

## Tools & APIs

* VirusTotal API v3
* AbuseIPDB API v2
* URLScan API

---

## Author

K Sai Chaitanya

Focused on Security Operations, Threat Intelligence, Pentesting, and Security Automation.


GitHub: [SaiChaitanya1313](https://github.com/SaiChaitanya1313)
LinkedIn: [Sai Chaitanya Kondapalli](https://www.linkedin.com/in/sai-chaitanya-kondapalli-b7034325a)
