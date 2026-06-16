def map_mitre(ioc_type, verdict):
    if verdict == "MALICIOUS":
        if ioc_type == "ip":
            return "T1071 - Application Layer Protocol"
        elif ioc_type == "domain":
            return "T1566 - Phishing"
        elif ioc_type == "url":
            return "T1204 - User Execution"
        elif ioc_type in ["md5", "sha1", "sha256"]:
            return "T1105 - Ingress Tool Transfer"
    return "N/A"