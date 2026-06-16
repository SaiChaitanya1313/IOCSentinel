def calculate_severity(vt_result, abuse_result=None):
    if "error" in vt_result:
        return ("UNKNOWN", 0)

    score = 0

    malicious = vt_result.get("malicious", 0)
    suspicious = vt_result.get("suspicious", 0)

    score += malicious * 15
    score += suspicious * 5

    if abuse_result and "error" not in abuse_result:
        score += abuse_result.get("abuse_score", 0)

    if score >= 81:
        return ("CRITICAL", score)
    elif score >= 51:
        return ("HIGH", score)
    elif score >= 21:
        return ("MEDIUM", score)
    else:
        return ("LOW", score)