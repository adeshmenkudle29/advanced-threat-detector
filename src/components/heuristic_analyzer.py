import re
from urllib.parse import urlparse

class ThreatHeuristicAnalyzer:
    def __init__(self):
        # Psychological triggers and social engineering keywords
        self.urgency_keywords = [
            "immediate", "urgent", "lottery", "winner", "account suspended",
            "verify identity", "bank details", "wire transfer", "action required",
            "password expired", "unauthorized access", "limited time"
        ]
        # High-risk Top-Level Domains frequently linked to disposable phishing sites
        self.suspicious_tlds = [".xyz", ".top", ".biz", ".ru", ".work", ".click", ".tk"]

    def analyze(self, raw_email_text: str) -> dict:
        text = str(raw_email_text)
        
        # 1. Extract and inspect all URLs
        urls = re.findall(r'(https?://[^\s<>"]+|www\.[^\s<>"]+)', text)
        flagged_urls = []
        for u in urls:
            normalized_url = u if u.startswith("http") else "http://" + u
            domain = urlparse(normalized_url).netloc.lower()
            if any(domain.endswith(tld) for tld in self.suspicious_tlds) or "@" in u:
                flagged_urls.append(u)

        # 2. Match urgency and manipulation cues
        urgency_found = [
            kw for kw in self.urgency_keywords 
            if re.search(r'\b' + re.escape(kw) + r'\b', text, re.IGNORECASE)
        ]

        # 3. Calculate heuristic risk score (0 to 100)
        threat_score = (len(flagged_urls) * 35) + (len(urgency_found) * 15)
        threat_score = min(threat_score, 100)

        return {
            "threat_score": threat_score,
            "detected_urls": urls,
            "suspicious_urls": flagged_urls,
            "urgency_triggers": urgency_found
        }