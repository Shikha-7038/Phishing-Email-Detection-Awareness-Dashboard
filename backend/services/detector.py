"""Static, explainable phishing analysis. Nothing is ever opened, fetched or executed."""
import re
from urllib.parse import urlparse

LEX = {  # category -> (keywords, points, label)
 "URGENCY": (["urgent","immediately","act now","asap","within 24 hours","final notice","expires today","right away"], 10, "Urgent language"),
 "FEAR": (["suspended","locked","terminated","legal action","unauthorized","will be closed","deactivated"], 10, "Threat / fear language"),
 "FINANCIAL": (["invoice","payment due","outstanding","refund","wire transfer","overdue","unpaid"], 8, "Financial pressure"),
 "CREDENTIAL": (["password","verify your","log in","login","credentials","otp","confirm your account","sign in"], 20, "Credential request"),
 "REWARD": (["you have won","prize","reward","gift card","congratulations"], 8, "Reward bait"),
 "PERSONAL_INFO": (["date of birth","social security","personal details","card number","bank details"], 12, "Personal-info request"),
}
SHORTENERS = {"bit.ly","tinyurl.com","t.co","goo.gl","is.gd","ow.ly"}
RISKY_EXT = {"exe","scr","bat","cmd","js","vbs","ps1","jar","msi"}
DOC_EXT = {"pdf","doc","docx","xls","xlsx","txt","png","jpg"}
ARCHIVES = {"zip","rar","7z","iso"}
URL_KW = ["verify","login","secure","update","account","password","confirm","signin"]
EMAIL_RE = re.compile(r"^([A-Za-z0-9._%+-]+)@([A-Za-z0-9.-]+\.[A-Za-z]{2,})$")
GREETING_RE = re.compile(r"^\s*(dear (customer|user|member|employee|winner|sir|madam|team member)|valued customer)", re.I)
URL_RE = re.compile(r"https?://[^\s<>\"')]+", re.I)

ANCHOR_RE = re.compile(r"<a\s+[^>]*href=[\"']([^\"']+)[\"'][^>]*>(.*?)</a>", re.I | re.S)
def link_mismatches(body):
    out = []
    for href, text in ANCHOR_RE.findall(body or ""):
        t = re.sub(r"<[^>]+>", "", text).strip().lower(); h = (urlparse(href).hostname or "").lower()
        m = re.search(r"([a-z0-9-]+(?:\.[a-z0-9-]+)+)", t)
        if m and h and m.group(1) not in h: out.append(f"Link text shows '{m.group(1)}' but points to '{h}'")
    return out

def grammar_anomalies(text):
    t = text or ""; n = len(re.findall(r"[!?]{2,}", t)) + len(re.findall(r"\b(\w+) \1\b", t, re.I)) + len(re.findall(r"\s{3,}", t)) + len(re.findall(r"(?:^|[.!?] )i ", t))
    return n

def defang(u): return u.replace("http", "hxxp").replace(".", "[.]")

def analyze_sender(sender, display_name=""):
    m = EMAIL_RE.match((sender or "").strip())
    if not m: return {"score": 40, "domain": "", "findings": ["Sender is not a valid email address"]}
    domain, labels, s, f = m.group(2).lower(), m.group(2).lower().split("."), 0, []
    if len(labels) > 3: s += 15; f.append(f"Excessive subdomains ({len(labels)-2})")
    if labels[-1] in {"invalid","test","zip","click","gq","top","xyz"}: s += 10; f.append(f"Unusual/reserved TLD '.{labels[-1]}'")
    if any(w in domain for w in ("account","secure","verify","login","alert","check")) and "-" in domain: s += 10; f.append("Security-style words with hyphens in domain")
    if re.search(r"[a-z][0-9][a-z]", domain): s += 10; f.append("Digit inside a word (possible lookalike spelling)")
    if len(domain) > 30: s += 5; f.append("Very long sender domain")
    w = re.findall(r"[a-z]{4,}", (display_name or "").lower())
    if w and w[0] not in domain: s += 10; f.append("Display name does not match sender domain")
    return {"score": min(s, 100), "domain": domain, "findings": f or ["No unusual sender patterns (an unfamiliar domain is not proof of phishing)"]}

def analyze_url(url):
    u = (url or "").strip(); p = urlparse(u if "://" in u else "http://" + u)
    host, s, f = (p.hostname or "").lower(), 0, []
    if p.scheme != "https": s += 15; f.append("Non-HTTPS URL (HTTPS alone never proves a site is safe)")
    if re.fullmatch(r"\d{1,3}(\.\d{1,3}){3}", host): s += 35; f.append("Raw IP address instead of a domain name")
    if host in SHORTENERS: s += 20; f.append("URL shortener hides the real destination")
    if max(len(host.split(".")) - 2, 0) > 2: s += 15; f.append("Excessive subdomains")
    kws = [k for k in URL_KW if k in (host + p.path + (p.query or "")).lower()]
    if kws: s += 10; f.append("Credential-style keywords in URL: " + ", ".join(kws))
    if "@" in u: s += 20; f.append("'@' in URL can disguise the real host")
    if len(u) > 75: s += 10; f.append("Unusually long URL")
    if re.search(r"[a-z][0-9][a-z]", host.split(".")[0]): s += 10; f.append("Digit inside a word in hostname")
    return {"url": defang(u), "host": host, "score": min(s, 100), "findings": f or ["No suspicious URL structure found"]}

def analyze_attachment(name):
    name = (name or "").strip().lower()
    if not name: return {"score": 0, "findings": []}
    parts = name.split("."); ext = parts[-1] if len(parts) > 1 else ""
    if len(parts) >= 3 and parts[-2] in DOC_EXT and ext in RISKY_EXT: return {"score": 85, "findings": [f"Double extension '.{parts[-2]}.{ext}' disguises an executable"]}
    if ext in RISKY_EXT: return {"score": 65, "findings": [f"Executable/script extension '.{ext}'"]}
    if ext in ARCHIVES: return {"score": 20, "findings": [f"Archive '.{ext}' can hide contents; inspect before opening"]}
    return {"score": 0, "findings": ["Common document type (still verify it was expected)"]}

def analyze_email_content(subject, body):
    text = f"{subject or ''} {body or ''}".lower(); cats = {}
    for c, (kws, _, _) in LEX.items():
        hits = [k for k in kws if k in text]
        if hits: cats[c] = hits
    raw = f"{subject or ''} {body or ''}"; letters = [c for c in raw if c.isalpha()]
    return {"categories": cats, "generic_greeting": bool(GREETING_RE.match(body or "")), "exclamations": raw.count("!"),
            "uppercase_ratio": round(sum(c.isupper() for c in letters) / max(len(letters), 1), 3), "urls": URL_RE.findall(body or ""), "mismatches": link_mismatches(body), "grammar": grammar_anomalies(raw)}

def extract_email_features(sender, subject, body, attachment=""):
    c, s = analyze_email_content(subject, body), analyze_sender(sender)
    n = lambda k: len(c["categories"].get(k, []))
    urls = [analyze_url(u) for u in c["urls"]]
    return {"urgent_keyword_count": n("URGENCY"), "credential_keyword_count": n("CREDENTIAL"), "financial_keyword_count": n("FINANCIAL"),
            "threat_keyword_count": n("FEAR"), "url_count": len(urls), "suspicious_url_count": sum(u["score"] >= 30 for u in urls),
            "has_ip_url": any(re.fullmatch(r"\d{1,3}(\.\d{1,3}){3}", u["host"]) for u in urls),
            "sender_domain_length": len(s["domain"]), "subdomain_count": max(len(s["domain"].split(".")) - 2, 0),
            "has_shortened_url_pattern": any(u["host"] in SHORTENERS for u in urls), "contains_password_request": "password" in f"{subject} {body}".lower(), "contains_personal_info_request": n("PERSONAL_INFO") > 0, "link_text_mismatch_count": len(c["mismatches"]), "grammar_anomaly_count": c["grammar"],
            "suspicious_attachment": analyze_attachment(attachment)["score"] >= 50, "generic_greeting": c["generic_greeting"],
            "exclamation_count": c["exclamations"], "uppercase_ratio": c["uppercase_ratio"], "body_length": len(body or ""), "subject_length": len(subject or "")}

def classify(score):  # thresholds are project assumptions; calibrate on validation data in real use
    return "SAFE" if score <= 10 else "LOW RISK" if score <= 30 else "SUSPICIOUS" if score <= 60 else "HIGH RISK"

ACTIONS = {
 "HIGH RISK": ["Do not click any links or open attachments.", "Verify the sender through a trusted channel.", "Report the email to your security team.", "Go to the official website/app directly instead."],
 "SUSPICIOUS": ["Hover over links and check the domain spelling.", "Confirm the request with the sender by phone or chat.", "Report it if anything still feels off."],
 "LOW RISK": ["Check that the request matches what you expected.", "Avoid sharing credentials by email."],
 "SAFE": ["No indicators found. Stay alert: no tool catches everything."]}

def calculate_phishing_score(sender, subject, body, attachment="", display_name=""):
    ind, pts = [], 0
    def add(t, d, sev, p):
        nonlocal pts; pts += p; ind.append({"type": t, "description": d, "severity": sev, "points": p})
    sd = analyze_sender(sender, display_name)
    if sd["score"] >= 20: add("Suspicious sender", "; ".join(sd["findings"]), 3, 15)
    elif sd["score"] >= 10: add("Suspicious sender", "; ".join(sd["findings"]), 2, 8)
    c = analyze_email_content(subject, body)
    for cat, hits in c["categories"].items(): add(LEX[cat][2], "Matched: " + ", ".join(hits), 3 if LEX[cat][1] >= 12 else 2, LEX[cat][1])
    if c["generic_greeting"]: add("Generic greeting", "Impersonal greeting instead of your name", 1, 5)
    if c["exclamations"] >= 3 or c["uppercase_ratio"] > 0.35: add("Aggressive formatting", "Heavy capitals or exclamation marks", 1, 5)
    if c["mismatches"]: add("Link text mismatch", "; ".join(c["mismatches"]), 3, 10)
    if c["grammar"] >= 2: add("Grammar / formatting anomalies", f"{c['grammar']} anomalies (repeated words, odd spacing, repeated punctuation)", 1, 5)
    urls = [analyze_url(u) for u in c["urls"]]; top = max((u["score"] for u in urls), default=0)
    if top >= 40: add("Suspicious URL", f"{sum(u['score']>=40 for u in urls)} high-risk link(s) found", 3, 20)
    elif top >= 15: add("Suspicious URL", "Link has weak risk signals", 2, 10)
    att = analyze_attachment(attachment)
    if att["score"] >= 50: add("Risky attachment", att["findings"][0], 3, 25)
    elif att["score"] >= 15: add("Risky attachment", att["findings"][0], 2, 10)
    score = min(pts, 100); cls = classify(score)
    return {"score": score, "classification": cls, "indicators": ind, "sender": sd, "urls": urls, "attachment": att,
            "keywords": [k for h in c["categories"].values() for k in h], "recommendations": ACTIONS[cls],
            "features": extract_email_features(sender, subject, body, attachment)}
