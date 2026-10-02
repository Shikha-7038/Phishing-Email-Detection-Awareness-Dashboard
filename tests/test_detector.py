import os, tempfile, pytest
os.environ["PHISH_DB"] = os.path.join(tempfile.mkdtemp(), "t.db")
from fastapi.testclient import TestClient
from backend.app import app
from backend.services.detector import *

PH = dict(sender="security-alert@account-check.invalid.test", subject="URGENT: Verify Your Account Immediately",
          body="Dear customer, your account will be suspended. Verify your password now: http://198.51.100.10/verify-account")

def test_phishing_high(): assert calculate_phishing_score(**PH)["classification"] == "HIGH RISK"
def test_legit_safe():
    r = calculate_phishing_score("training@example.org", "Cybersecurity Workshop Reminder", "Hi Asha, the workshop starts Friday at 3 PM.")
    assert r["classification"] == "SAFE" and r["score"] == 0
def test_raw_ip_and_http(): f = " ".join(analyze_url("http://198.51.100.10/verify-account")["findings"]); assert "Raw IP" in f and "Non-HTTPS" in f
def test_https_not_trusted(): assert "never proves" not in " ".join(analyze_url("https://example.com")["findings"])
def test_shortener(): assert analyze_url("http://bit.ly/abc")["score"] >= 30
def test_subdomains(): assert any("subdomains" in x for x in analyze_url("https://a.b.c.d.example.com")["findings"])
def test_url_keyword(): assert any("keywords" in x for x in analyze_url("https://example.com/login")["findings"])
def test_defanged(): assert analyze_url("http://example.com")["url"].startswith("hxxp")
def test_no_url(): assert extract_email_features("a@example.com", "Hi", "Hello")["url_count"] == 0
def test_multi_url(): assert extract_email_features("a@example.com", "Hi", "http://a.invalid.test http://198.51.100.1/x")["url_count"] == 2
def test_attachments():
    assert analyze_attachment("report.pdf")["score"] == 0 and analyze_attachment("setup.exe")["score"] >= 50 and analyze_attachment("invoice.pdf.exe")["score"] >= 80
def test_invalid_sender(): assert analyze_sender("not-an-email")["score"] > 0
def test_generic_greeting(): assert analyze_email_content("x", "Dear customer, hi")["generic_greeting"]
def test_uppercase_and_exclaim(): c = analyze_email_content("WIN NOW!!!", "ACT FAST!!!"); assert c["uppercase_ratio"] > .35 and c["exclamations"] == 6
def test_empty_inputs(): assert calculate_phishing_score("", "", "")["score"] >= 0
def test_score_capped(): assert calculate_phishing_score(PH["sender"], PH["subject"] + " invoice prize", PH["body"] + " bank details wire transfer", "a.pdf.exe")["score"] <= 100
@pytest.mark.parametrize("s,c", [(0, "SAFE"), (10, "SAFE"), (11, "LOW RISK"), (30, "LOW RISK"), (31, "SUSPICIOUS"), (60, "SUSPICIOUS"), (61, "HIGH RISK")])
def test_boundaries(s, c): assert classify(s) == c

def test_api_flow():
    with TestClient(app) as c:
        assert c.post("/api/analyze", json={"sender": "a@example.com", "subject": "", "body": ""}).status_code == 422
        r = c.post("/api/analyze", json=PH); assert r.status_code == 200 and r.json()["classification"] == "HIGH RISK"
        aid = r.json()["analysis_id"]
        assert c.get(f"/api/analyses/{aid}").json()["risk_score"] == r.json()["score"]
        assert len(c.get("/api/analyses?cls=HIGH RISK").json()) >= 1
        assert c.get("/api/dashboard/stats").json()["total"] >= 240
        assert c.delete(f"/api/analyses/{aid}").status_code == 204 and c.get(f"/api/analyses/{aid}").status_code == 404

def test_new_features():
    f = extract_email_features("a@example.com", "Reset", "Enter your password. Confirm your personal details: http://bit.ly/x")
    assert f["contains_password_request"] and f["contains_personal_info_request"] and f["has_shortened_url_pattern"]
def test_link_mismatch():
    r = calculate_phishing_score("a@example.com", "Hi", 'See <a href="http://198.51.100.5/x">www.example.com</a>')
    assert any(i["type"] == "Link text mismatch" for i in r["indicators"])
def test_hybrid_math():
    from backend.services.hybrid import hybrid
    assert hybrid(70, 0.84)["score"] == round(.6 * 70 + .4 * 84) and hybrid(50, None) is None
def test_preprocess_keeps_evidence():
    from data.preprocess import load_clean
    d = load_clean(); assert d["body"].str.contains("http").any() and d["text"].str.contains("!").any() and not d.duplicated(["sender","subject","body"]).any()

def test_dashboard_has_tabs():
    html = open(os.path.join(os.path.dirname(__file__), "..", "frontend", "index.html"), encoding="utf-8").read()
    for t in ("t-dash", "t-an", "t-hist", "t-aw"): assert f'id="{t}"' in html
