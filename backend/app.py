"""FastAPI backend. Run from the project root:  uvicorn backend.app:app --reload"""
import csv, os, random, sqlite3, subprocess, sys
from collections import Counter
from datetime import datetime, timedelta
from fastapi import FastAPI, HTTPException, Query
from fastapi.responses import FileResponse
from fastapi.staticfiles import StaticFiles
from pydantic import BaseModel, Field
from backend.services.hybrid import hybrid, ml_probability
from backend.services.detector import analyze_url, calculate_phishing_score

ROOT = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
DB = os.environ.get("PHISH_DB", os.path.join(ROOT, "phishing.db"))
CSV = os.path.join(ROOT, "data", "phishing_email_dataset.csv")
app = FastAPI(title="Phishing Email Detection & Awareness Dashboard")

class Mail(BaseModel):
    sender: str = Field("", max_length=254)
    display_name: str = Field("", max_length=100)
    subject: str = Field("", max_length=300)
    body: str = Field("", max_length=20000)
    attachment: str = Field("", max_length=255)

class UrlIn(BaseModel):
    url: str = Field(..., min_length=1, max_length=2000)

def db():
    c = sqlite3.connect(DB); c.row_factory = sqlite3.Row; return c

def init():
    c = db()
    c.executescript("""CREATE TABLE IF NOT EXISTS analyses(analysis_id INTEGER PRIMARY KEY AUTOINCREMENT, sender_domain TEXT, subject TEXT, risk_score INTEGER, classification TEXT, created_at TEXT);
    CREATE TABLE IF NOT EXISTS indicators(indicator_id INTEGER PRIMARY KEY AUTOINCREMENT, analysis_id INTEGER REFERENCES analyses(analysis_id) ON DELETE CASCADE, indicator_type TEXT, description TEXT, severity INTEGER);
    CREATE TABLE IF NOT EXISTS url_analyses(url_analysis_id INTEGER PRIMARY KEY AUTOINCREMENT, analysis_id INTEGER REFERENCES analyses(analysis_id) ON DELETE CASCADE, url_safe_representation TEXT, risk_score INTEGER, findings TEXT);""")
    if c.execute("SELECT COUNT(*) FROM analyses").fetchone()[0] == 0:  # seed so the dashboard is never empty
        if not os.path.exists(CSV): subprocess.run([sys.executable, os.path.join(ROOT, "data", "generate_dataset.py")], check=True)
        rows = list(csv.DictReader(open(CSV))); rnd = random.Random(3)
        for r in rnd.sample(rows, 240):
            ts = datetime.now() - timedelta(days=rnd.randint(0, 13), minutes=rnd.randint(0, 1400))
            save(c, calculate_phishing_score(r["sender"], r["subject"], r["body"], r["attachment_name"]), r["sender"], r["subject"], ts)
    c.commit(); c.close()

def save(c, res, sender, subject, ts=None):
    domain = sender.split("@")[-1].lower() if "@" in sender else "invalid"
    cur = c.execute("INSERT INTO analyses(sender_domain,subject,risk_score,classification,created_at) VALUES(?,?,?,?,?)",
                    (domain, subject[:200], res["score"], res["classification"], (ts or datetime.now()).strftime("%Y-%m-%d %H:%M:%S")))
    aid = cur.lastrowid  # NOTE: the email body is deliberately NOT stored (privacy)
    for i in res["indicators"]: c.execute("INSERT INTO indicators(analysis_id,indicator_type,description,severity) VALUES(?,?,?,?)", (aid, i["type"], i["description"], i["severity"]))
    for k in res["keywords"]: c.execute("INSERT INTO indicators(analysis_id,indicator_type,description,severity) VALUES(?,?,?,?)", (aid, "KEYWORD", k, 1))
    for u in res["urls"]: c.execute("INSERT INTO url_analyses(analysis_id,url_safe_representation,risk_score,findings) VALUES(?,?,?,?)", (aid, u["url"], u["score"], "; ".join(u["findings"])))
    return aid

@app.on_event("startup")
def _startup(): init()

@app.post("/api/analyze")
def analyze(m: Mail):
    if not (m.subject.strip() or m.body.strip()): raise HTTPException(422, "Provide a subject or body to analyze.")
    res = calculate_phishing_score(m.sender, m.subject, m.body, m.attachment, m.display_name)
    pr = ml_probability(m.subject, m.body); res["ml_probability"] = pr; res["hybrid"] = hybrid(res["score"], pr)
    c = db(); res["analysis_id"] = save(c, res, m.sender, m.subject); c.commit(); c.close(); return res

@app.post("/api/analyze/url")
def analyze_one_url(u: UrlIn): return analyze_url(u.url)

@app.get("/api/analyses")
def analyses(cls: str = "", q: str = "", sort: str = "newest", limit: int = Query(100, le=500)):
    order = {"score_desc": "risk_score DESC", "score_asc": "risk_score ASC"}.get(sort, "created_at DESC")
    sql, args = "SELECT * FROM analyses WHERE 1=1", []
    if cls: sql += " AND classification=?"; args.append(cls)
    if q: sql += " AND (subject LIKE ? OR sender_domain LIKE ?)"; args += [f"%{q}%"] * 2
    c = db(); out = [dict(r) for r in c.execute(sql + f" ORDER BY {order} LIMIT ?", args + [limit])]; c.close(); return out

@app.get("/api/analyses/{aid}")
def one(aid: int):
    c = db(); a = c.execute("SELECT * FROM analyses WHERE analysis_id=?", (aid,)).fetchone()
    if not a: raise HTTPException(404, "Analysis not found")
    out = dict(a, indicators=[dict(r) for r in c.execute("SELECT indicator_type,description,severity FROM indicators WHERE analysis_id=? AND indicator_type!='KEYWORD'", (aid,))],
               urls=[dict(r) for r in c.execute("SELECT url_safe_representation,risk_score,findings FROM url_analyses WHERE analysis_id=?", (aid,))]); c.close(); return out

@app.delete("/api/analyses/{aid}", status_code=204)
def delete(aid: int):
    c = db(); n = c.execute("DELETE FROM analyses WHERE analysis_id=?", (aid,)).rowcount
    c.execute("DELETE FROM indicators WHERE analysis_id=?", (aid,)); c.execute("DELETE FROM url_analyses WHERE analysis_id=?", (aid,)); c.commit(); c.close()
    if not n: raise HTTPException(404, "Analysis not found")

@app.get("/api/dashboard/stats")
def stats():
    c = db(); rows = c.execute("SELECT risk_score s, classification k, date(created_at) d FROM analyses").fetchall(); c.close()
    dist = Counter(r["k"] for r in rows); hist = [0] * 10
    for r in rows: hist[min(r["s"] // 10, 9)] += 1
    today = datetime.now().date(); days = [(today - timedelta(days=i)).isoformat() for i in range(13, -1, -1)]
    trend = [{"date": d[5:], "high": sum(r["d"] == d and r["k"] == "HIGH RISK" for r in rows), "suspicious": sum(r["d"] == d and r["k"] == "SUSPICIOUS" for r in rows), "total": sum(r["d"] == d for r in rows)} for d in days]
    flagged = dist["HIGH RISK"] + dist["SUSPICIOUS"]
    return {"total": len(rows), "high": dist["HIGH RISK"], "suspicious": dist["SUSPICIOUS"], "low": dist["LOW RISK"], "safe": dist["SAFE"],
            "avg": round(sum(r["s"] for r in rows) / max(len(rows), 1), 1), "distribution": dict(dist), "histogram": hist, "trend": trend, "flagged": flagged, "clear": len(rows) - flagged}

@app.get("/api/dashboard/indicators")
def indicators():
    c = db()
    top = [dict(r) for r in c.execute("SELECT indicator_type t, COUNT(*) n FROM indicators WHERE indicator_type!='KEYWORD' GROUP BY t ORDER BY n DESC LIMIT 8")]
    kw = [dict(r) for r in c.execute("SELECT description t, COUNT(*) n FROM indicators WHERE indicator_type='KEYWORD' GROUP BY t ORDER BY n DESC LIMIT 8")]; c.close()
    return {"top": top, "keywords": kw}

@app.get("/")
def index(): return FileResponse(os.path.join(ROOT, "frontend", "index.html"))
app.mount("/static", StaticFiles(directory=os.path.join(ROOT, "frontend")), name="static")
