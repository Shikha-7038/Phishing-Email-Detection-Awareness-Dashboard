"""Hybrid = weighted rules + ML probability. A probability is NOT certainty; it is a second opinion."""
import os, joblib
from backend.services.detector import classify
PATH = os.path.join(os.path.dirname(os.path.dirname(os.path.dirname(os.path.abspath(__file__)))), "models", "lr_tfidf.joblib")
_m = None
def ml_probability(subject, body):
    global _m
    if _m is None:
        if not os.path.exists(PATH): return None
        _m = joblib.load(PATH)
    vec, lr = _m; return float(lr.predict_proba(vec.transform([f"{subject} {body}"]))[0][1])
def hybrid(rule_score, prob, w_rule=0.6):
    if prob is None: return None
    s = round(w_rule * rule_score + (1 - w_rule) * prob * 100); return {"score": s, "classification": classify(s)}
