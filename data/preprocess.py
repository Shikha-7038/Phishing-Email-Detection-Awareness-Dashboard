"""Preprocessing that keeps cybersecurity evidence (URLs, digits, capitals, punctuation) intact."""
import os, re
import pandas as pd
ROOT = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
def load_clean(path=os.path.join(ROOT, "data", "phishing_email_dataset.csv")):
    df = pd.read_csv(path).fillna("")                                   # missing-value handling
    df = df.drop_duplicates(subset=["sender", "subject", "body", "attachment_name"]).reset_index(drop=True)  # duplicate removal
    df["sender_domain"] = df["sender"].str.split("@").str[-1].str.lower()           # sender-domain extraction
    df["attachment_ext"] = df["attachment_name"].str.extract(r"\.([A-Za-z0-9]+)$")[0].fillna("").str.lower()  # extension extraction
    df["urls_found"] = df["body"].apply(lambda b: re.findall(r"https?://[^\s<>\"')]+", b))                    # URL extraction
    df["text"] = (df["subject"] + " " + df["body"]).str.replace(r"\s+", " ", regex=True).str.strip()      # light cleaning only
    # NOT done on purpose: stripping punctuation, digits, URLs or capitals (they ARE the evidence: 'paypa1', '!!!', IP URLs, 'URGENT').
    return df
