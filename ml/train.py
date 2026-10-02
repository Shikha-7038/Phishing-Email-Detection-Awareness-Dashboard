"""Trains and compares 3 models on the synthetic dataset. Run from project root: python ml/train.py"""
import json, os, sys
import numpy as np, joblib, matplotlib; matplotlib.use("Agg")
import matplotlib.pyplot as plt
from scipy.sparse import hstack, csr_matrix
from sklearn.ensemble import RandomForestClassifier
from sklearn.feature_extraction.text import TfidfVectorizer
from sklearn.linear_model import LogisticRegression
from sklearn.metrics import accuracy_score, confusion_matrix, f1_score, precision_score, recall_score
from sklearn.model_selection import train_test_split
from sklearn.naive_bayes import MultinomialNB
ROOT = os.path.dirname(os.path.dirname(os.path.abspath(__file__))); sys.path.insert(0, ROOT)
from backend.services.detector import extract_email_features
from data.preprocess import load_clean
from ml.unseen_examples import UNSEEN
os.makedirs(f"{ROOT}/results", exist_ok=True); os.makedirs(f"{ROOT}/models", exist_ok=True)
df = load_clean(); y = (df["label"] == "PHISHING").astype(int).values
fx = lambda r: [float(v) for v in extract_email_features(r["sender"], r["subject"], r["body"], r["attachment_name"]).values()]
F = np.array([fx(r) for _, r in df.iterrows()])
tr, te = train_test_split(np.arange(len(df)), test_size=0.25, stratify=y, random_state=42)
mk = lambda: TfidfVectorizer(lowercase=True, ngram_range=(1, 2), min_df=2, token_pattern=r"(?u)\b\w+\b")
vec = mk(); Xt = vec.fit_transform(df["text"].iloc[tr]); Xe = vec.transform(df["text"].iloc[te])
Xt2, Xe2 = hstack([Xt, csr_matrix(F[tr])]).tocsr(), hstack([Xe, csr_matrix(F[te])]).tocsr()
models = {"Logistic Regression": (LogisticRegression(max_iter=1000), Xt, Xe), "Naive Bayes": (MultinomialNB(), Xt, Xe),
          "Random Forest (TF-IDF + indicators)": (RandomForestClassifier(200, random_state=42), Xt2, Xe2)}
res, cms = {}, {}
for n, (m, a, b) in models.items():
    m.fit(a, y[tr]); p = m.predict(b)
    res[n] = {k: round(float(f(y[te], p)), 4) for k, f in [("accuracy", accuracy_score), ("precision", precision_score), ("recall", recall_score), ("f1", f1_score)]}
    cms[n] = confusion_matrix(y[te], p).tolist()
# honest generalisation check on hand-written emails the templates never produced
ud = [(f"{s} {b}", l) for _, _, b, _, l in [(0, 0, b, 0, l) for s, sub, b, a, l in UNSEEN] for s in [""]]
ut = [f"{sub} {b}" for s, sub, b, a, l in UNSEEN]; ul = np.array([l for *_, l in UNSEEN])
UF = np.array([[float(v) for v in extract_email_features(s, sub, b, a).values()] for s, sub, b, a, l in UNSEEN]); UX = vec.transform(ut)
for n, (m, *_ ) in models.items():
    x = hstack([UX, csr_matrix(UF)]).tocsr() if "Forest" in n else UX
    res[n]["unseen_accuracy"] = round(float(accuracy_score(ul, m.predict(x))), 4)
fig, ax = plt.subplots(1, 3, figsize=(13, 4))
for a, (n, cm) in zip(ax, cms.items()):
    a.imshow(cm, cmap="Blues"); a.set_title(n, fontsize=9); a.set_xticks([0, 1]); a.set_yticks([0, 1]); a.set_xticklabels(["Legit", "Phish"]); a.set_yticklabels(["Legit", "Phish"]); a.set_xlabel("Predicted"); a.set_ylabel("Actual")
    for i in range(2):
        for j in range(2): a.text(j, i, cm[i][j], ha="center", va="center", color="#c00" if i != j else "#000", fontsize=14)
plt.tight_layout(); plt.savefig(f"{ROOT}/results/confusion_matrices.png", dpi=130); plt.close()
fig, a = plt.subplots(figsize=(8, 4)); w = .2
for i, k in enumerate(["accuracy", "precision", "recall", "f1"]): a.bar(np.arange(3) + i * w, [res[n][k] for n in res], w, label=k)
a.set_xticks(np.arange(3) + .3); a.set_xticklabels([n.split(" (")[0] for n in res], fontsize=8); a.set_ylim(0, 1.05); a.legend(ncol=4, fontsize=8); a.set_title("Held-out test metrics (synthetic data)")
plt.tight_layout(); plt.savefig(f"{ROOT}/results/model_comparison.png", dpi=130); plt.close()
lr = models["Logistic Regression"][0]; names = np.array(vec.get_feature_names_out()); co = lr.coef_[0]
res["_top_phishing_terms"] = names[np.argsort(co)[-10:][::-1]].tolist(); res["_test_size"] = int(len(te)); res["_train_size"] = int(len(tr)); res["_confusion"] = cms
json.dump(res, open(f"{ROOT}/results/metrics.json", "w"), indent=2); joblib.dump((vec, lr), f"{ROOT}/models/lr_tfidf.joblib")
print(json.dumps({k: v for k, v in res.items() if not k.startswith("_")}, indent=1)); print("test/train:", len(te), len(tr), "| confusion:", cms)
