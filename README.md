# Phishing Email Detection & Awareness Dashboard
Defensive cybersecurity project: explainable phishing risk scoring for sender, content, URLs and attachment filenames, with a dense analytics dashboard and awareness module.

## Run (from this folder)
```
python -m venv venv && venv\Scripts\activate      # macOS/Linux: source venv/bin/activate
pip install -r requirements.txt
python data/generate_dataset.py
python ml/train.py        # optional: trains models, writes results/ and models/ (enables the hybrid view)
uvicorn backend.app:app --reload
```
Open http://127.0.0.1:8000 . Tests: `python -m pytest -q tests`


## Dashboard tabs
Dashboard (KPIs, 6 charts, latest analyses, score legend) | Analyze email | History (search, filter, sort, details, delete) | Awareness (checklist, tips, quiz, incident playbook). The URL hash (for example `/#hist`) opens a tab directly.

## What is inside
`backend/` FastAPI + detector + hybrid | `frontend/` dashboard | `data/` generator + preprocessing | `ml/` training | `results/` metrics and charts | `docs/` guide, report, GitHub/resume/interview kit, screenshot list | `tests/` 29 tests

## Model results (synthetic data)
| Model | Accuracy | Precision | Recall | F1 | Accuracy on 12 unseen hand-written emails |
|---|---|---|---|---|---|
| Logistic Regression | 1.0 | 1.0 | 1.0 | 1.0 | 1.0 |
| Naive Bayes | 1.0 | 1.0 | 1.0 | 1.0 | 0.9167 |
| Random Forest (TF-IDF + indicators) | 1.0 | 1.0 | 1.0 | 1.0 | 1.0 |

Test set: 298 emails (train 891), stratified 75/25 split, random_state=42. Every model scored 1.0 on the held-out split because the synthetic emails come from a small set of templates, so train and test emails are near-copies. **Treat this as a pipeline sanity check, not as real-world accuracy.** The 12 hand-written emails are a small, slightly more honest check, but 12 samples prove very little. Real evaluation needs real, de-identified emails and a time-based or template-based split.

## Safety
Synthetic data and fictional domains only. URLs are analyzed as strings, never opened. Attachments are judged by filename, never run. Email bodies are not stored. Scoring weights and thresholds are project assumptions, not universal rules.
