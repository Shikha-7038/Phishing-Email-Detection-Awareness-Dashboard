# Project Report: Phishing Email Detection & Awareness Dashboard
**Author:** Shikha | **Programme:** MCA, Chitkara University | **Type:** Defensive cybersecurity course project

## Abstract
A local web application that analyses an email's sender, text, URLs and attachment filename with an explainable rule engine, optionally adds an ML probability, stores analysis history in SQLite and visualises it on a dashboard with an awareness module. It uses synthetic data only.

## Objectives
Detect phishing indicators; give an explainable risk score and class; recommend actions; track analytics; teach users to spot phishing.

## Architecture
Frontend (single HTML file with four tabs: Dashboard, Analyze, History, Awareness, using Chart.js) -> FastAPI (`/api/analyze`, `/api/analyses`, `/api/dashboard/*`) -> detector (sender, content, URL, attachment, score) + hybrid (ML) -> SQLite (`analyses`, `indicators`, `url_analyses`). Email bodies are not stored.

## Method
Rule weights per `docs/PROJECT_GUIDE.md`. ML: TF-IDF with 3 classifiers on 891 training emails.

## Results
| Model | Accuracy | Precision | Recall | F1 | Accuracy on 12 unseen hand-written emails |
|---|---|---|---|---|---|
| Logistic Regression | 1.0 | 1.0 | 1.0 | 1.0 | 1.0 |
| Naive Bayes | 1.0 | 1.0 | 1.0 | 1.0 | 0.9167 |
| Random Forest (TF-IDF + indicators) | 1.0 | 1.0 | 1.0 | 1.0 | 1.0 |

Test set: 298 emails (train 891), stratified 75/25 split, random_state=42. Every model scored 1.0 on the held-out split because the synthetic emails come from a small set of templates, so train and test emails are near-copies. **Treat this as a pipeline sanity check, not as real-world accuracy.** The 12 hand-written emails are a small, slightly more honest check, but 12 samples prove very little. Real evaluation needs real, de-identified emails and a time-based or template-based split.
29 automated tests pass (`python -m pytest -q tests`).

## Limitations
Synthetic, template-based data; English only; no header (SPF/DKIM/DMARC) or HTML-rendering analysis; no live URL reputation; weights are hand-set. A human must make the final decision.

## Future work
Real de-identified corpora; header authentication checks; calibrated weights; threat-intel feeds; analyst feedback loop; user login and audit log.

## Ethics and safety
No real phishing is sent, no credentials are collected, URLs are never visited, attachments are never run, and only fictional domains are used.
