# Project Report: Phishing Email Detection & Awareness Dashboard

| | |
|---|---|
| **Author** | Shikha |
| **Programme** | MCA |
| **Type** | Defensive cybersecurity course project |
| **Data** | Synthetic only |

## 1. Abstract
A local web application that analyzes an email's sender, text, links and attachment filename with an explainable rule engine, optionally adds a machine-learning probability, stores analysis history in SQLite, and shows it on a tabbed dashboard with an awareness module.

## 2. Objectives
- Detect common phishing indicators.
- Give an explainable 0-100 risk score and a class.
- Recommend actions for each result.
- Track analytics over time.
- Teach users to recognize phishing.

## 3. Architecture
| Layer | Component | Role |
|---|---|---|
| Frontend | Single HTML file with 4 tabs (Dashboard, Analyze, History, Awareness) and Chart.js | User interface and charts |
| API | FastAPI routes under `/api` | Analyze, list, delete, statistics |
| Detection | `detector.py`, `hybrid.py` | Analyzers, features, scoring, hybrid score |
| Storage | SQLite (`analyses`, `indicators`, `url_analyses`) | History; email bodies are not stored |
| ML | `ml/train.py` | Trains and compares three models |

## 4. Method
| Stage | Detail |
|---|---|
| Data | Template-generated synthetic emails, fictional domains, documentation IP ranges |
| Preprocessing | Missing values, duplicates, extraction; punctuation, digits and capitals kept |
| Features | 20 features (see `docs/PROJECT_GUIDE.md`) |
| Rule scoring | 13 weighted signals, capped at 100 |
| ML | TF-IDF with Logistic Regression, Naive Bayes and Random Forest |
| Hybrid | `0.6 x rules + 0.4 x ML probability x 100` |

## 5. Results
**Dataset:** 1,189 emails (600 legitimate, 589 phishing). **Split:** 891 train / 298 test (stratified 75/25, `random_state=42`).

| Model | Input | Accuracy | Precision | Recall | F1 | Unseen set (12 emails) |
|---|---|---|---|---|---|---|
| Logistic Regression | TF-IDF | 1.0 | 1.0 | 1.0 | 1.0 | 12/12 |
| Naive Bayes | TF-IDF | 1.0 | 1.0 | 1.0 | 1.0 | 11/12 |
| Random Forest (TF-IDF + indicators) | TF-IDF + 20 features | 1.0 | 1.0 | 1.0 | 1.0 | 12/12 |

> **Read this before quoting the numbers.** Every model scored 1.0 on the held-out split because the synthetic emails are generated from a small set of templates, so training and test emails are near-copies. Treat this as proof that the **pipeline works**, not as real-world accuracy. The 12 hand-written emails are a more honest check, but 12 samples prove very little. Real evaluation needs real, de-identified emails and a template-based or time-based split.

**Testing:** 29 automated tests pass (`python -m pytest -q tests`).

## 6. Challenge and fix
| | |
|---|---|
| Problem | After removing duplicates, the first dataset had roughly four times more phishing than legitimate emails, because the legitimate templates repeated |
| Why it matters | A model trained on lopsided data can lean toward the bigger class and look better than it is |
| Fix | Made each legitimate email unique with a reference number, rebuilt a balanced dataset, retrained |
| Honest note | This is a workaround for synthetic data. Real emails are naturally varied |

## 7. Limitations
- Synthetic, template-based data
- English only
- No SPF / DKIM / DMARC or HTML-rendering analysis
- No live URL reputation lookups
- Hand-set weights and thresholds
- A human must make the final decision

## 8. Future work
| Idea | Benefit |
|---|---|
| Real, de-identified corpora with template- or time-based split | Honest accuracy |
| Header authentication checks | Catch spoofing |
| Calibrated weights | Fewer false positives and misses |
| Threat-intelligence feeds | Known-bad domains |
| Analyst feedback loop | Continuous improvement |
| Login and audit log | Multi-user use |

## 9. Ethics and safety
No real phishing is sent, no credentials are collected, URLs are never visited, attachments are never run, and only fictional domains are used.
