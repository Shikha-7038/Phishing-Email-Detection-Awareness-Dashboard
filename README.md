# Phishing Email Detection & Awareness Dashboard

An explainable phishing-analysis tool with a security-analytics dashboard and an awareness module. It checks an email's **sender, text, links and attachment name**, gives a **0-100 risk score** with a class, and lists **every reason** behind the score. Built as a defensive cybersecurity course project (MCA, Chitkara University) using **synthetic data only**.

## Contents
[Features](#features) · [Dashboard tabs](#dashboard-tabs) · [How it works](#how-it-works) · [Scoring](#scoring) · [Tech stack](#tech-stack) · [Project structure](#project-structure) · [Getting started](#getting-started) · [API reference](#api-reference) · [Database](#database) · [ML results](#machine-learning-results) · [Testing](#testing) · [Safety and ethics](#safety-and-ethics) · [Limitations](#limitations) · [Future work](#future-work) · [Troubleshooting](#troubleshooting)

## Features
| Area | What it does |
|---|---|
| Sender analysis | Flags odd TLDs, excessive subdomains, hyphenated "security" domains, lookalike spellings (digit inside a word) and display-name/domain mismatch |
| Content analysis | Detects urgency, threats, financial pressure, credential requests, reward bait, personal-info requests, generic greetings, aggressive formatting and grammar anomalies |
| URL analysis | Checks for raw IPs, missing HTTPS, shorteners, many subdomains, credential keywords, `@` tricks, long URLs and link text that hides the real destination |
| Attachment analysis | Judges the **filename only**: executables, scripts, double extensions (`.pdf.exe`) and archives |
| Explainable score | 0-100 score, a class, per-indicator points and recommended actions |
| Hybrid view | Combines the rule score with a Logistic Regression probability |
| History | Every analysis is stored in SQLite with search, filter, sort, detail view and delete |
| Awareness | Checklist, 10 tips, a 5-question quiz and an incident playbook |

## Dashboard tabs
| Tab | Contents |
|---|---|
| **Dashboard** | 5 KPI cards, 6 charts, latest analyses, score-to-class legend |
| **Analyze email** | Input form, sample buttons, `.txt`/`.eml` loader, result gauge, "Why?" list, URL and attachment breakdown, hybrid view, recommended actions |
| **History** | Searchable, filterable, sortable table; click a row for details; delete records |
| **Awareness** | "Before you click" checklist, tip tiles, phish-or-legitimate quiz, incident playbook |

Each tab has its own link, for example `/#hist`. On first start the database is seeded with 240 synthetic analyses so every chart has data.

## How it works
```
Email input -> sender / content / URL / attachment analyzers -> 20 features
            -> rule score (0-100) + optional ML probability -> hybrid score
            -> class + explanation + recommended actions -> SQLite history -> dashboard
```
The ML model is a second opinion. The rule engine always produces the explanation.

## Scoring
| Signal | Condition | Points |
|---|---|---|
| Suspicious sender | sender sub-score ≥ 20 (or ≥ 10) | +15 (or +8) |
| Credential request | password, verify your, login, OTP, … | +20 |
| Suspicious URL | worst link scores ≥ 40 (or ≥ 15) | +20 (or +10) |
| Risky attachment | executable/script/double extension (or archive) | +25 (or +10) |
| Personal-info request | date of birth, card number, bank details, … | +12 |
| Urgent language | urgent, immediately, within 24 hours, … | +10 |
| Threat / fear language | suspended, locked, legal action, … | +10 |
| Link text mismatch | visible link text differs from real destination | +10 |
| Financial pressure | invoice, overdue, wire transfer, … | +8 |
| Reward bait | you have won, prize, gift card, … | +8 |
| Generic greeting | "Dear customer", "Dear user", … | +5 |
| Aggressive formatting | 3+ exclamation marks or heavy capitals | +5 |
| Grammar / formatting anomalies | 2+ repeated words, odd spacing, repeated punctuation | +5 |

The total is capped at 100.

**Classes**

| Class | Score | Meaning | Suggested action |
|---|---|---|---|
| SAFE | 0-10 | No meaningful indicators | Stay alert; no tool catches everything |
| LOW RISK | 11-30 | Minor signals | Confirm the request was expected |
| SUSPICIOUS | 31-60 | Several signals | Verify through another channel before acting |
| HIGH RISK | 61-100 | Likely phishing | Do not click or open; report it |

> Weights and thresholds are **project assumptions**. They should be calibrated on validation data before any real use. HTTPS alone never proves a site is safe.

**Hybrid score** = `0.6 x rule score + 0.4 x ML probability x 100`. A probability is not certainty.

## Tech stack
| Layer | Tools |
|---|---|
| Backend | Python, FastAPI, Uvicorn, Pydantic |
| Detection | Rule-based Python modules (`detector.py`, `hybrid.py`) |
| Machine learning | scikit-learn (TF-IDF, Logistic Regression, Naive Bayes, Random Forest), pandas, matplotlib, joblib |
| Database | SQLite |
| Frontend | HTML, CSS, JavaScript, Chart.js |
| Testing | pytest, httpx |

## Project structure
```
Phishing-Email-Detection-Awareness-Dashboard/
├── backend/
│   ├── app.py                 # FastAPI app, routes, SQLite, seeding
│   └── services/
│       ├── detector.py        # analyzers, 20 features, scoring
│       └── hybrid.py          # rules + ML combination
├── frontend/index.html        # tabbed dashboard
├── data/
│   ├── generate_dataset.py    # synthetic email generator
│   ├── preprocess.py          # cleaning and extraction
│   └── phishing_email_dataset.csv
├── ml/
│   ├── train.py               # trains and compares 3 models
│   └── unseen_examples.py     # 12 hand-written test emails
├── models/                    # saved model (created by train.py)
├── results/                   # metrics.json and charts
├── docs/                      # guide, report, GitHub/resume kit, screenshots list
├── tests/test_detector.py     # 29 tests
└── requirements.txt
```

## Getting started
**Prerequisites:** Python 3.10 or newer and an internet connection (pip packages and the Chart.js CDN).

| Step | Command (Windows) | macOS / Linux |
|---|---|---|
| 1. Create a virtual environment | `python -m venv venv` | `python3 -m venv venv` |
| 2. Activate it | `venv\Scripts\activate` | `source venv/bin/activate` |
| 3. Install packages | `pip install -r requirements.txt` | same |
| 4. Generate the dataset (optional, a copy is included) | `python data/generate_dataset.py` | same |
| 5. Train the models (optional, enables the hybrid view) | `python ml/train.py` | same |
| 6. Start the app | `uvicorn backend.app:app --reload` | same |
| 7. Open the dashboard | http://127.0.0.1:8000 | same |

Run all commands from the project root folder.

**Quick try-out:** open the **Analyze email** tab, click *Phishing sample*, then *Analyze email*. Repeat with *Legitimate sample* and compare the scores and reasons.

## API reference
| Method | Endpoint | Purpose |
|---|---|---|
| POST | `/api/analyze` | Analyze an email (`sender`, `display_name`, `subject`, `body`, `attachment`) and save it |
| POST | `/api/analyze/url` | Analyze a single URL string |
| GET | `/api/analyses` | List history; query params `cls`, `q`, `sort` (`newest`, `score_desc`, `score_asc`), `limit` |
| GET | `/api/analyses/{id}` | One analysis with its indicators and URLs |
| DELETE | `/api/analyses/{id}` | Delete an analysis |
| GET | `/api/dashboard/stats` | KPIs, class counts, histogram, 14-day trend |
| GET | `/api/dashboard/indicators` | Top indicators and top keywords |

FastAPI's interactive docs are at http://127.0.0.1:8000/docs.

## Database
| Table | Columns |
|---|---|
| `analyses` | `analysis_id`, `sender_domain`, `subject`, `risk_score`, `classification`, `created_at` |
| `indicators` | `indicator_id`, `analysis_id`, `indicator_type`, `description`, `severity` |
| `url_analyses` | `url_analysis_id`, `analysis_id`, `url_safe_representation`, `risk_score`, `findings` |

Email bodies are **not stored**. URLs are stored in defanged form (`hxxp://example[.]com`).

## Machine learning results
**Dataset:** 1,189 synthetic emails (600 legitimate, 589 phishing). **Split:** 891 train / 298 test (stratified 75/25, `random_state=42`).

| Model | Input | Accuracy | Precision | Recall | F1 | Unseen set (12 emails) |
|---|---|---|---|---|---|---|
| Logistic Regression | TF-IDF | 1.0 | 1.0 | 1.0 | 1.0 | 12/12 |
| Naive Bayes | TF-IDF | 1.0 | 1.0 | 1.0 | 1.0 | 11/12 |
| Random Forest (TF-IDF + indicators) | TF-IDF + 20 features | 1.0 | 1.0 | 1.0 | 1.0 | 12/12 |

> **Read this before quoting the numbers.** Every model scored 1.0 on the held-out split because the synthetic emails are generated from a small set of templates, so training and test emails are near-copies. Treat this as proof that the **pipeline works**, not as real-world accuracy. The 12 hand-written emails are a more honest check, but 12 samples prove very little. Real evaluation needs real, de-identified emails and a template-based or time-based split.

Logistic Regression confusion matrix (rows = actual, columns = predicted):

| | Predicted legitimate | Predicted phishing |
|---|---|---|
| **Actual legitimate** | 150 (true negative) | 0 (false positive) |
| **Actual phishing** | 0 (false negative) | 148 (true positive) |

Charts are in `results/confusion_matrices.png` and `results/model_comparison.png`. Details and the 20 features are in [`docs/PROJECT_GUIDE.md`](docs/PROJECT_GUIDE.md).

## Testing
```
python -m pytest -q tests
```
29 tests cover URL, sender and attachment analyzers, feature extraction, score boundaries, hybrid maths, preprocessing, the API flow and the dashboard tabs. You may see 3 framework deprecation warnings (`on_event`, `httpx`). They do not affect results.

## Safety and ethics
- Synthetic data and fictional domains only (`.invalid.test`, `example.*`, documentation IP ranges).
- URLs are analyzed as **text** and are never opened.
- Attachments are judged by **filename** and are never run.
- Email bodies are not saved.
- The score is a decision aid. A human makes the final call.

## Limitations
- Synthetic, template-based data, so the ML scores do not reflect real-world accuracy.
- English text only.
- No email-header checks (SPF, DKIM, DMARC) and no HTML rendering analysis.
- No live URL or domain reputation lookups.
- Rule weights and thresholds are hand-set.

## Future work
- Test on real, de-identified emails with a template-based or time-based split.
- Add header authentication checks (SPF, DKIM, DMARC).
- Calibrate weights from validation data.
- Add threat-intelligence feeds and an analyst feedback loop.
- Add user login and an audit log.

## Troubleshooting
| Problem | Fix |
|---|---|
| `pip` cannot reach `files.pythonhosted.org` | Check the internet, run `ipconfig /flushdns`, try another network or turn off VPN, then retry |
| `uvicorn` not found | Activate the virtual environment and run `pip install -r requirements.txt` |
| Port 8000 busy | `uvicorn backend.app:app --reload --port 8001` |
| Charts are blank | Chart.js loads from a CDN, so the page needs internet |
| No hybrid box in results | Run `python ml/train.py` once, then restart the app |
| Want a fresh history | Stop the server, delete `phishing.db`, start again |
| Old page still showing | Hard refresh with Ctrl+F5 |

## Author
**Shikha** - MCA student, Cybersecurity course project.