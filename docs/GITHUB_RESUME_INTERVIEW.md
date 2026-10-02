# GitHub, Resume and Interview Kit

## 1. Repository setup
| Item | Suggestion |
|---|---|
| Name | `Phishing-Email-Detection-Awareness-Dashboard` |
| Description | Explainable phishing email detection (rules + ML) with a security analytics dashboard and awareness module. Synthetic data only. |
| Topics | `cybersecurity`, `phishing-detection`, `soc`, `fastapi`, `machine-learning`, `email-security`, `security-awareness` |
| Visibility | Public, with the README rendering correctly |
| Do not commit | `venv/`, `phishing.db`, `__pycache__/` (already in `.gitignore`) |

## 2. Suggested commit plan
Make each commit on the real day you do the work.

| # | Commit | Files |
|---|---|---|
| 1 | Project skeleton | README, `.gitignore`, `requirements.txt` |
| 2 | Synthetic dataset | `data/generate_dataset.py` |
| 3 | Preprocessing | `data/preprocess.py` |
| 4 | Sender and content analyzers | `backend/services/detector.py` |
| 5 | URL and attachment analyzers | `detector.py` |
| 6 | Scoring and explanations | `detector.py` |
| 7 | Database and API | `backend/app.py` |
| 8 | Dashboard | `frontend/index.html` |
| 9 | Awareness module | `frontend/index.html` |
| 10 | ML training and results | `ml/`, `results/` |
| 11 | Hybrid scoring | `backend/services/hybrid.py` |
| 12 | Tests | `tests/` |
| 13 | Docs and screenshots | `docs/` |

## 3. Resume bullets
Every claim below is true of the delivered project.
- Built an explainable phishing-detection engine in Python/FastAPI that scores sender, content, URL and attachment indicators (0-100) with per-indicator reasons and recommended actions.
- Engineered 20 email features and compared Logistic Regression, Naive Bayes and Random Forest (TF-IDF) using precision, recall, F1 and confusion matrices; combined rules and ML in a hybrid score.
- Designed a tabbed SOC-style dashboard (KPIs, 6 charts, searchable history) backed by SQLite, plus a phishing-awareness quiz and incident playbook; wrote 29 automated tests.
- Followed defensive practice: synthetic data only, URLs analyzed as text and never opened, no stored email bodies.

## 4. LinkedIn post checklist
| Do | Why |
|---|---|
| Attach 2-4 screenshots | Posts with images get more attention |
| Include the repo link | Lets people verify the work |
| State the 100% accuracy caveat | Shows you understand evaluation |
| Say future work is a plan, not done | Keeps every claim accurate |

## 5. Interview questions and short answers
| Question | Short answer |
|---|---|
| Why is one indicator not enough? | Legitimate emails can also be urgent and attackers can use HTTPS, so signals are combined and explained |
| Why avoid heavy text cleaning? | Punctuation, digits, capitals and URLs are the evidence (`paypa1`, `!!!`, IP links) |
| Precision or recall for phishing? | Both matter. Recall limits missed phishing, precision limits false alarms; F1 balances them |
| Why are false negatives risky? | A missed phishing email leaves the user exposed |
| Why did every model score 1.0? | Synthetic template data means train and test are near-copies. It shows the pipeline works, not real accuracy. Fix: real data and a template-based split |
| Why does HTTPS not mean safe? | Attackers can get certificates too. HTTPS only encrypts the connection |
| How would you reduce false positives? | Calibrate weights on labelled data, add allow-lists and sender reputation, use analyst feedback |
| How would you add SPF/DKIM/DMARC? | Parse the `Authentication-Results` header and add points when checks fail |
| How do rules and ML complement each other? | Rules are transparent and explain; ML catches wording patterns rules miss |
| Why add a reference number to legitimate emails? | De-duplication had unbalanced the dataset. It is a workaround for synthetic data; real emails are naturally varied |
| What does a SOC analyst do with a reported email? | Check sender, links and headers, decide block or release, and report or escalate |
