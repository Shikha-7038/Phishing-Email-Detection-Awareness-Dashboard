# GitHub, Resume and Interview Kit

## Repo name and description
`Phishing-Email-Detection-Awareness-Dashboard` - "Explainable phishing email detection (rules + ML) with a security analytics dashboard and awareness module. Synthetic data only." Topics: cybersecurity, phishing-detection, soc, fastapi, machine-learning, email-security, security-awareness.

## Commit plan (suggested, one theme per commit)
1. Project skeleton, README, .gitignore 2. Synthetic dataset generator 3. Preprocessing 4. Sender and content analyzers 5. URL and attachment analyzers 6. Scoring engine + explanations 7. SQLite + FastAPI 8. Dashboard 9. Awareness module 10. ML training and results 11. Hybrid scoring 12. Tests 13. Report and screenshots. Commit them on the real days you do the work.

## README checklist
Problem, features, architecture, run steps, screenshots, results table with the honest caveat, limitations, safety statement.

## Resume bullets (every claim below is true of the delivered project)
- Built an explainable phishing-detection engine in Python/FastAPI scoring sender, content, URL and attachment indicators (0-100) with per-indicator reasons and recommended actions.
- Engineered 24 email features and compared Logistic Regression, Naive Bayes and Random Forest (TF-IDF) with precision, recall, F1 and confusion matrices; combined rules + ML in a hybrid score.
- Designed a SOC-style analytics dashboard (KPIs, 6 charts, searchable history) backed by SQLite, plus a phishing-awareness quiz and incident playbook; wrote 29 automated tests.
- Followed defensive practice: synthetic data only, static URL analysis (links never opened), no stored email bodies.

## LinkedIn post idea
Share the dashboard screenshot, the problem (email is a top attack route), one lesson (why 100% accuracy on synthetic data is not proof), and the repo link.

## Interview questions to practise
1. Why is a single indicator not enough? 2. Why avoid heavy text cleaning? 3. Precision vs recall for phishing? 4. Why are false negatives risky? 5. Why do all models score 1.0 here, and what would you change? (templated data, leakage; use real data and a template split.) 6. Why does HTTPS not mean safe? 7. How would you reduce false positives? 8. How would you add SPF/DKIM/DMARC checks? 9. How are rules and ML complementary? 10. What does a SOC analyst do with a reported email?
