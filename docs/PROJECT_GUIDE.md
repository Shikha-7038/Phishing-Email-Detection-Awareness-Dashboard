# Project Guide (concepts, design and results)

## 1. What is phishing?
**Simple:** phishing is a fake message that pretends to be someone you trust so you click, reply or hand over information. **Technical:** a social-engineering attack, usually by email, that combines impersonation (sender/domain spoofing or lookalikes), pressure (urgency, fear, rewards) and a payload (credential-harvesting link or malicious attachment). Email is a top initial-access vector, so one click can start a wider compromise.
**Why no single indicator proves phishing:** real companies also send urgent mail, and attackers can use HTTPS. Detection therefore adds many weak signals and explains them. That is why this tool reports a *risk score with reasons* rather than a bare verdict. Explainability lets a SOC analyst verify the reasoning, tune rules and spot false positives, and lets users learn what to look for.

## Workflow
Email input -> preprocessing -> sender analysis -> subject/content analysis -> URL analysis -> feature extraction -> rule score (+ optional ML probability) -> risk score -> classification -> explanation -> recommendations -> dashboard and history.

## 2. Industry relevance
Secure email gateways, anti-spam systems, SOC triage queues, managed security providers and awareness-training platforms all combine rules, ML and user education. **SOC / email security analyst:** triages reported emails, checks headers and links, decides block or release. **Threat intelligence:** tracks lookalike domains and campaigns. **Incident response:** scopes who clicked and contains the damage. This project shows rule engineering, feature engineering, explainable scoring, evaluation and security awareness for those roles.

## 3. Indicators implemented (and the false-positive caveat)
Sender: excessive subdomains, odd TLD, hyphenated security-words, digit-in-word lookalikes, display-name/domain mismatch. Content: urgency, fear, financial pressure, credential request, reward bait, personal-info request, generic greeting, aggressive formatting, grammar anomalies. URL: raw IP, non-HTTPS, shorteners, subdomains, keywords, `@`, length, link-text/destination mismatch. Attachment: executable/script extensions, double extensions, archives. A real HR email can say "urgent", so each signal only adds points; context still matters. **HTTPS does not mean a site is trustworthy.**

## 5. Preprocessing (`data/preprocess.py`)
Missing values filled, duplicates removed, sender domain, attachment extension and URLs extracted, whitespace normalised. Aggressive cleaning (removing punctuation, digits, capitals, URLs) is avoided because `paypa1`, `!!!`, `URGENT` and IP-address links are the evidence.

## 6. Features (`extract_email_features`)
Counts of urgent, credential, financial and threat keywords; URL count and suspicious-URL count; `has_ip_url`; `has_shortened_url_pattern`; sender domain length and subdomain count; `suspicious_attachment`; `generic_greeting`; `contains_password_request`; `contains_personal_info_request`; link-text mismatch count; grammar-anomaly count; exclamation count; uppercase ratio; body and subject length. Each is a measurable clue a model or rule can weigh.

## 11. Scoring and thresholds
Weights: suspicious sender +15 (or +8), urgency +10, credential +20, suspicious URL +20 (or +10), risky attachment +25 (or +10), generic greeting +5, fear +10, financial +8, reward +8, personal info +12, link mismatch +10, formatting/grammar +5. Score is capped at 100. Classes: SAFE 0-10, LOW RISK 11-30, SUSPICIOUS 31-60, HIGH RISK 61-100. **These weights and thresholds are project assumptions and should be calibrated on validation data.**

## 13-15. Machine learning, confusion matrix and hybrid
Models: Logistic Regression and Naive Bayes on TF-IDF (1-2 grams, digits kept), Random Forest on TF-IDF plus the structured features. Results from `python ml/train.py` (real run, saved in `results/metrics.json`):

| Model | Accuracy | Precision | Recall | F1 | Accuracy on 12 unseen hand-written emails |
|---|---|---|---|---|---|
| Logistic Regression | 1.0 | 1.0 | 1.0 | 1.0 | 1.0 |
| Naive Bayes | 1.0 | 1.0 | 1.0 | 1.0 | 0.9167 |
| Random Forest (TF-IDF + indicators) | 1.0 | 1.0 | 1.0 | 1.0 | 1.0 |

Test set: 298 emails (train 891), stratified 75/25 split, random_state=42. Every model scored 1.0 on the held-out split because the synthetic emails come from a small set of templates, so train and test emails are near-copies. **Treat this as a pipeline sanity check, not as real-world accuracy.** The 12 hand-written emails are a small, slightly more honest check, but 12 samples prove very little. Real evaluation needs real, de-identified emails and a time-based or template-based split.

Confusion matrix (Logistic Regression, rows = actual, columns = predicted): TN 150, FP 0, FN 0, TP 148. See `results/confusion_matrices.png`. **TP** phishing caught; **TN** legitimate passed; **FP** legitimate wrongly flagged (alert fatigue); **FN** phishing missed (the dangerous one, since the user is exposed). Accuracy alone misleads when classes are imbalanced. Precision limits false alarms, recall limits misses, F1 balances them.
**Hybrid:** `0.6 x rule score + 0.4 x ML probability x 100`. Rules are transparent and ML catches wording patterns rules miss. The 0.6/0.4 weights are assumptions, and a probability is not certainty.
Top phishing terms from the Logistic Regression: http, dear, verify, details, payment, invoice, login, verify your, password expires, expires.
