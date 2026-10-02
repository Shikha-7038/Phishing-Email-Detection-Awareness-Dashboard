# Project Guide: concepts, design and results

| Section | Topic |
|---|---|
| 1 | What is phishing |
| 2 | Industry relevance |
| 3 | Workflow |
| 4 | Indicators implemented |
| 5 | Preprocessing |
| 6 | Features |
| 7 | Scoring and classes |
| 8 | Machine learning |
| 9 | Confusion matrix |
| 10 | Hybrid score |

## 1. What is phishing?
| Level | Explanation |
|---|---|
| Simple | A fake message that pretends to be someone you trust so you click, reply or hand over information |
| Technical | A social-engineering attack, usually by email, combining **impersonation** (spoofed or lookalike senders), **pressure** (urgency, fear, rewards) and a **payload** (a credential-harvesting link or malicious attachment) |

**Why one signal is not enough:** real companies also send urgent email, and attackers can use HTTPS. So this tool adds many weak signals together and **explains** them. Explainability lets a SOC analyst check the reasoning, tune rules and spot false positives, and lets users learn what to look for.

## 2. Industry relevance
| Role / system | What it does | How this project relates |
|---|---|---|
| SOC / email security analyst | Triages reported emails, checks links and headers, decides block or release | Explainable score and indicator list support triage |
| Secure email gateway / anti-spam | Filters mail at scale with rules plus ML | Hybrid rules + ML design |
| Threat intelligence | Tracks lookalike domains and campaigns | Sender and URL lookalike checks |
| Incident response | Finds who clicked and contains the damage | Incident playbook in the Awareness tab |
| Awareness training | Teaches staff to spot phishing | Checklist, tips and quiz |

## 3. Workflow
```
Email input -> preprocessing -> sender analysis -> content analysis -> URL analysis
            -> feature extraction -> rule score (+ ML probability) -> risk score
            -> classification -> explanation -> recommended actions -> history -> dashboard
```

## 4. Indicators implemented
| Category | Indicators |
|---|---|
| Sender | Excessive subdomains, unusual TLD, hyphenated security words in domain, digit-in-word lookalike, very long domain, display name that does not match the domain, invalid address |
| Content | Urgency, fear/threats, financial pressure, credential request, reward bait, personal-info request, generic greeting, aggressive formatting, grammar anomalies |
| URL | Raw IP address, non-HTTPS, shortener, many subdomains, credential keywords, `@` in URL, very long URL, digit-in-word host, link text that differs from the destination |
| Attachment | Executable or script extension, double extension (`.pdf.exe`), archive |

**False-positive caveat:** an HR email can legitimately say "urgent". Each signal only adds points, so context still matters. **HTTPS does not mean a site is trustworthy.**

## 5. Preprocessing (`data/preprocess.py`)
| Step | Why |
|---|---|
| Fill missing values | Avoid errors on empty fields |
| Remove duplicates | Prevent the same email appearing in both train and test |
| Extract sender domain, attachment extension and URLs | Reusable evidence for analysis and features |
| Normalize whitespace | Clean text without losing meaning |
| **Do not** strip punctuation, digits, capitals or URLs | `paypa1`, `!!!`, `URGENT` and IP links **are** the evidence |

## 6. Features
| # | Feature | What it measures |
|---|---|---|
| 1 | `urgent_keyword_count` | Pressure words |
| 2 | `credential_keyword_count` | Password / login / OTP wording |
| 3 | `financial_keyword_count` | Invoice / payment / wire wording |
| 4 | `threat_keyword_count` | Suspension / legal-threat wording |
| 5 | `url_count` | Links in the body |
| 6 | `suspicious_url_count` | Links scoring 30 or more |
| 7 | `has_ip_url` | A link that uses a raw IP address |
| 8 | `has_shortened_url_pattern` | A link that uses a URL shortener |
| 9 | `sender_domain_length` | Length of the sender's domain |
| 10 | `subdomain_count` | Subdomains in the sender's domain |
| 11 | `contains_password_request` | The word "password" appears |
| 12 | `contains_personal_info_request` | Personal / financial detail requests |
| 13 | `link_text_mismatch_count` | Link text that hides the real destination |
| 14 | `grammar_anomaly_count` | Repeated words, odd spacing, repeated punctuation |
| 15 | `suspicious_attachment` | Risky attachment filename |
| 16 | `generic_greeting` | Impersonal opening |
| 17 | `exclamation_count` | Number of `!` |
| 18 | `uppercase_ratio` | Share of capital letters |
| 19 | `body_length` | Characters in the body |
| 20 | `subject_length` | Characters in the subject |

## 7. Scoring and classes
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

| Class | Score | Meaning | Suggested action |
|---|---|---|---|
| SAFE | 0-10 | No meaningful indicators | Stay alert; no tool catches everything |
| LOW RISK | 11-30 | Minor signals | Confirm the request was expected |
| SUSPICIOUS | 31-60 | Several signals | Verify through another channel before acting |
| HIGH RISK | 61-100 | Likely phishing | Do not click or open; report it |

Weights and thresholds are **project assumptions** to be calibrated on validation data.

## 8. Machine learning
| Item | Detail |
|---|---|
| Data | 1,189 synthetic emails (600 legitimate, 589 phishing) |
| Split | 891 train / 298 test (stratified 75/25, `random_state=42`) |
| Text model input | TF-IDF, 1-2 word n-grams, digits kept |
| Models | Logistic Regression, Naive Bayes (TF-IDF); Random Forest (TF-IDF + 20 features) |
| Command | `python ml/train.py` (writes `results/` and `models/`) |

| Model | Input | Accuracy | Precision | Recall | F1 | Unseen set (12 emails) |
|---|---|---|---|---|---|---|
| Logistic Regression | TF-IDF | 1.0 | 1.0 | 1.0 | 1.0 | 12/12 |
| Naive Bayes | TF-IDF | 1.0 | 1.0 | 1.0 | 1.0 | 11/12 |
| Random Forest (TF-IDF + indicators) | TF-IDF + 20 features | 1.0 | 1.0 | 1.0 | 1.0 | 12/12 |

> **Read this before quoting the numbers.** Every model scored 1.0 on the held-out split because the synthetic emails are generated from a small set of templates, so training and test emails are near-copies. Treat this as proof that the **pipeline works**, not as real-world accuracy. The 12 hand-written emails are a more honest check, but 12 samples prove very little. Real evaluation needs real, de-identified emails and a template-based or time-based split.

Top phishing-leaning terms from Logistic Regression: http, dear, verify, details, payment, invoice, login, verify your, password expires, expires.

## 9. Confusion matrix
| Term | Meaning | Why it matters |
|---|---|---|
| True positive (TP) | Phishing correctly caught | The goal |
| True negative (TN) | Legitimate correctly passed | The goal |
| False positive (FP) | Legitimate wrongly flagged | Causes alert fatigue and lost trust |
| False negative (FN) | Phishing missed | The dangerous error, the user is exposed |

| Metric | Reading |
|---|---|
| Accuracy | Overall correct share; misleading when classes are unbalanced |
| Precision | Of flagged emails, how many were really phishing (limits false alarms) |
| Recall | Of real phishing, how many were caught (limits misses) |
| F1 | Balance of precision and recall |

Logistic Regression result: TN 150, FP 0, FN 0, TP 148. Chart: `results/confusion_matrices.png`.

## 10. Hybrid score
`hybrid = 0.6 x rule score + 0.4 x ML probability x 100`

| Part | Strength |
|---|---|
| Rules | Transparent, give the explanation |
| ML | Catches wording patterns the rules miss |

The 0.6 / 0.4 weights are assumptions. A probability is a second opinion, not certainty.
