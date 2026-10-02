"""Generates a SAFE synthetic dataset (fictional domains + RFC 5737 documentation IPs only)."""
import csv, os, random
random.seed(7)
OUT = os.path.join(os.path.dirname(__file__), "phishing_email_dataset.csv")
NAMES = ["Asha", "Rohan", "Meera", "Kabir", "Isha", "Dev", "Nina", "Arjun"]
LEGIT = [  # (sender, subject, body)
 ("registrar@example.edu", "Semester registration opens Monday", "Hello {n}, registration opens Monday at 9 AM. Visit the student portal from the university website."),
 ("hr@example.com", "Updated leave policy for 2026", "Hi {n}, the updated leave policy is attached to the HR wiki page. Please read it this week."),
 ("hr@example.com", "Urgent: submit your timesheet today", "Hi {n}, please submit your timesheet today so payroll can close on time. Thanks, HR."),
 ("training@example.org", "Cybersecurity Workshop Reminder", "Hi {n}, the workshop starts Friday at 3 PM in Hall B. Bring your laptop."),
 ("team@example.net", "Sprint 14 project update", "Hi {n}, sprint 14 is on track. Demo is on Thursday. Notes are in the shared folder."),
 ("orders@shop.example.com", "Your order #{k} has shipped", "Hello {n}, your order #{k} shipped today. Track it from the Orders page in your account."),
 ("news@digest.example.org", "Weekly newsletter: security tips", "Hello {n}, this week: patch your devices, use a password manager, enable MFA."),
 ("noreply@bank.example.com", "Your password was changed", "Hi {n}, your password was changed. If this was not you, call the number on your card."),
]
PHISH = [
 ("security-alert@account-check.invalid.test", "URGENT: Verify your account immediately", "Dear customer, your account will be suspended. Verify your password now: {u}"),
 ("billing@invoice-center.example.net", "Invoice overdue - payment due today", "Dear user, outstanding payment on invoice #{k}. Pay immediately: {u}"),
 ("rewards@prize-draw.invalid.test", "Congratulations! You have won a gift card", "Dear winner, you have won a prize. Confirm your personal details and card number: {u}"),
 ("it-support@login.secure.mail.example.com", "Password expires today", "Dear member, your password expires within 24 hours. Log in to keep access: {u}"),
 ("delivery@parc3l-track.invalid.test", "Delivery failed - action required", "Dear customer, we could not deliver. Act now and confirm your address: {u}"),
 ("hr-desk@example.com.hr-portal.invalid.test", "HR request: confirm bank details", "Dear employee, send your bank details and date of birth for payroll. URGENT. {u}"),
 ("ceo@exampl3.invalid.test", "Quick favour - urgent wire transfer", "Dear team member, I need a wire transfer right away. Reply with payment details. {u}"),
]
URLS = ["http://198.51.100.{i}/verify-account", "http://secure-login.invalid.test/update?id={k}", "http://bit.ly/x{k}", "http://203.0.113.{i}/login"]
ATT = ["", "", "", "invoice.pdf.exe", "update.scr", "form.docx", "payload.js", "details.zip"]
def row(i, label):
    n, k = random.choice(NAMES), random.randint(1000, 9999)
    if label == "LEGITIMATE":
        s, sub, b = random.choice(LEGIT)
        url = "https://www.example.com/portal" if random.random() < .6 else ""
        att = random.choice(["", "", "agenda.pdf", "notes.docx"])
    else:
        s, sub, b = random.choice(PHISH)
        url = random.choice(URLS).format(i=random.randint(1, 250), k=k)
        att = random.choice(ATT)
    body = b.format(n=n, k=k, u=url) + (f" Ref #{k}." if label == "LEGITIMATE" else "")
    return [f"E{i:04d}", s, s.split("@")[1], sub.format(k=k), body, url, att, label]
rows = [row(i, "PHISHING" if i % 2 else "LEGITIMATE") for i in range(1200)]
seen, out = set(), []
for r in rows:
    if (r[3], r[4]) not in seen: seen.add((r[3], r[4])); out.append(r)
with open(OUT, "w", newline="") as f:
    w = csv.writer(f); w.writerow(["email_id","sender","sender_domain","subject","body","urls","attachment_name","label"]); w.writerows(out)
print(f"Wrote {len(out)} synthetic emails to {OUT}")
