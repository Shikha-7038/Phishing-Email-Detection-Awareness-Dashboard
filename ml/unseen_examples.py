"""Hand-written emails that are NOT produced by the dataset templates, to test real generalisation."""
UNSEEN = [
 ("it-helpdesk@mail-portal.invalid.test", "Mailbox storage full", "Dear user, your mailbox is full and will be deactivated. Confirm your account login here: http://203.0.113.9/mailbox", "", 1),
 ("payroll@exampl3.invalid.test", "Salary slip held", "Dear employee, we need your bank details and date of birth immediately to release your salary.", "", 1),
 ("lucky@draw-center.invalid.test", "You have won a reward!!!", "Congratulations winner. Claim your gift card now: http://bit.ly/claimit", "", 1),
 ("accounts@vendor-billing.example.net", "Overdue invoice final notice", "Outstanding payment of 4,500. Pay right away or legal action will follow. See attached.", "statement.pdf.exe", 1),
 ("security@secure-verify.login.alert.example.com", "Unusual sign in", "Dear member, sign in to verify your password within 24 hours: https://secure-verify.invalid.test/signin", "", 1),
 ("director@exampl3.invalid.test", "Confidential task", "Dear team member, buy gift cards urgently and send the card numbers. Do not tell anyone.", "", 1),
 ("professor@example.edu", "Assignment 3 deadline moved", "Hi class, the deadline for assignment 3 moves to Friday. Submit through the course page as usual.", "", 0),
 ("library@example.org", "Book reservation ready", "Hello Meera, the book you reserved is ready for pickup at the front desk until Monday.", "", 0),
 ("manager@example.com", "Team lunch on Thursday", "Hi all, team lunch is Thursday at 1 PM. Reply with dietary needs. Agenda attached.", "agenda.pdf", 0),
 ("alerts@bank.example.com", "Statement available", "Hello Dev, your monthly statement is available in the app. We never ask for your password by email.", "", 0),
 ("it@example.com", "Scheduled maintenance Saturday", "Hi team, servers will be offline Saturday 2 AM to 4 AM for maintenance. No action needed.", "", 0),
 ("events@example.net", "Hackathon registration", "Hello Isha, registration for the campus hackathon is open. Details are on the events page.", "", 0),
]
