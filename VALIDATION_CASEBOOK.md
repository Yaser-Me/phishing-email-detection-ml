# Validation Casebook

These eight cases are every Logistic Regression error in the corrected frozen
pre-2025 validation partition: 2 false positives and 6 false negatives. I
manually reviewed each source record locally. The committed CSV contains only
the reproducible sanitized summaries in `results/validation_triage.csv`.

Terms described as supporting a class are correlational linear-model
associations, not confirmed malicious indicators or independent evidence.
They explain the review score only within this fitted development model.

## False positives

### VAL-FP-01

- Actual / predicted / score: legitimate / phishing / 0.557.
- Text and terms: account-security code message with a self-service link;
  `cuenta`, `seguridad`, and `clic` supported phishing. The URL token supported
  legitimate classification.
- **What the email text shows:** account-security wording, a code, and a link.
- **What the model inferred:** phishing review from overlapping security wording.
- **What the analyst still needs:** sender, authentication, destination, and
  whether the event was expected.
- **Recommended review or escalation:** verify before escalation.
- **What cannot yet be concluded:** text cannot prove sender ownership or destination.

### VAL-FP-02

- Actual / predicted / score: legitimate / phishing / 0.574.
- Text and terms: payment receipt with transaction details; `pago`, `cuenta`,
  `transacción`, and `tarjeta` supported phishing.
- **What the email text shows:** payment, account, and card wording.
- **What the model inferred:** phishing review from payment-related language.
- **What the analyst still needs:** sender, payment history, destination, and expectation.
- **Recommended review or escalation:** compare with an expected receipt through a trusted channel.
- **What cannot yet be concluded:** text cannot confirm a real payment.

## False negatives

### VAL-FN-01

- Actual / predicted / score: phishing / legitimate / 0.327.
- Text and terms: low-cost trial offer with several links; `here` supported
  phishing while common English and URL terms supported legitimate classification.
- **What the email text shows:** an offer, links, and persuasive marketing language.
- **What the model inferred:** legitimate, likely because it resembles a newsletter.
- **What the analyst still needs:** sender reputation, destinations, subscription history, and expectation.
- **Recommended review or escalation:** review destinations before deciding.
- **What cannot yet be concluded:** text does not establish whether the offer is legitimate.

### VAL-FN-02

- Actual / predicted / score: phishing / legitimate / 0.345.
- Text and terms: threatening payment-demand message; `cuenta`, `hemos`, and
  `usd` supported phishing, but common terms supported legitimate overall.
- **What the email text shows:** threats, claimed compromise, urgency, and a payment demand.
- **What the model inferred:** legitimate, with a low review score.
- **What the analyst still needs:** sender, headers, payment details, and campaign reports.
- **Recommended review or escalation:** escalate for threat/extortion review.
- **What cannot yet be concluded:** text cannot prove a compromise occurred.

### VAL-FN-03

- Actual / predicted / score: phishing / legitimate / 0.413.
- Text and terms: short invoice notice with an attachment and password;
  `factura`, `archivo adjunto`, and `archivo` supported phishing.
- **What the email text shows:** invoice, attachment, and password references.
- **What the model inferred:** legitimate despite limited context.
- **What the analyst still needs:** attachment details, sender, invoice history, and expectation.
- **Recommended review or escalation:** treat the attachment as suspicious until verified.
- **What cannot yet be concluded:** text cannot show whether it is harmful.

### VAL-FN-04

- Actual / predicted / score: phishing / legitimate / 0.456.
- Text and terms: prize notice requesting personal details; `ganador`, `envíe`,
  and `cuenta` supported phishing.
- **What the email text shows:** a prize claim and a personal-data request.
- **What the model inferred:** legitimate, likely from mixed common and prize wording.
- **What the analyst still needs:** sender, reply-to, routing, and contest context.
- **Recommended review or escalation:** escalate for personal-data collection review.
- **What cannot yet be concluded:** text does not prove who sent it.

### VAL-FN-05

- Actual / predicted / score: phishing / legitimate / 0.465.
- Text and terms: unexpected personal message asking for a reply; `tengo`,
  `contigo`, and `por favor` supported phishing while greeting/date wording did not.
- **What the email text shows:** unexpected contact and a request for a reply.
- **What the model inferred:** legitimate because it resembles informal correspondence.
- **What the analyst still needs:** sender, prior relationship, reply-to, routing, and reports.
- **Recommended review or escalation:** check whether the sender and relationship are expected.
- **What cannot yet be concluded:** text alone cannot establish malicious intent or label context.

### VAL-FN-06

- Actual / predicted / score: phishing / legitimate / 0.494.
- Text and terms: invoice and payment-administration request; `cfdi`, `factura`,
  `entrega`, and `pago` supported phishing.
- **What the email text shows:** invoice, payment, delivery, and reply-request wording.
- **What the model inferred:** legitimate because detailed business language can look routine.
- **What the analyst still needs:** sender, relationship, invoice history, and payment context.
- **Recommended review or escalation:** verify through a known supplier contact first.
- **What cannot yet be concluded:** text cannot confirm a real business relationship.

## What these cases show

The casebook does not prove why a message is malicious. It shows why a text-only
model can miss threats or over-prioritize normal account and payment messages.
Use the [triage playbook](PHISHING_TRIAGE_PLAYBOOK.md) for the next analyst checks.
