# Validation Casebook

These nine cases are every Logistic Regression error in the frozen pre-2025
validation partition: 2 false positives and 7 false negatives. I manually
reviewed each source record locally, then committed only the reproducible,
sanitized case output in `results/validation_triage.csv`.

## False positives

### VAL-FP-01

- Actual / predicted / score: legitimate / phishing / 0.546.
- Sanitized excerpt and influential terms: account-security code message with a
  self-service link; `cuenta`, `seguridad`, `clic`.
- **What the email text shows:** account-security wording, a code, and a link.
- **What the model inferred:** phishing review, probably because security and click
  wording overlap with phishing patterns.
- **What the analyst still needs:** sender identity, authentication, destination,
  and whether the account event was expected.
- **Recommended review or escalation:** verify before escalation.
- **What cannot yet be concluded:** text cannot prove sender ownership or link destination.

### VAL-FP-02

- Actual / predicted / score: legitimate / phishing / 0.557.
- Sanitized excerpt and influential terms: payment receipt with transaction and
  total details; `pago`, `cuenta`, `transacción`, `tarjeta`.
- **What the email text shows:** payment, account, and card wording.
- **What the model inferred:** phishing review from payment-related language.
- **What the analyst still needs:** sender, payment history, destination, and
  recipient expectation.
- **Recommended review or escalation:** compare with an expected receipt through a trusted channel.
- **What cannot yet be concluded:** text cannot confirm a real payment.

## False negatives

### VAL-FN-01

- Actual / predicted / score: phishing / legitimate / 0.332.
- Sanitized excerpt and influential terms: threat-style message claiming account
  monitoring and personal harm; `cuenta`, `hemos`, `seguridad`.
- **What the email text shows:** intimidation and a claimed compromise.
- **What the model inferred:** legitimate, with a low review score.
- **What the analyst still needs:** sender, headers, payment-demand details, and
  related campaign reports.
- **Recommended review or escalation:** escalate for threat/extortion review.
- **What cannot yet be concluded:** text cannot prove a compromise occurred.

### VAL-FN-02

- Actual / predicted / score: phishing / legitimate / 0.338.
- Sanitized excerpt and influential terms: promotional trial with a price and
  several links; `requerida`, `day`, `here`.
- **What the email text shows:** an offer, links, and persuasive marketing language.
- **What the model inferred:** legitimate, likely because it resembles a newsletter.
- **What the analyst still needs:** sender reputation, destinations, subscription
  history, and recipient expectation.
- **Recommended review or escalation:** review destinations before deciding.
- **What cannot yet be concluded:** text does not establish whether the offer is legitimate.

### VAL-FN-03

- Actual / predicted / score: phishing / legitimate / 0.351.
- Sanitized excerpt and influential terms: urgent quotation request referring to
  an attachment; `solicitud`, `adjunto`, `cuenta`.
- **What the email text shows:** urgency, business wording, and an attachment
  reference.
- **What the model inferred:** legitimate, likely because the wording looks routine.
- **What the analyst still needs:** sender domain, attachment type/hash, recipient
  relationship, and procurement context.
- **Recommended review or escalation:** quarantine the attachment and verify with a known contact.
- **What cannot yet be concluded:** text does not reveal attachment content.

### VAL-FN-04

- Actual / predicted / score: phishing / legitimate / 0.409.
- Sanitized excerpt and influential terms: short invoice notice with an
  attachment and password; `factura`, `archivo adjunto`, `archivo`.
- **What the email text shows:** invoice, attachment, and password references.
- **What the model inferred:** legitimate, despite limited context.
- **What the analyst still needs:** attachment details, sender identity, invoice
  history, and recipient expectation.
- **Recommended review or escalation:** treat the attachment as suspicious until verified.
- **What cannot yet be concluded:** text cannot show whether it is harmful.

### VAL-FN-05

- Actual / predicted / score: phishing / legitimate / 0.445.
- Sanitized excerpt and influential terms: prize notice requesting personal
  details by email; `ganador`, `envíe`, `cuenta`.
- **What the email text shows:** prize language and a personal-data request.
- **What the model inferred:** legitimate, possibly because mixed warning and prize
  language reduced the score.
- **What the analyst still needs:** sender, reply-to, routing, and contest context.
- **Recommended review or escalation:** escalate for personal-data collection review.
- **What cannot yet be concluded:** text does not prove who sent it.

### VAL-FN-06

- Actual / predicted / score: phishing / legitimate / 0.492.
- Sanitized excerpt and influential terms: card-activation notice warning that
  service will stop; `tarjeta`, `cliente`, `seguridad`.
- **What the email text shows:** service warning, activation request, and urgency.
- **What the model inferred:** legitimate, likely because familiar service wording
  appears in normal account notices too.
- **What the analyst still needs:** sender alignment, destination, account status,
  and authentication results.
- **Recommended review or escalation:** use the official service channel, not message links.
- **What cannot yet be concluded:** text cannot verify a real service change.

### VAL-FN-07

- Actual / predicted / score: phishing / legitimate / 0.499.
- Sanitized excerpt and influential terms: coupon and password-reset notice with
  account-safety wording; `clic`, `seguridad`, `cuenta`.
- **What the email text shows:** offer, password-reset prompt, and account language.
- **What the model inferred:** legitimate, despite suspicious overlap.
- **What the analyst still needs:** sender, destination, subscription history, and
  authentication results.
- **Recommended review or escalation:** independently review sender and destination.
- **What cannot yet be concluded:** text cannot confirm the claimed service.

## What these cases show

The casebook does not prove why a message is malicious. It shows why a
text-only model can miss threats or over-prioritize normal account and payment
messages. Use the [triage playbook](PHISHING_TRIAGE_PLAYBOOK.md) for the next
analyst checks.
