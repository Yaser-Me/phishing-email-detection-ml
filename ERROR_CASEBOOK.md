# Error casebook

This casebook records every error from the pre-2025 validation partition and
three selected false negatives from the locked 2025 holdout. The summaries were
written after local review and exclude raw messages, addresses, destinations,
and identifiers.

For the validation cases, terms described as supporting a class are
correlational contributions from the fitted development model. They explain its
score but are not independent indicators of maliciousness.

For the final cases, the selected records are the lowest-scoring false negative,
the midpoint false negative, and the false negative nearest the 0.5 threshold.
The public final evidence records the outcomes, but term-contribution directions
were not recomputed after the final evaluation closed. The listed terms describe
visible wording from the sanitized review only.

## Pre-2025 validation errors

The model made eight errors on 170 validation messages: 2 false positives and 6
false negatives. The corresponding generated records are in
`results/validation_triage.csv`.

### VAL-FP-01

- Actual / predicted / score: legitimate / phishing / 0.557.
- Text and terms: account-security code message with a self-service link;
  `cuenta`, `seguridad`, and `clic` contributed toward phishing.
- What the text shows: account-security wording, a code, and a link.
- What the model inferred: phishing review from overlapping security wording.
- What an analyst still needs: sender, authentication, destination, and whether
  the event was expected.
- Next step: verify those details before escalating.
- Limit: text cannot prove sender ownership or the destination.

### VAL-FP-02

- Actual / predicted / score: legitimate / phishing / 0.574.
- Text and terms: payment receipt with transaction details; `pago`, `cuenta`,
  `transacción`, and `tarjeta` contributed toward phishing.
- What the text shows: payment, account, and card wording.
- What the model inferred: phishing review from payment-related language.
- What an analyst still needs: sender, payment history, destination, and
  recipient expectation.
- Next step: compare it with an expected receipt through a trusted channel.
- Limit: text cannot confirm that a payment is real.

### VAL-FN-01

- Actual / predicted / score: phishing / legitimate / 0.327.
- Text and terms: low-cost trial offer with several links; `here` contributed
  toward phishing, while `mail` and `drive` contributed toward legitimate.
- What the text shows: an offer, links, and persuasive marketing language.
- What the model inferred: legitimate, resembling a newsletter.
- What an analyst still needs: sender reputation, destinations, subscription
  history, and expectation.
- Next step: review the destinations before deciding.
- Limit: text does not establish whether the offer is legitimate.

### VAL-FN-02

- Actual / predicted / score: phishing / legitimate / 0.345.
- Text and terms: threatening payment demand; `cuenta`, `hemos`, and `usd`
  contributed toward phishing.
- What the text shows: threats, claimed compromise, urgency, and a payment
  demand.
- What the model inferred: legitimate, with a low review score.
- What an analyst still needs: sender, headers, payment details, and campaign
  reports.
- Next step: escalate for threat or extortion review.
- Limit: text cannot prove that a compromise occurred.

### VAL-FN-03

- Actual / predicted / score: phishing / legitimate / 0.413.
- Text and terms: short invoice notice with an attachment and password;
  `factura`, `archivo adjunto`, and `archivo` contributed toward phishing.
- What the text shows: invoice, attachment, and password references.
- What the model inferred: legitimate despite limited context.
- What an analyst still needs: attachment details, sender, invoice history, and
  expectation.
- Next step: treat the attachment as suspicious until verified.
- Limit: text cannot show whether the attachment is harmful.

### VAL-FN-04

- Actual / predicted / score: phishing / legitimate / 0.456.
- Text and terms: prize notice requesting personal details; `ganador`, `envíe`,
  and `cuenta` contributed toward phishing.
- What the text shows: a prize claim and a personal-data request.
- What the model inferred: legitimate from mixed common and prize wording.
- What an analyst still needs: sender, reply-to, routing, and contest context.
- Next step: escalate for personal-data collection review.
- Limit: text does not prove who sent the message.

### VAL-FN-05

- Actual / predicted / score: phishing / legitimate / 0.465.
- Text and terms: unexpected personal message asking for a reply; `tengo`,
  `contigo`, and `por favor` contributed toward phishing.
- What the text shows: unexpected contact and a request for a reply.
- What the model inferred: legitimate, resembling informal correspondence.
- What an analyst still needs: sender, prior relationship, reply-to, routing,
  and related reports.
- Next step: determine whether the sender and relationship are expected.
- Limit: text alone cannot establish malicious intent or label context.

### VAL-FN-06

- Actual / predicted / score: phishing / legitimate / 0.494.
- Text and terms: invoice and payment-administration request; `cfdi`, `factura`,
  `entrega`, and `pago` contributed toward phishing.
- What the text shows: invoice, payment, delivery, and reply-request wording.
- What the model inferred: legitimate because detailed business language can
  look routine.
- What an analyst still needs: sender, relationship, invoice history, and
  payment context.
- Next step: verify through a known supplier contact.
- Limit: text cannot confirm a real business relationship.

These cases show both sides of the text-only limitation: ordinary security and
payment messages can be over-prioritized, while threats, invoices, prizes, and
informal contact can be missed.

## Locked 2025 false negatives

The final result contained 107 false negatives and no false positives. The three
cases below provide a deterministic spread across the missed-message scores;
they are examples, not a claim that only these patterns were missed.

### FINAL-FN-LOW

- Actual / predicted / score: phishing / legitimate / 0.201.
- Terms observed: `seguridad`, organization-like wording, and a link reference.
- What the text shows: a workplace-policy notice, a safety reference, and a link
  to a purported policy.
- What the model inferred: legitimate with a very low review score.
- Why it can look routine: institutional policy language resembles a normal
  announcement.
- What an analyst still needs: sender-domain alignment, destination,
  authentication, and whether the policy was expected.
- Next step: verify the sender and destination before following the link.
- Limit: text cannot prove that the linked policy is real.

### FINAL-FN-MEDIAN

- Actual / predicted / score: phishing / legitimate / 0.400.
- Terms observed: `cuenta`, `tu cuenta`, and privacy-style wording.
- What the text shows: an account-report offer, an access claim, and contact
  information.
- What the model inferred: legitimate despite account-related terms.
- Why it can look routine: a formal report offer and contact details resemble
  ordinary business communication.
- What an analyst still needs: sender/reply-to alignment, destination,
  relationship history, and recipient expectation.
- Next step: verify through the official service path, not through the message.
- Limit: text cannot establish who controls the offer.

### FINAL-FN-NEAR-THRESHOLD

- Actual / predicted / score: phishing / legitimate / 0.499.
- Terms observed: `alerta`, `24 horas`, `última`, and storage-service wording.
- What the text shows: urgency and a request to update storage access.
- What the model inferred: legitimate, just below the 0.5 review threshold.
- Why it can look routine: a short storage update resembles a familiar account
  notification.
- What an analyst still needs: sender, destination, account status, and whether
  a storage change was expected.
- Next step: avoid message links and verify through the normal service channel.
- Limit: text alone cannot prove an account problem.

The missed cases include both institution-like messages and a short urgent
service notice. A low score is not a reason to treat a message as safe.

## Follow-up checks

The model uses only subject and visible body text. Before reaching a conclusion,
separate what the text directly shows from what the model inferred, then seek
the missing evidence through approved systems.

| Check | Available from this model | Safe follow-up |
|---|---|---|
| Sender and reply-to relationship | No | Compare their domains. |
| Sender-domain alignment | No | Verify the claimed organization through a trusted channel. |
| URL destination | Not in sanitized output | Inspect it safely without opening it. |
| SPF, DKIM, and DMARC | No | Review headers or mail-gateway records. |
| Expected message | No | Confirm whether the recipient expected it. |
| Credential request | Sometimes visible | Check whether it uses an official workflow. |
| Payment or bank-detail change | Sometimes visible | Verify with a known contact. |
| Impersonation | Sometimes visible | Compare branding, sender, and normal communication style. |
| Attachment | Only a reference may be visible | Quarantine and scan it; inspect type and hash. |
| Urgency or pressure | Sometimes visible | Treat it as a review signal, not proof. |
| Similarity to known campaigns | No for one isolated case | Search approved security records. |

Record the score as model inference, document the direct evidence and missing
context, and escalate only when the combined evidence supports that decision.
Never block a message from the review score alone.
