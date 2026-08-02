# Final Holdout Casebook

The final 2025 result had 107 false negatives and no false positives. These
three manually reviewed cases are a deterministic score spread: the lowest
false-negative score, midpoint false-negative score, and score nearest 0.5.
They are sanitized summaries, not raw email publications.

## FINAL-FN-LOW

- Actual / predicted / score: phishing / legitimate / 0.201.
- Terms: `seguridad` supported phishing; organization-like wording and the URL
  token supported legitimate classification.
- **What the email text shows:** a workplace-policy notice, a safety reference,
  and a link to a purported policy.
- **What the model inferred:** legitimate with a very low review score.
- **What the analyst still needs:** sender-domain alignment, the destination,
  authentication, and whether the policy was expected.
- **Recommended review or escalation:** verify the sender and destination before
  following the link; escalate if they do not align.
- **What cannot yet be concluded:** text cannot prove the linked policy is real.

## FINAL-FN-MEDIAN

- Actual / predicted / score: phishing / legitimate / 0.400.
- Terms: `cuenta` and `tu cuenta` supported phishing; privacy-style wording
  supported legitimate classification.
- **What the email text shows:** an account-report offer, an access claim, and
  contact information.
- **What the model inferred:** legitimate despite account-related terms.
- **What the analyst still needs:** sender/reply-to alignment, destination,
  relationship history, and the recipient's expectation.
- **Recommended review or escalation:** verify through an official service path,
  not through the message.
- **What cannot yet be concluded:** the text cannot establish who controls the offer.

## FINAL-FN-NEAR-THRESHOLD

- Actual / predicted / score: phishing / legitimate / 0.499.
- Terms: `alerta`, `24 horas`, and `última` supported phishing; storage-service
  wording supported legitimate classification.
- **What the email text shows:** urgency and a request to update storage access.
- **What the model inferred:** legitimate, but only just below the 0.5 review threshold.
- **What the analyst still needs:** sender, destination, account status, and
  whether a storage change was expected.
- **Recommended review or escalation:** do not use message links; verify through
  the normal service channel.
- **What cannot yet be concluded:** text alone cannot prove an account problem.

## What the final cases show

The final model missed both longer messages that looked institution-like and a
short urgent service-style message. A low score is not a reason to treat a
message as safe. Use [PHISHING_TRIAGE_PLAYBOOK.md](PHISHING_TRIAGE_PLAYBOOK.md)
for the follow-up checks that this dataset cannot provide.
