# Final Holdout Casebook

The final 2025 result had 107 false negatives and no false positives. These
three manually reviewed cases are a deterministic score spread: the lowest
false-negative score, midpoint false-negative score, and score nearest 0.5.
They are sanitized summaries, not raw email publications.

The terms below describe visible wording from the sanitized reviews. The saved
public final evidence records the model outcome, but the term-contribution
directions were not recomputed after the final evaluation was closed. They are
not confirmed malicious indicators or independent evidence.

## FINAL-FN-LOW

- Actual / predicted / score: phishing / legitimate / 0.201.
- Terms observed in the sanitized review: `seguridad`, organization-like
  wording, and a link reference.
- **What the email text shows:** a workplace-policy notice, a safety reference,
  and a link to a purported policy.
- **What the model inferred:** legitimate with a very low review score.
- **Why it could look routine:** workplace-policy language can look like a normal
  institutional announcement.
- **What the analyst still needs:** sender-domain alignment, the destination,
  authentication, and whether the policy was expected.
- **Recommended review or escalation:** verify the sender and destination before
  following the link; escalate if they do not align.
- **What cannot yet be concluded:** text cannot prove the linked policy is real.

## FINAL-FN-MEDIAN

- Actual / predicted / score: phishing / legitimate / 0.400.
- Terms observed in the sanitized review: `cuenta`, `tu cuenta`, and
  privacy-style wording.
- **What the email text shows:** an account-report offer, an access claim, and
  contact information.
- **What the model inferred:** legitimate despite account-related terms.
- **Why it could look routine:** a formal report offer and contact details can
  resemble ordinary business communication.
- **What the analyst still needs:** sender/reply-to alignment, destination,
  relationship history, and the recipient's expectation.
- **Recommended review or escalation:** verify through an official service path,
  not through the message.
- **What cannot yet be concluded:** the text cannot establish who controls the offer.

## FINAL-FN-NEAR-THRESHOLD

- Actual / predicted / score: phishing / legitimate / 0.499.
- Terms observed in the sanitized review: `alerta`, `24 horas`, `última`, and
  storage-service wording.
- **What the email text shows:** urgency and a request to update storage access.
- **What the model inferred:** legitimate, but only just below the 0.5 review threshold.
- **Why it could look routine:** a short storage-service update can resemble a
  familiar account notification.
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
