# Phishing Triage Playbook

This is a small analyst workflow for the P1A model review score. It is a review
aid, not an automatic blocking rule.

## Decision flow

1. Receive a model-prioritized message and record the score as model inference.
2. Record what is actually available: P1A has only subject and visible body text.
3. Review visible indicators such as urgency, account action, payment change,
   credential request, prize, attachment reference, or impersonation wording.
4. Separate direct text evidence from what the model inferred.
5. List missing evidence before making a conclusion.
6. Safely check available organizational evidence outside the model.
7. Escalate when the text plus independent checks support risk; otherwise keep
   the decision as review-needed or benign-context-confirmed.
8. Document the reason, missing evidence, and next action.
9. Do not block an email from the model review score alone.

## Practical checklist

| Check | P1A text-only evidence | Safe follow-up |
|---|---|---|
| Sender and reply-to relationship | Unavailable | Compare sender and reply-to domains. |
| Sender-domain alignment | Unavailable | Verify the claimed organization through a trusted channel. |
| URL destination | Unavailable in sanitized output | Inspect the actual destination safely; do not open it. |
| SPF, DKIM, DMARC | Unavailable | Review message headers or mail-gateway records. |
| Expected message | Unavailable | Ask whether the recipient expected it. |
| Credential request | Sometimes visible | Check whether the request uses an official workflow. |
| Payment or bank-detail change | Sometimes visible | Verify with a known contact, not the message. |
| Impersonation | Sometimes visible | Compare branding, sender, and normal communication style. |
| Attachment review | Only an attachment reference may be visible | Quarantine and scan the file; check its type and hash. |
| Urgency or pressure | Sometimes visible | Treat it as a review signal, not proof. |
| Similarity to known campaigns | Unavailable for one case | Search approved security records for related reports. |

The SpaPhish file has some technical metadata, but P1A deliberately uses only
subject and body. These checks therefore were not performed on the P1A cases.
The final holdout's 107 false negatives show why a low score must not end review
when other available evidence is suspicious.
