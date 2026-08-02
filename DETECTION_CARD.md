# Detection Card

## Capability

Spanish-Language Phishing Detection Validation and Analyst Triage.

## Dataset and model

- Active data: SpaPhish v5, Spanish-language email records.
- Input: subject and visible body only.
- Model: word TF-IDF and Logistic Regression with `class_weight="balanced"`.
- Comparator: Multinomial Naive Bayes in the development evaluation.
- Never-use fields: label, date, row/file order, hash, split, campaign group,
  technical metadata, persuasion annotations, and human-written justifications.

## Intended use

Use the model review score to prioritize an analyst's review of a message. The
development casebook documents eight mistakes and the follow-up evidence an
analyst would need.

> The model review score prioritizes analyst review. It is not proof that an email is malicious.

## Prohibited use

- Do not automatically block, delete, or label an email as malicious from this score.
- Do not use the prohibited fields above as model inputs.
- Do not claim production, multilingual, English, Arabic, Qatar-specific, or
  independent-inbox performance.

## Development evidence

The locked split uses pre-2025 training and validation records only. Logistic
Regression recorded 0.953 accuracy, 0.938 balanced accuracy, 0.926 F1, 2 false
positives, and 6 false negatives on 170 validation emails. The development
triage command regenerates sanitized case data and the confusion matrix.

## Final-holdout status

The frozen pipeline was trained on all permitted pre-2025 development records
and scored the locked 2025 holdout once. It recorded 0.792 accuracy, 0.874
balanced accuracy, 1.000 phishing precision, 0.747 phishing recall, 0.855 F1,
0 false positives, and 107 false negatives on 92 legitimate and 423 phishing
messages. The holdout never entered development fitting, prediction, or case
review.

Final confusion counts: 92 true negatives, 0 false positives, 316 true
positives, and 107 false negatives. Zero final false positives does not show
that future legitimate emails will never be flagged. The 107 false negatives
make automatic blocking and standalone phishing prevention unsafe.

## Known limitations and privacy

- Candidate campaign groups are a similarity heuristic, not campaign proof.
- Date and missing-value patterns differ by label; they are audited but not used.
- The later holdout's phishing recall was lower than development validation;
  the cause is not established from this one dataset.
- Text-only data cannot verify sender identity, domains, authentication, URLs,
  attachments, or recipient context.
- Raw email files stay ignored. Published results contain only aggregate values
  and manually reviewed sanitized case notes.

## Allowed claims

This repository demonstrates reproducible email-dataset checks, leakage-aware
development evaluation, validation error analysis, and careful analyst-triage
reasoning. It does not demonstrate a deployable phishing blocker, a calibrated
maliciousness probability, or generalization beyond this Spanish dataset.

## Prohibited claims

Do not claim production readiness, automatic blocking, zero false-positive
guarantees, detection of all phishing, English/Arabic/multilingual or
Qatar-specific performance, independent-organization generalization, SIEM/SOAR
integration, or professional SOC experience.
