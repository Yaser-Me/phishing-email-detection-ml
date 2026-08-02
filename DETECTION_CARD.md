# Detection Card

## Capability

Spanish-Language Phishing Detection Validation and Analyst Triage.

## Dataset and model

- Active data: SpaPhish v5, Spanish-language email records.
- Input: subject and visible body only.
- Model: word TF-IDF and Logistic Regression with `class_weight="balanced"`.
- Comparator: Multinomial Naive Bayes in the P0 development result.

## Intended use

Use the model review score to prioritize an analyst's review of a message. P1A
documents the nine pre-2025 validation mistakes and the follow-up evidence an
analyst would need.

> The model review score prioritizes analyst review. It is not proof that an email is malicious.

## Prohibited use

- Do not automatically block, delete, or label an email as malicious from this score.
- Do not use annotation columns, dates, row order, hashes, groups, or metadata
  as model inputs.
- Do not claim production, multilingual, English, Arabic, Qatar-specific, or
  independent-inbox performance.

## Development evidence

The locked split uses pre-2025 training and validation records only. Logistic
Regression recorded 0.944 accuracy, 0.917 balanced accuracy, 0.899 F1, 2 false
positives, and 7 false negatives on 161 validation emails. The P1A command
regenerates the sanitized error casebook data and confusion matrix.

## Final-holdout status

The 2025 holdout is locked, unscored, and excluded from P1A loading, fitting,
prediction, and case review.

## Known limitations and privacy

- Candidate campaign groups are a similarity heuristic, not campaign proof.
- Date and missing-value patterns differ by label; they are audited but not used.
- Text-only data cannot verify sender identity, domains, authentication, URLs,
  attachments, or recipient context.
- Raw email files stay ignored. Published results contain only aggregate values
  and manually reviewed sanitized case notes.

## Allowed claims

This repository demonstrates reproducible email-dataset checks, leakage-aware
development evaluation, validation error analysis, and careful analyst-triage
reasoning. It does not demonstrate a deployable phishing blocker.
