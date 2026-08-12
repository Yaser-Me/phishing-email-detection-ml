# Model card

## Purpose

This project tests a simple Spanish-language phishing classifier under a
leakage-aware, later-period evaluation. Its output is a review score for
prioritizing analyst attention. It is not proof that a message is malicious.

## Data and prediction boundary

- Data: SpaPhish v5, with 1,395 Spanish-language email records.
- Model input: subject and visible body text only.
- Primary model: word TF-IDF and Logistic Regression with balanced class
  weights.
- Development comparator: Multinomial Naive Bayes.
- Excluded from prediction: labels, dates, row order, hashes, split and campaign
  identifiers, technical metadata, persuasion annotations, and written
  justifications.

Raw messages remain ignored because they can contain historical URLs and
identifier-like values. Public artifacts contain aggregate values, identifiers
that cannot reconstruct message text, and manually written sanitized summaries.

## Frozen configuration

The final configuration was fixed before the 2025 holdout was scored:

- Spanish-safe visible-text cleanup;
- word TF-IDF with 1–2 grams;
- Logistic Regression with `class_weight="balanced"`;
- 0.90 similarity threshold for candidate campaign grouping;
- 0.5 review threshold;
- every candidate campaign group kept in one partition.

Candidate groups are a conservative similarity heuristic, not proof that the
messages belong to one real campaign.

## Evaluation

The pre-2025 validation partition contained 170 messages. Logistic Regression
recorded 0.953 accuracy, 0.938 balanced accuracy, 0.926 phishing F1, 2 false
positives, and 6 false negatives.

The frozen pipeline was then trained on all 853 permitted pre-2025 records and
scored the locked 2025 holdout once:

| Measure | Result |
|---|---:|
| Accuracy | 0.792 |
| Balanced accuracy | 0.874 |
| Phishing precision | 1.000 |
| Phishing recall | 0.747 |
| Phishing F1 | 0.855 |
| True negatives | 92 |
| False positives | 0 |
| False negatives | 107 |
| True positives | 316 |

The holdout never entered development fitting, prediction, threshold selection,
or case review. Its lower phishing recall is a measured result; temporal change,
template differences, and the text-only input are possible explanations, not
established causes.

## Intended use

Use the score as one input when deciding which messages deserve analyst review.
Follow it with independent evidence such as sender and reply-to alignment,
authentication results, URL destinations, attachment inspection, recipient
expectation, and known campaign information.

Do not automatically block, delete, or label a message as malicious from this
score. The 107 final false negatives show that a low score cannot establish
safety, while zero false positives on one holdout cannot guarantee that future
legitimate messages will never be flagged.

## Limitations

- Text alone cannot verify sender identity, domains, SPF/DKIM/DMARC results,
  destinations, attachments, or recipient context.
- Missing values, dates, and HTML patterns differ by label. They are audited but
  never used as prediction features.
- The evaluation uses one Spanish dataset rather than independent inboxes or a
  live mail stream.
- The review score is not a calibrated probability of maliciousness.

The evidence supports claims about dataset inspection, leakage-aware evaluation,
group-aware temporal splitting, error analysis, and analyst-review reasoning. It
does not establish production readiness, automatic-blocking safety, multilingual
or Qatar-specific performance, independent-organization generalization, or
SIEM/SOAR integration.
