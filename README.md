# Spanish phishing detection: fixing a misleading evaluation

The first version of this project appeared to classify every test email
correctly. That perfect score was not trustworthy: the 2,000-row dataset held
only about 100 unique raw messages, and every message in the random test split
had an exact copy in training. The evaluation measured repetition more than
phishing detection.

This repository replaces that experiment with verified SpaPhish v5 data,
keeps duplicate-like and campaign-like messages in one partition, and reserves
2025 messages for one later-period evaluation. The frozen model did not remain
perfect: it missed 107 of 423 phishing messages in the final holdout.

That imperfect result is the point. It is credible evidence of a limited
text-only classifier, not a deployable phishing blocker. The score can help
prioritize analyst review, but it cannot establish that a message is malicious
or safe.

Start with the [model card](MODEL_CARD.md), the
[error casebook](ERROR_CASEBOOK.md), or the
[machine-readable result comparison](results/development_final_comparison.csv).

## Final result

The model was frozen after development, trained on all 853 permitted pre-2025
records, and evaluated once on 515 locked 2025 records.

| Measure | Pre-2025 validation | Locked 2025 holdout |
|---|---:|---:|
| Accuracy | 0.953 | 0.792 |
| Balanced accuracy | 0.938 | 0.874 |
| Phishing precision | 0.962 | 1.000 |
| Phishing recall | 0.893 | 0.747 |
| Phishing F1 | 0.926 | 0.855 |
| False positives | 2 | 0 |
| False negatives | 6 | 107 |

The final confusion counts were 92 true negatives, 0 false positives, 107
false negatives, and 316 true positives. Zero false positives on this holdout
does not guarantee that future legitimate messages will never be flagged. The
107 misses make automatic blocking and standalone prevention unsafe.

The holdout contains far more phishing than legitimate messages, so its raw
accuracy and error counts are not directly comparable with validation. The
drop in phishing recall is real, but this dataset alone cannot establish its
cause.

## What changed

The corrected evaluation:

1. verifies the four official SpaPhish files against recorded SHA-256 hashes;
2. audits labels, missing values, file order, residual HTML, and annotations;
3. checks exact duplicates, normalized duplicates, and high-similarity candidate
   campaign groups;
4. keeps every candidate group inside one partition;
5. fits text preprocessing on training text only;
6. excludes 2025 messages from development fitting, prediction, and case review;
7. records all eight development errors and selected final misses as sanitized
   summaries.

Only subject and visible body text enter the model. Dates, labels, row order,
hashes, split and group identifiers, technical metadata, and human annotations
are excluded from prediction.

## Data and partitions

[SpaPhish v5](https://doi.org/10.17632/hz2d6gz7pc.5) contains 1,395
Spanish-language messages: 664 legitimate and 731 phishing. The raw package is
not committed even though it is licensed CC BY 4.0; messages can contain
historical URLs and identifier-like values.

The audit found no exact duplicate groups, 35 normalized duplicate groups
affecting 89 rows, and 115 multi-message candidate groups affecting 442 rows.
Candidate grouping is a reproducible similarity heuristic, not proof of a real
campaign.

| Partition | Legitimate | Phishing |
|---|---:|---:|
| Training | 458 | 225 |
| Development validation | 114 | 56 |
| Locked 2025 holdout | 92 | 423 |
| Excluded as undated or mixed-undated | 0 | 27 |

See [the dataset source record](data/DATASET_SOURCE.md) for attribution, hashes,
privacy decisions, grouping rules, and the previous dataset findings.

## Evidence

| Question | Evidence |
|---|---|
| Were the source files verified? | [Source manifest](data/spaphish_v5_manifest.json) and [dataset audit](results/dataset_audit.csv) |
| Were related messages separated safely? | [Frozen split manifest](results/split_manifest.csv) and [tests](tests/test_project.py) |
| What happened during development? | [Development metrics](results/development_metrics.csv), [triage metrics](results/validation_triage_metrics.csv), and [sanitized cases](results/validation_triage.csv) |
| What did the final evaluation show? | [Final metrics](results/final_holdout_metrics.csv), [confusion counts](results/final_holdout_confusion_matrix.csv), and [error summary](results/final_holdout_error_summary.csv) |
| What do individual mistakes look like? | [Error casebook](ERROR_CASEBOOK.md) |
| What can the model legitimately claim? | [Model card](MODEL_CARD.md) |

No raw emails or public final prediction rows are committed.

## Run the supported workflows

Create an isolated environment and install the declared dependencies:

```powershell
python -m venv .venv
.\.venv\Scripts\Activate.ps1
python -m pip install -r requirements.txt
```

The public tests run without the raw dataset. Two source-dependent integration
tests skip when SpaPhish is absent:

```powershell
python -m unittest discover -s tests -v
```

For the source-present checks, download SpaPhish version 5 and place the four
files in the ignored `data/external/spaphish/` directory as described in the
[source record](data/DATASET_SOURCE.md). Then run:

```powershell
python phishing_validation.py
python phishing_validation.py --validation-triage
python -m unittest discover -s tests -v
jupyter nbconvert --execute --to notebook --inplace phishing_email_detection.ipynb
```

These commands regenerate only development evidence. Review the notebook and
`results/` diffs before retaining generated output.

## Frozen final evaluation

The committed 2025 result is the only official final evaluation. The normal
`--score-final-holdout` action is permanently closed and refuses before reading
data, even when given alternate paths.

A separate private reproduction action exists only for deliberate verification
of the frozen procedure. It requires the verified source files and a new output
directory outside the repository:

```powershell
python phishing_validation.py --reproduce-final-holdout --reproduction-output-dir D:\private\spaphish-reproduction
```

That action cannot overwrite the committed result and should not be used for
tuning or as a replacement evaluation.

## Limits

- The data comes from one Spanish dataset, not independent organizations or a
  live mail stream.
- Text cannot verify sender identity, authentication, destinations,
  attachments, or recipient context.
- Candidate campaign groups reduce obvious overlap but do not prove campaign
  identity or remove every possible template relationship.
- The review score is not a calibrated probability of maliciousness.
- The results do not establish production, multilingual, Qatar-specific,
  independent-inbox, or automatic-blocking performance.

The repository supports a narrower claim: careful data inspection and a frozen,
leakage-aware evaluation produced an honest result whose failures remain visible.
