# Spanish-Language Phishing Detection Validation

This university project now focuses on **Spanish-Language Phishing Detection
Validation and Analyst Triage**. It audits the data before training, keeps
related messages in one partition, and treats the model output as a **model
review score** that can support an analyst. It does not automatically declare
an email malicious.

P1A adds a development-only validation casebook and analyst-triage workflow.
The final 2025 holdout remains locked and has not been scored.

## Review this project in five minutes

1. Read this README for the project decision and key dataset findings.
2. Review [DETECTION_CARD.md](DETECTION_CARD.md).
3. Compare `results/development_metrics.csv` and
   `results/validation_triage_metrics.csv`.
4. Inspect the eight sanitized cases in
   [VALIDATION_CASEBOOK.md](VALIDATION_CASEBOOK.md).
5. Review the follow-up workflow in
   [PHISHING_TRIAGE_PLAYBOOK.md](PHISHING_TRIAGE_PLAYBOOK.md).
6. Inspect [tests/test_project.py](tests/test_project.py) for leakage,
   holdout-isolation, and sanitization checks.
7. Use [PROJECT_OWNERSHIP_GUIDE.md](PROJECT_OWNERSHIP_GUIDE.md) for the full
   explanation and interview practice.

## What the project demonstrates

1. Verify the official dataset files against recorded SHA-256 hashes.
2. Inspect labels, missing values, file order, residual HTML, and annotation
   fields before choosing prediction features.
3. Check exact duplicates, normalized duplicates, and high-similarity
   campaign candidates.
4. Keep every candidate campaign group inside one partition.
5. Fit text preprocessing only on the training partition.
6. Compare a simple Logistic Regression model with Multinomial Naive Bayes on
   the pre-2025 development validation partition.
7. Review all 2 false positives and 6 false negatives using sanitized case
   cards and a text-versus-analyst-evidence workflow.
8. Preserve the 2025 holdout until a later approved final evaluation.

Only the email subject and visible body text are used for prediction. Human
annotations, labels, dates, row order, hashes, group identifiers, and technical
metadata are excluded.

## Active dataset

The active dataset is **SpaPhish: A Spanish Dataset for Phishing and
Psychological Pattern Detection**, version 5.

- DOI: [10.17632/hz2d6gz7pc.5](https://doi.org/10.17632/hz2d6gz7pc.5)
- Published: May 12, 2026
- License: CC BY 4.0
- 1,395 records and 47 columns
- 664 legitimate and 731 phishing records
- Spanish-language messages collected from personal and institutional inboxes

The raw messages are not committed even though the license permits
redistribution. They may contain historical URLs and identifier-like values.
See [data/DATASET_SOURCE.md](data/DATASET_SOURCE.md) for the download,
attribution, integrity, privacy, and split rules.

## P0 findings

The audit reproduced these important findings:

- 0 exact duplicate groups;
- 35 normalized duplicate groups affecting 89 rows;
- 115 multi-message candidate campaign groups affecting 442 rows;
- 0 conflicting-label normalized or campaign groups;
- 3 missing subjects, 0 missing bodies, and 24 missing dates;
- every missing subject and date occurs in the phishing class;
- legitimate dates span 2014–2025 while phishing dates span 2019–2025;
- the public file is sorted into one phishing block and one legitimate block;
- residual HTML occurs in 14 phishing and 106 legitimate messages;
- 35 annotation columns are available but none are used as prediction input.

The frozen temporal/group-aware split contains:

| Partition | Legitimate | Phishing |
|---|---:|---:|
| Training | 458 | 225 |
| Development validation | 114 | 56 |
| Locked 2025 holdout | 92 | 423 |
| Excluded because undated or in a mixed undated group | 0 | 27 |

On the pre-2025 development validation partition, Logistic Regression recorded
0.953 accuracy, 0.938 balanced accuracy, 0.926 F1, 2 false positives, and 6
false negatives. Multinomial Naive Bayes recorded 0.912 accuracy, 0.866
balanced accuracy, 0.845 F1, 0 false positives, and 15 false negatives. These
are development results, not final or production results.

The generated evidence is in `results/dataset_audit.csv`,
`results/split_manifest.csv`, and `results/development_metrics.csv`.

P1A repeats the Logistic Regression validation result without using the holdout:
2 false positives, 6 false negatives, 0.953 accuracy, 0.938 balanced accuracy,
and 0.926 F1. Its generated evidence is `results/validation_triage.csv`,
`results/validation_error_summary.csv`, and the development confusion matrix.
The cases are sanitized summaries, not raw email publications.

## Repository contents

| File | Purpose |
|---|---|
| `phishing_email_detection.ipynb` | Readable P0 audit and development evaluation |
| `phishing_validation.py` | Shared checks, grouping, splitting, and simple models |
| `data/DATASET_SOURCE.md` | Dataset source, privacy, and historical decision |
| `data/spaphish_v5_manifest.json` | Official filenames, hashes, and frozen rules |
| `tests/test_project.py` | Focused checks using synthetic fixtures |
| `results/` | Reproducible non-sensitive P0 evidence |
| `DETECTION_CARD.md` | One-page purpose, limits, and allowed claims |
| `VALIDATION_CASEBOOK.md` | Nine reviewed, sanitized validation errors |
| `PHISHING_TRIAGE_PLAYBOOK.md` | Text-only triage workflow and missing-evidence checks |
| `PROJECT_OWNERSHIP_GUIDE.md` | Concise learning and interview-defense guide |
| `AGENTS.md` | Student-level coding and project scope rules |
| `phishing_email_detection_report.pdf` | Historical university report; not current P0 evidence |
| `phishing_email_detection_presentation.pptx` | Historical university presentation; not current P0 evidence |

## Run locally

Download SpaPhish version 5 from its official DOI page. Place the four required
files in `data/external/spaphish/` as described in
`data/DATASET_SOURCE.md`. That directory is ignored by Git.

Create an environment and install the small dependency set:

```powershell
python -m venv .venv
.\.venv\Scripts\Activate.ps1
python -m pip install -r requirements.txt
```

Run the reproducible P0 workflow:

```powershell
python phishing_validation.py
python -m unittest discover -s tests -v
jupyter nbconvert --execute --to notebook --inplace phishing_email_detection.ipynb
```

Run the P1A development-only triage workflow:

```powershell
python phishing_validation.py --validation-triage
```

It regenerates primary validation metrics, the eight reviewed sanitized case
records, an aggregate error summary, and a development confusion matrix. It
does not put 2025 holdout records into fitting, prediction, or triage.

The `--score-final-holdout` command is reserved for one P1B final run after the
model settings, threshold handling, and analyst case analysis are frozen.

The frozen P1B command is:

```powershell
python phishing_validation.py --score-final-holdout
```

It fits the frozen Logistic Regression pipeline once on all permitted pre-2025
development records, then scores the locked 2025 partition. It refuses a rerun
after final predictions exist.

## Honest claims and limitations

This repository supports claims about inspecting a security dataset, detecting
evaluation leakage risks, using group-aware temporal partitions, measuring
false positives and false negatives, and documenting reproducible evidence.

It does not prove production performance, automatic blocking safety, English
or Arabic capability, multilingual performance, Qatar-specific performance,
independent-inbox generalization, advanced machine-learning engineering, or
cloud/SIEM incident response. The campaign grouping is a reproducible
similarity heuristic, not proof of real campaign identity.

## Why the original dataset was replaced

The first notebook used a 2,000-row academic dataset that mixed real and
artificial messages. Direct inspection found only about 100 unique raw messages
and complete exact-message overlap between its random training and test
partitions. Its saved perfect scores therefore could not provide credible
phishing-detection evidence.

Git history preserves that original work. The active workflow uses SpaPhish v5
because its real collected Spanish phishing and legitimate messages allow a
more honest, same-corpus validation study.
