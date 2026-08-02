# Spanish-Language Phishing Detection Validation

This project examines how dataset leakage, repeated email templates, and
evaluation design affect phishing-classification results. The workflow audits
real Spanish-language email data, keeps related messages in one partition,
evaluates a frozen model on a later holdout, and documents where analyst review
is still required. The model output is a **model review score**; it does not
automatically declare an email malicious.

The workflow includes development error analysis and one later-period 2025
holdout evaluation with frozen settings.

## Quick review

1. Read this README for the project decision and key dataset findings.
2. Review [DETECTION_CARD.md](DETECTION_CARD.md).
3. Review [the development-versus-final comparison](results/development_final_comparison.csv).
4. Inspect [the final confusion matrix](results/final_holdout_confusion_matrix.csv)
   and its [plot](results/final_holdout_confusion_matrix.png).
5. Read [VALIDATION_CASEBOOK.md](VALIDATION_CASEBOOK.md) and the selected
   [FINAL_HOLDOUT_CASEBOOK.md](FINAL_HOLDOUT_CASEBOOK.md) examples.
6. Review the follow-up workflow in
   [PHISHING_TRIAGE_PLAYBOOK.md](PHISHING_TRIAGE_PLAYBOOK.md).
7. Inspect [tests/test_project.py](tests/test_project.py) for leakage,
   holdout-isolation, and sanitization checks.
8. Read [EVALUATION_NOTES.md](EVALUATION_NOTES.md) for the key fixed decisions.

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
8. Retrain once on permitted pre-2025 development data and evaluate the later
   2025 holdout without changing the frozen configuration.

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

## Dataset audit

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

## Development validation

Logistic Regression was fitted on training text only and evaluated on the
pre-2025 validation partition: 2 false positives, 6 false negatives, 0.953
accuracy, 0.938 balanced accuracy, and 0.926 phishing F1. Its generated
evidence is `results/validation_triage.csv`,
`results/validation_error_summary.csv`, and the development confusion matrix.
The cases are sanitized summaries, not raw email publications.

## Final 2025 holdout

The frozen Logistic Regression configuration was fit once on all 853 permitted
pre-2025 development records and evaluated on 515 locked 2025 records.

| Metric | Pre-2025 validation | Locked 2025 holdout |
|---|---:|---:|
| Accuracy | 0.953 | 0.792 |
| Balanced accuracy | 0.938 | 0.874 |
| Phishing precision | 0.962 | 1.000 |
| Phishing recall | 0.893 | 0.747 |
| Phishing F1 | 0.926 | 0.855 |
| Legitimate specificity | 0.982 | 1.000 |
| False positives | 2 | 0 |
| False negatives | 6 | 107 |

The holdout is far more phishing-weighted (423 phishing and 92 legitimate) than
validation (56 phishing and 114 legitimate), so raw accuracy and error counts
are not directly comparable. The measured drop in phishing recall is a real
holdout finding. Its cause is unresolved; temporal change, template differences,
and the limited text-only input are possibilities, not confirmed explanations.

See [the machine-readable comparison](results/development_final_comparison.csv),
[final metrics](results/final_holdout_metrics.csv),
[the final confusion matrix](results/final_holdout_confusion_matrix.csv), and
[FINAL_HOLDOUT_CASEBOOK.md](FINAL_HOLDOUT_CASEBOOK.md). No raw emails or public
final prediction rows are committed.

## Repository contents

| File | Purpose |
|---|---|
| `phishing_email_detection.ipynb` | Readable dataset audit and development evaluation |
| `phishing_validation.py` | Shared checks, grouping, splitting, and simple models |
| `data/DATASET_SOURCE.md` | Dataset source, privacy, and historical decision |
| `data/spaphish_v5_manifest.json` | Official filenames, hashes, and frozen rules |
| `tests/test_project.py` | Focused checks using synthetic fixtures |
| `results/` | Reproducible non-sensitive audit and evaluation evidence |
| `DETECTION_CARD.md` | One-page purpose, limits, and allowed claims |
| `VALIDATION_CASEBOOK.md` | Eight reviewed, sanitized validation errors |
| `FINAL_HOLDOUT_CASEBOOK.md` | Three sanitized final false-negative examples |
| `PHISHING_TRIAGE_PLAYBOOK.md` | Text-only triage workflow and missing-evidence checks |
| `EVALUATION_NOTES.md` | Short record of the key evaluation decisions |

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

Run the dataset audit and development evaluation:

```powershell
python phishing_validation.py
python -m unittest discover -s tests -v
jupyter nbconvert --execute --to notebook --inplace phishing_email_detection.ipynb
```

Run the development-only triage workflow:

```powershell
python phishing_validation.py --validation-triage
```

It regenerates primary validation metrics, the eight reviewed sanitized case
records, an aggregate error summary, and a development confusion matrix. It
does not put 2025 holdout records into fitting, prediction, or triage.

The committed 2025 result is the single official final evaluation. The public
release permanently closes `--score-final-holdout`: it refuses before reading
data, including when an alternate output directory is supplied. That prevents a
fresh clone, a missing private-predictions file, or a normal command from
creating a second official result or overwriting the committed evidence.

If a deliberate verification of the frozen procedure is needed, use the
separate private reproduction action and an empty directory **outside** this
repository:

```powershell
python phishing_validation.py --reproduce-final-holdout --reproduction-output-dir D:\private\spaphish-reproduction
```

It verifies the recorded source files, uses the committed manifest and split,
and writes only clearly prefixed local reproduction files. It cannot write
inside the repository, overwrite an earlier reproduction, or alter the
official artifacts. It is not part of normal development and should not be
used for tuning or to replace the committed final result.

## Verification and troubleshooting

| Situation | Safe check or response |
|---|---|
| External dataset is unavailable | Run `python -m unittest discover -s tests -v`. The source-data tests are expected to skip; the public checks must still pass. |
| Dataset hash or file check fails | Re-download version 5 from the official DOI and compare the four local files with `data/spaphish_v5_manifest.json`. Do not edit a hash to make a local file pass. |
| Development evidence needs checking | Run `python phishing_validation.py --validation-triage` only after the external files verify. It works only with pre-2025 development rows. |
| Official final command is refused | This is expected. The recorded result is closed; do not use another `results` directory to create a replacement. Use the explicit private reproduction path only for a deliberate frozen-procedure check. |
| Notebook check is needed | Execute `jupyter nbconvert --execute --to notebook --inplace phishing_email_detection.ipynb` after installing the pinned dependencies and locally available source data. Review the diff before retaining any output. |

## Evidence and limitations

The committed evidence is deliberately narrow: the dataset manifest and audit
support provenance and data-quality checks; `split_manifest.csv` and tests
support grouping and temporal isolation; `validation_triage.csv` and the
casebooks support sanitized development-error review; and the final metric,
confusion, and error-summary files record one frozen 2025 outcome. These
artifacts do not establish live-email performance, independent-organization
generalization, or a production blocking decision.

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

The sanitized history retains the original notebook source and the replacement
decision, while intentionally removing the original raw dataset and private
project artifacts. The active workflow uses SpaPhish v5 because its real
collected Spanish phishing and legitimate messages allow a more honest,
same-corpus validation study.
