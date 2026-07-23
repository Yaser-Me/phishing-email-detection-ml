# Spanish-Language Phishing Detection Validation

This university project now focuses on **Spanish-Language Phishing Detection
Validation and Analyst Triage**. It audits the data before training, keeps
related messages in one partition, and treats the model output as a **model
review score** that can support an analyst. It does not automatically declare
an email malicious.

P0 is a development-stage credibility check. The final 2025 holdout remains
locked and has not been scored.

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
7. Preserve the 2025 holdout until the workflow and analyst review method are
   fixed.

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
| Training | 458 | 237 |
| Development validation | 114 | 47 |
| Locked 2025 holdout | 92 | 423 |
| Excluded because undated | 0 | 24 |

On the pre-2025 development validation partition, Logistic Regression recorded
0.944 accuracy, 0.917 balanced accuracy, 0.899 F1, 2 false positives, and 7
false negatives. Multinomial Naive Bayes recorded 0.901 accuracy, 0.830
balanced accuracy, 0.795 F1, 0 false positives, and 16 false negatives. These
are development results, not final or production results.

The generated evidence is in `results/dataset_audit.csv`,
`results/split_manifest.csv`, and `results/development_metrics.csv`.

## Repository contents

| File | Purpose |
|---|---|
| `phishing_email_detection.ipynb` | Readable P0 audit and development evaluation |
| `phishing_validation.py` | Shared checks, grouping, splitting, and simple models |
| `data/DATASET_SOURCE.md` | Dataset source, privacy, and historical decision |
| `data/spaphish_v5_manifest.json` | Official filenames, hashes, and frozen rules |
| `tests/test_project.py` | Focused checks using synthetic fixtures |
| `results/` | Reproducible non-sensitive P0 evidence |
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

The script refuses `--score-final-holdout` during P0. Scoring the final holdout
requires a later reviewed phase that first freezes model settings, threshold
handling, and the analyst case-analysis method.

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
