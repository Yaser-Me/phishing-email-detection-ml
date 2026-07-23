# SpaPhish v5 Dataset Source

## Active dataset

The active replacement dataset is:

**SpaPhish: A Spanish Dataset for Phishing and Psychological Pattern Detection**

- DOI: [10.17632/hz2d6gz7pc.5](https://doi.org/10.17632/hz2d6gz7pc.5)
- Published: May 12, 2026
- Version: 5
- License: [CC BY 4.0](https://creativecommons.org/licenses/by/4.0/)
- Official record: <https://data.mendeley.com/datasets/hz2d6gz7pc/5>

The dataset contains real Spanish-language phishing and legitimate emails
collected from the personal and institutional inboxes of its contributors. The
authors state that generic spam and synthetic generation were excluded. Three
experts labeled every message and a fourth expert handled adjudication.

The public CSV does not include inbox or contributor identifiers. The project
therefore cannot claim inbox-held-out, institution-held-out, or source-held-out
evaluation.

## Local data location

Download the official version 5 package and copy the required files to:

```text
data/external/spaphish/
```

Required local files:

```text
Spaphish dataset - DiB.csv
README.txt
dataset_schema.json
annotation_guidelines.pdf
```

The directory is ignored by Git. The official sizes and SHA-256 hashes are in
`data/spaphish_v5_manifest.json`.

The actual version 5 CSV is UTF-8 with a byte-order mark and uses a comma
delimiter. Some source documentation still describes a semicolon delimiter or
version 4. The downloaded version 5 file and its published hash are treated as
the source of truth.

## Frozen P0 grouping rules

These rules are frozen before the 2025 holdout is scored:

1. Exact duplicate key: unmodified subject plus a newline plus body.
2. Normalized key:
   - join subject and body;
   - normalize Unicode with NFKC;
   - decode HTML entities;
   - remove residual HTML tags;
   - lowercase;
   - replace URLs, email addresses, and numbers with ordinary placeholders;
   - remove remaining punctuation;
   - collapse whitespace.
3. Candidate campaign grouping:
   - use normalized text;
   - character TF-IDF with `char_wb` and n-grams from 3 to 5;
   - use `min_df=2`, `max_features=30000`, and `sublinear_tf=True`;
   - connect pairs with cosine similarity `>= 0.90`;
   - keep the complete connected group in one partition.
4. The campaign rule is a conservative heuristic. It does not prove that a
   group is one real campaign.
5. A group containing both labels is quarantined and stops evaluation.
6. If any dated group member is from 2025, the complete group moves to the
   locked final holdout.
7. Undated messages outside a 2025 group are excluded from the temporal
   experiment.
8. Remaining pre-2025 groups are split into training and validation with
   `random_state=42`.

The final holdout must not be scored during P0.

## Prediction restrictions

The P0 model may use only:

- `subject`
- `body`

It must not use row position, index, file order, date, hash, split name,
campaign group, technical metadata, the target label, persuasion annotations,
or human-written justifications.

The Logistic Regression output is called a **model review score**. It is one
signal for analyst review and is not proof that an email is malicious.

## Privacy and redistribution

SpaPhish is published under CC BY 4.0 and the project records the required
attribution. Raw messages are still not committed because the text contains
historical URLs and identifier-like values. The repository commits only code,
official hashes, aggregate findings, split identifiers, and later manually
sanitized analyst examples.

## Previous dataset

The original academic dataset contained 2,000 rows but only about 100 unique
raw messages. Approximately 95% of the rows were redundant, and every message
in the original random test split had an exact training-set match. It also mixed
real and artificial messages.

It was useful for the first university notebook, but it could not provide
credible evaluation evidence. Git history preserves the original file and
implementation after the P0 removal gate is complete.
