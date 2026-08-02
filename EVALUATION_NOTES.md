# Evaluation Notes

The original 2,000-row coursework dataset was replaced because repeated messages
created complete train/test overlap. Its perfect saved scores were therefore not
credible phishing-detection evidence.

SpaPhish v5 was used after file, schema, label, duplicate, and source-artifact
checks. Exact duplicates were absent, but normalized duplicates and
high-similarity candidate campaign groups were found. Every candidate group is
kept in one partition. A pre-2025 group that mixed dated and undated records is
excluded as a whole.

The final configuration uses subject and body text, Spanish-safe cleanup, word
TF-IDF 1–2 grams, Logistic Regression with balanced class weights, a 0.90
campaign-similarity rule, and a 0.5 review threshold. These settings were fixed
before the 2025 holdout result was recorded.

The 2025 result is a later-period evaluation for this dataset, not a production
claim. It supports error analysis and analyst review reasoning, not automatic
blocking.
