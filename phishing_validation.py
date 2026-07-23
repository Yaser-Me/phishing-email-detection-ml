"""Reproducible SpaPhish v5 checks and P0 development evaluation."""

import argparse
import hashlib
import html
import json
import re
import unicodedata
from pathlib import Path

import numpy as np
import pandas as pd
from sklearn.feature_extraction.text import TfidfVectorizer
from sklearn.linear_model import LogisticRegression
from sklearn.metrics import (
    accuracy_score,
    balanced_accuracy_score,
    confusion_matrix,
    f1_score,
    precision_score,
    recall_score,
    roc_auc_score,
)
from sklearn.metrics.pairwise import cosine_similarity
from sklearn.model_selection import train_test_split
from sklearn.naive_bayes import MultinomialNB


ROOT = Path(__file__).resolve().parent
DEFAULT_DATASET = ROOT / "data" / "external" / "spaphish" / "Spaphish dataset - DiB.csv"
DEFAULT_MANIFEST = ROOT / "data" / "spaphish_v5_manifest.json"
DEFAULT_RESULTS = ROOT / "results"

RANDOM_SEED = 42
HOLDOUT_YEAR = 2025
CAMPAIGN_SIMILARITY_THRESHOLD = 0.90
VALIDATION_FRACTION = 0.20
FINAL_HOLDOUT_LOCKED = True

EXPECTED_COLUMNS = [
    "hash",
    "subject",
    "body",
    "date",
    "url_count",
    "urls",
    "attachments_count",
    "attachments_types",
    "attachments_total_size",
    "attachments_sizes",
    "hops_count",
    "Label",
    "authority_A",
    "justif_authority_A",
    "social_proof_A",
    "justif_social_proof_A",
    "liking_similarity_deception_A",
    "justif_liking_similarity_deception_A",
    "commitment_integrity_reciprocation_A",
    "justif_commitment_integrity_reciprocation_A",
    "distraction_A",
    "justif_distraction_A",
    "authority_B",
    "justif_authority_B",
    "social_proof_B",
    "justif_social_proof_B",
    "liking_similarity_deception_B",
    "justif_liking_similarity_deception_B",
    "commitment_integrity_reciprocation_B",
    "justif_commitment_integrity_reciprocation_B",
    "distraction_B",
    "justif_distraction_B",
    "authority_C",
    "justif_authority_C",
    "social_proof_C",
    "justif_social_proof_C",
    "liking_similarity_deception_C",
    "justif_liking_similarity_deception_C",
    "commitment_integrity_reciprocation_C",
    "justif_commitment_integrity_reciprocation_C",
    "distraction_C",
    "justif_distraction_C",
    "authority",
    "social_proof",
    "liking_similarity_deception",
    "commitment_integrity_reciprocation",
    "distraction",
]

PREDICTION_COLUMNS = ["subject", "body"]
ANNOTATION_COLUMNS = EXPECTED_COLUMNS[12:]
SAFE_SPLIT_COLUMNS = ["hash", "campaign_group", "Label", "date_year", "split"]
SAFE_METRIC_COLUMNS = [
    "model",
    "partition",
    "accuracy",
    "balanced_accuracy",
    "precision",
    "recall",
    "f1",
    "roc_auc",
    "true_negative",
    "false_positive",
    "false_negative",
    "true_positive",
    "legitimate_support",
    "phishing_support",
]

HTML_TAG_PATTERN = re.compile(r"<[^>\n]+>")
HTML_TAG_NAME_PATTERN = re.compile(r"<\s*/?\s*[A-Za-z][A-Za-z0-9]*\b")
URL_PATTERN = re.compile(r"(?i)\b(?:https?://|www\.)\S+")
EMAIL_PATTERN = re.compile(r"(?i)\b[A-Z0-9._%+-]+@[A-Z0-9.-]+\.[A-Z]{2,}\b")
NUMBER_PATTERN = re.compile(r"\b\d+\b")
PUNCTUATION_PATTERN = re.compile(r"[^\w\s<>]", re.UNICODE)
WHITESPACE_PATTERN = re.compile(r"\s+")


def load_manifest(manifest_path=DEFAULT_MANIFEST):
    """Load the small committed source and checksum manifest."""
    with Path(manifest_path).open(encoding="utf-8") as handle:
        return json.load(handle)


def file_sha256(file_path):
    """Calculate a SHA-256 value without loading the complete file into memory."""
    digest = hashlib.sha256()
    with Path(file_path).open("rb") as handle:
        for block in iter(lambda: handle.read(1024 * 1024), b""):
            digest.update(block)
    return digest.hexdigest()


def verify_external_files(external_dir, manifest_path=DEFAULT_MANIFEST):
    """Verify every required local SpaPhish file against the official manifest."""
    manifest = load_manifest(manifest_path)
    checks = []

    for expected in manifest["files"]:
        file_path = Path(external_dir) / expected["filename"]
        exists = file_path.is_file()
        actual_size = file_path.stat().st_size if exists else None
        actual_hash = file_sha256(file_path) if exists else None
        checks.append(
            {
                "filename": expected["filename"],
                "exists": exists,
                "expected_bytes": expected["bytes"],
                "actual_bytes": actual_size,
                "expected_sha256": expected["sha256"],
                "actual_sha256": actual_hash,
                "matches": (
                    exists
                    and actual_size == expected["bytes"]
                    and actual_hash == expected["sha256"]
                ),
            }
        )

    if not all(check["matches"] for check in checks):
        failed = [check["filename"] for check in checks if not check["matches"]]
        raise ValueError(f"SpaPhish file verification failed: {failed}")

    return pd.DataFrame(checks)


def validate_spaphish(df, expected_rows=1395):
    """Validate the fixed SpaPhish schema, labels, and required content."""
    if list(df.columns) != EXPECTED_COLUMNS:
        raise ValueError("SpaPhish v5 columns do not match the expected 47-column schema.")
    if len(df) != expected_rows:
        raise ValueError(
            f"Expected {expected_rows:,} SpaPhish rows, found {len(df):,}."
        )
    if df["Label"].isna().any() or set(df["Label"].unique()) != {0, 1}:
        raise ValueError("SpaPhish labels must be complete binary values 0 and 1.")

    no_subject = df["subject"].fillna("").astype(str).str.strip().eq("")
    no_body = df["body"].fillna("").astype(str).str.strip().eq("")
    if (no_subject & no_body).any():
        raise ValueError("Every message must contain a subject or body.")

    return df


def load_spaphish(data_path=DEFAULT_DATASET):
    """Load SpaPhish v5 and enforce the fixed schema and target rules."""
    df = pd.read_csv(data_path, encoding="utf-8-sig", sep=",")
    return validate_spaphish(df)


def clean_visible_text(subject, body):
    """Create simple Spanish-safe visible text from subject and body."""
    subject_text = "" if pd.isna(subject) else str(subject)
    body_text = "" if pd.isna(body) else str(body)
    text = f"{subject_text}\n{body_text}"
    text = html.unescape(text)
    text = unicodedata.normalize("NFKC", text)
    text = HTML_TAG_PATTERN.sub(" ", text)
    return WHITESPACE_PATTERN.sub(" ", text).strip()


def combine_visible_text(df):
    """Combine only the two permitted prediction fields."""
    return df.apply(
        lambda row: clean_visible_text(row["subject"], row["body"]),
        axis=1,
    )


def exact_duplicate_key(subject, body):
    """Return the unmodified subject and body key used for exact checks."""
    subject_text = "" if pd.isna(subject) else str(subject)
    body_text = "" if pd.isna(body) else str(body)
    return f"{subject_text}\n{body_text}"


def normalized_duplicate_key(subject, body):
    """Return the frozen normalized key used for duplicate and campaign checks."""
    text = clean_visible_text(subject, body).lower()
    text = URL_PATTERN.sub(" <url> ", text)
    text = EMAIL_PATTERN.sub(" <email> ", text)
    text = NUMBER_PATTERN.sub(" <num> ", text)
    text = PUNCTUATION_PATTERN.sub(" ", text)
    return WHITESPACE_PATTERN.sub(" ", text).strip()


def duplicate_statistics(keys, labels):
    """Summarize repeated keys and conflicting labels."""
    key_frame = pd.DataFrame({"key": keys, "Label": labels})
    sizes = key_frame["key"].value_counts()
    duplicate_groups = sizes[sizes > 1]
    label_counts = key_frame.groupby("key")["Label"].nunique()
    conflicts = label_counts[label_counts > 1]

    return {
        "unique": int(key_frame["key"].nunique()),
        "duplicate_groups": int(len(duplicate_groups)),
        "affected_rows": int(duplicate_groups.sum()),
        "redundant_rows": int((duplicate_groups - 1).sum()),
        "maximum_group_size": int(sizes.max()),
        "conflicting_label_groups": int(len(conflicts)),
    }


def _find_group(parent, index):
    """Find the current connected-group root."""
    while parent[index] != index:
        parent[index] = parent[parent[index]]
        index = parent[index]
    return index


def _join_groups(parent, first, second):
    """Join two connected groups."""
    first_root = _find_group(parent, first)
    second_root = _find_group(parent, second)
    if first_root != second_root:
        parent[second_root] = first_root


def build_campaign_groups(df, threshold=CAMPAIGN_SIMILARITY_THRESHOLD):
    """Build conservative candidate campaign groups from normalized visible text."""
    campaign_text = df.apply(
        lambda row: normalized_duplicate_key(row["subject"], row["body"]),
        axis=1,
    )
    vectorizer = TfidfVectorizer(
        analyzer="char_wb",
        ngram_range=(3, 5),
        min_df=2,
        max_features=30000,
        sublinear_tf=True,
    )
    campaign_features = vectorizer.fit_transform(campaign_text)
    similarities = cosine_similarity(campaign_features, dense_output=True)

    parent = list(range(len(df)))
    similar_pairs = 0
    cross_label_pairs = 0

    for first in range(len(df)):
        matching = np.where(similarities[first, first + 1 :] >= threshold)[0]
        for second in matching + first + 1:
            similar_pairs += 1
            if df.iloc[first]["Label"] != df.iloc[second]["Label"]:
                cross_label_pairs += 1
            _join_groups(parent, first, int(second))

    roots = [_find_group(parent, index) for index in range(len(df))]
    root_members = {}
    for index, root in enumerate(roots):
        root_members.setdefault(root, []).append(index)

    stable_names = {}
    for root, members in root_members.items():
        smallest_hash = min(df.iloc[members]["hash"])
        stable_names[root] = f"campaign_{smallest_hash[:16]}"

    groups = pd.Series(
        [stable_names[root] for root in roots],
        index=df.index,
        name="campaign_group",
    )
    group_frame = pd.DataFrame({"campaign_group": groups, "Label": df["Label"]})
    group_summary = group_frame.groupby("campaign_group").agg(
        rows=("Label", "size"),
        labels=("Label", "nunique"),
        label=("Label", "first"),
    )
    repeated = group_summary[group_summary["rows"] > 1]

    stats = {
        "threshold": threshold,
        "all_groups": int(len(group_summary)),
        "candidate_multi_message_groups": int(len(repeated)),
        "affected_rows": int(repeated["rows"].sum()),
        "redundant_rows": int((repeated["rows"] - 1).sum()),
        "maximum_group_size": int(group_summary["rows"].max()),
        "conflicting_label_groups": int((group_summary["labels"] > 1).sum()),
        "similar_pairs": int(similar_pairs),
        "cross_label_pairs": int(cross_label_pairs),
        "legitimate_multi_message_groups": int(
            ((group_summary["label"] == 0) & (group_summary["rows"] > 1)).sum()
        ),
        "phishing_multi_message_groups": int(
            ((group_summary["label"] == 1) & (group_summary["rows"] > 1)).sum()
        ),
        "legitimate_rows_in_multi_groups": int(
            group_summary.loc[
                (group_summary["label"] == 0) & (group_summary["rows"] > 1),
                "rows",
            ].sum()
        ),
        "phishing_rows_in_multi_groups": int(
            group_summary.loc[
                (group_summary["label"] == 1) & (group_summary["rows"] > 1),
                "rows",
            ].sum()
        ),
    }
    return groups, stats


def assign_temporal_splits(df, campaign_groups):
    """Assign frozen train, validation, locked holdout, and undated partitions."""
    split_frame = pd.DataFrame(
        {
            "hash": df["hash"],
            "campaign_group": campaign_groups,
            "Label": df["Label"],
            "parsed_date": pd.to_datetime(df["date"], dayfirst=True, errors="coerce"),
        }
    )
    label_counts = split_frame.groupby("campaign_group")["Label"].nunique()
    conflicts = label_counts[label_counts > 1]
    if not conflicts.empty:
        raise ValueError(
            "Candidate campaign groups contain conflicting labels and must be quarantined."
        )

    latest_group_date = split_frame.groupby("campaign_group")["parsed_date"].max()
    holdout_groups = set(
        latest_group_date[latest_group_date.dt.year == HOLDOUT_YEAR].index
    )
    holdout_mask = split_frame["campaign_group"].isin(holdout_groups)
    dated_pre_2025_mask = (
        ~holdout_mask
        & split_frame["parsed_date"].notna()
        & (split_frame["parsed_date"].dt.year < HOLDOUT_YEAR)
    )

    development_groups = (
        split_frame.loc[dated_pre_2025_mask, ["campaign_group", "Label"]]
        .drop_duplicates("campaign_group")
        .reset_index(drop=True)
    )
    train_groups, validation_groups = train_test_split(
        development_groups["campaign_group"],
        test_size=VALIDATION_FRACTION,
        random_state=RANDOM_SEED,
        stratify=development_groups["Label"],
    )

    split_frame["split"] = "excluded_undated"
    split_frame.loc[holdout_mask, "split"] = "locked_2025_holdout"
    split_frame.loc[
        dated_pre_2025_mask
        & split_frame["campaign_group"].isin(set(train_groups)),
        "split",
    ] = "train"
    split_frame.loc[
        dated_pre_2025_mask
        & split_frame["campaign_group"].isin(set(validation_groups)),
        "split",
    ] = "validation"
    split_frame["date_year"] = split_frame["parsed_date"].dt.year.astype("Int64")

    evaluated = split_frame[split_frame["split"].isin(["train", "validation"])]
    overlap = (
        evaluated.groupby("campaign_group")["split"].nunique().gt(1).sum()
    )
    if overlap:
        raise ValueError("A campaign group crosses train and validation partitions.")
    holdout_years = split_frame.loc[
        split_frame["split"] == "locked_2025_holdout",
        "parsed_date",
    ].dt.year
    if not holdout_years.eq(HOLDOUT_YEAR).any():
        raise ValueError("The locked holdout does not contain a 2025 message.")

    return split_frame


def vectorize_train_validation(train_text, validation_text):
    """Fit word TF-IDF on training text and transform validation text."""
    vectorizer = TfidfVectorizer(
        ngram_range=(1, 2),
        min_df=2,
        max_features=15000,
        sublinear_tf=True,
    )
    train_features = vectorizer.fit_transform(train_text)
    validation_features = vectorizer.transform(validation_text)
    return vectorizer, train_features, validation_features


def _model_metrics(model_name, actual, predicted, review_scores):
    """Return one safe aggregate metrics row."""
    matrix = confusion_matrix(actual, predicted, labels=[0, 1])
    true_negative, false_positive, false_negative, true_positive = matrix.ravel()
    return {
        "model": model_name,
        "partition": "pre_2025_validation",
        "accuracy": accuracy_score(actual, predicted),
        "balanced_accuracy": balanced_accuracy_score(actual, predicted),
        "precision": precision_score(actual, predicted, zero_division=0),
        "recall": recall_score(actual, predicted, zero_division=0),
        "f1": f1_score(actual, predicted, zero_division=0),
        "roc_auc": roc_auc_score(actual, review_scores),
        "true_negative": int(true_negative),
        "false_positive": int(false_positive),
        "false_negative": int(false_negative),
        "true_positive": int(true_positive),
        "legitimate_support": int((actual == 0).sum()),
        "phishing_support": int((actual == 1).sum()),
    }


def run_development_evaluation(df, split_frame):
    """Train and evaluate only on the pre-2025 development partitions."""
    if list(PREDICTION_COLUMNS) != ["subject", "body"]:
        raise ValueError("P0 prediction columns have changed.")

    train_mask = split_frame["split"].eq("train")
    validation_mask = split_frame["split"].eq("validation")
    if split_frame.loc[train_mask | validation_mask, "split"].str.contains(
        "holdout"
    ).any():
        raise ValueError("The final holdout cannot enter development evaluation.")

    visible_text = combine_visible_text(df)
    train_text = visible_text.loc[train_mask]
    validation_text = visible_text.loc[validation_mask]
    train_labels = df.loc[train_mask, "Label"]
    validation_labels = df.loc[validation_mask, "Label"]

    vectorizer, train_features, validation_features = vectorize_train_validation(
        train_text,
        validation_text,
    )

    lr_model = LogisticRegression(
        class_weight="balanced",
        max_iter=1000,
        random_state=RANDOM_SEED,
    )
    nb_model = MultinomialNB()
    rows = []

    for model_name, model in [
        ("Logistic Regression", lr_model),
        ("Multinomial Naive Bayes", nb_model),
    ]:
        model.fit(train_features, train_labels)
        predictions = model.predict(validation_features)
        review_scores = model.predict_proba(validation_features)[:, 1]
        rows.append(
            _model_metrics(
                model_name,
                validation_labels,
                predictions,
                review_scores,
            )
        )

    metrics = pd.DataFrame(rows, columns=SAFE_METRIC_COLUMNS)
    artifacts = {
        "vectorizer": vectorizer,
        "train_hashes": set(df.loc[train_mask, "hash"]),
        "validation_hashes": set(df.loc[validation_mask, "hash"]),
        "holdout_hashes": set(
            df.loc[split_frame["split"].eq("locked_2025_holdout"), "hash"]
        ),
    }
    return metrics, artifacts


def build_dataset_audit(df, campaign_groups, campaign_stats, split_frame):
    """Build the P0 audit from the verified CSV."""
    exact_keys = df.apply(
        lambda row: exact_duplicate_key(row["subject"], row["body"]),
        axis=1,
    )
    normalized_keys = df.apply(
        lambda row: normalized_duplicate_key(row["subject"], row["body"]),
        axis=1,
    )
    exact_stats = duplicate_statistics(exact_keys, df["Label"])
    normalized_stats = duplicate_statistics(normalized_keys, df["Label"])
    parsed_dates = pd.to_datetime(df["date"], dayfirst=True, errors="coerce")
    labels = df["Label"].tolist()
    label_transitions = int(sum(first != second for first, second in zip(labels, labels[1:])))
    expected_order = [1] * int((df["Label"] == 1).sum()) + [0] * int(
        (df["Label"] == 0).sum()
    )
    html_rows = df["body"].fillna("").str.contains(HTML_TAG_NAME_PATTERN)

    audit = {
        "dataset.rows": len(df),
        "dataset.columns": len(df.columns),
        "labels.legitimate": int((df["Label"] == 0).sum()),
        "labels.phishing": int((df["Label"] == 1).sum()),
        "missing.subject": int(df["subject"].isna().sum()),
        "missing.body": int(df["body"].isna().sum()),
        "missing.date": int(df["date"].isna().sum()),
        "missing.subject.legitimate": int(
            (df["subject"].isna() & df["Label"].eq(0)).sum()
        ),
        "missing.subject.phishing": int(
            (df["subject"].isna() & df["Label"].eq(1)).sum()
        ),
        "missing.date.legitimate": int(
            (df["date"].isna() & df["Label"].eq(0)).sum()
        ),
        "missing.date.phishing": int(
            (df["date"].isna() & df["Label"].eq(1)).sum()
        ),
        "date.legitimate.minimum": parsed_dates[df["Label"].eq(0)]
        .min()
        .date()
        .isoformat(),
        "date.legitimate.maximum": parsed_dates[df["Label"].eq(0)]
        .max()
        .date()
        .isoformat(),
        "date.phishing.minimum": parsed_dates[df["Label"].eq(1)]
        .min()
        .date()
        .isoformat(),
        "date.phishing.maximum": parsed_dates[df["Label"].eq(1)]
        .max()
        .date()
        .isoformat(),
        "file_order.label_transitions": label_transitions,
        "file_order.perfect_label_block": labels == expected_order,
        "annotations.available_columns": len(ANNOTATION_COLUMNS),
        "annotations.prediction_columns_used": 0,
        "annotations.legitimate_rows_with_missing_values": int(
            df.loc[df["Label"].eq(0), ANNOTATION_COLUMNS].isna().any(axis=1).sum()
        ),
        "annotations.phishing_rows_with_missing_values": int(
            df.loc[df["Label"].eq(1), ANNOTATION_COLUMNS].isna().any(axis=1).sum()
        ),
        "html.legitimate_rows": int((html_rows & df["Label"].eq(0)).sum()),
        "html.phishing_rows": int((html_rows & df["Label"].eq(1)).sum()),
    }
    for name, stats in [
        ("duplicates.exact", exact_stats),
        ("duplicates.normalized", normalized_stats),
        ("campaign", campaign_stats),
    ]:
        for key, value in stats.items():
            audit[f"{name}.{key}"] = value

    partition_counts = pd.crosstab(split_frame["split"], split_frame["Label"])
    for split_name in [
        "train",
        "validation",
        "locked_2025_holdout",
        "excluded_undated",
    ]:
        for label, label_name in [(0, "legitimate"), (1, "phishing")]:
            value = (
                int(partition_counts.loc[split_name, label])
                if split_name in partition_counts.index
                and label in partition_counts.columns
                else 0
            )
            audit[f"split.{split_name}.{label_name}"] = value

    return pd.DataFrame(
        [{"check": key, "value": value} for key, value in audit.items()]
    )


def write_p0_results(audit, split_frame, metrics, results_dir=DEFAULT_RESULTS):
    """Write only aggregate or identifier-only P0 evidence."""
    results_path = Path(results_dir)
    results_path.mkdir(parents=True, exist_ok=True)

    safe_split = split_frame[SAFE_SPLIT_COLUMNS].copy()
    if list(safe_split.columns) != SAFE_SPLIT_COLUMNS:
        raise ValueError("Unsafe split output columns were requested.")
    if list(metrics.columns) != SAFE_METRIC_COLUMNS:
        raise ValueError("Unsafe development metric columns were requested.")

    audit.to_csv(results_path / "dataset_audit.csv", index=False)
    safe_split.to_csv(results_path / "split_manifest.csv", index=False)
    metrics.to_csv(results_path / "development_metrics.csv", index=False)


def run_p0(data_path=DEFAULT_DATASET, manifest_path=DEFAULT_MANIFEST, results_dir=DEFAULT_RESULTS):
    """Run the complete P0 audit and development evaluation."""
    external_dir = Path(data_path).parent
    file_checks = verify_external_files(external_dir, manifest_path)
    df = load_spaphish(data_path)
    campaign_groups, campaign_stats = build_campaign_groups(df)
    split_frame = assign_temporal_splits(df, campaign_groups)
    metrics, artifacts = run_development_evaluation(df, split_frame)
    audit = build_dataset_audit(df, campaign_groups, campaign_stats, split_frame)
    write_p0_results(audit, split_frame, metrics, results_dir)
    return file_checks, audit, split_frame, metrics, artifacts


def main():
    parser = argparse.ArgumentParser(
        description="Run SpaPhish v5 P0 validation without scoring the final holdout."
    )
    parser.add_argument("--data", type=Path, default=DEFAULT_DATASET)
    parser.add_argument("--manifest", type=Path, default=DEFAULT_MANIFEST)
    parser.add_argument("--results-dir", type=Path, default=DEFAULT_RESULTS)
    parser.add_argument(
        "--score-final-holdout",
        action="store_true",
        help="Reserved for P1. P0 refuses this action.",
    )
    args = parser.parse_args()

    if args.score_final_holdout and FINAL_HOLDOUT_LOCKED:
        raise SystemExit(
            "The 2025 holdout is locked during P0. P1 approval is required."
        )

    file_checks, audit, split_frame, metrics, _ = run_p0(
        args.data,
        args.manifest,
        args.results_dir,
    )

    print("=======================")
    print("SpaPhish P0 Validation")
    print("=======================")
    print("Verified files:", int(file_checks["matches"].sum()))
    print("Audit checks:", len(audit))
    print("\nDevelopment partitions:")
    print(pd.crosstab(split_frame["split"], split_frame["Label"]))
    print("\nDevelopment metrics:")
    print(metrics.round(4).to_string(index=False))
    print("\nThe 2025 holdout was not scored.")


if __name__ == "__main__":
    main()
