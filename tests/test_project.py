import json
import re
import tempfile
import unittest
from pathlib import Path

import pandas as pd

from phishing_validation import (
    ANNOTATION_COLUMNS,
    CAMPAIGN_SIMILARITY_THRESHOLD,
    DEFAULT_DATASET,
    DEFAULT_MANIFEST,
    EXPECTED_COLUMNS,
    FINAL_HOLDOUT_LOCKED,
    PREDICTION_COLUMNS,
    SAFE_METRIC_COLUMNS,
    SAFE_TRIAGE_COLUMNS,
    SAFE_SPLIT_COLUMNS,
    assign_temporal_splits,
    build_campaign_groups,
    clean_visible_text,
    duplicate_statistics,
    load_manifest,
    load_split_manifest,
    load_spaphish,
    normalized_duplicate_key,
    build_sanitized_validation_triage,
    fit_primary_validation_model,
    load_development_rows,
    run_final_evaluation,
    run_development_evaluation,
    run_validation_triage,
    validate_spaphish,
    vectorize_train_validation,
    verify_external_files,
    write_p0_results,
)


ROOT = Path(__file__).resolve().parents[1]
NOTEBOOK = ROOT / "phishing_email_detection.ipynb"


def make_test_frame(rows):
    data = []
    for index, values in enumerate(rows):
        row = {column: 0 for column in EXPECTED_COLUMNS}
        row.update(
            {
                "hash": f"{index + 1:064x}",
                "subject": values["subject"],
                "body": values["body"],
                "date": values["date"],
                "urls": None,
                "attachments_types": None,
                "attachments_sizes": None,
                "Label": values["Label"],
            }
        )
        for column in ANNOTATION_COLUMNS:
            row[column] = (
                "justificación de prueba" if column.startswith("justif_") else 0
            )
        data.append(row)
    return pd.DataFrame(data, columns=EXPECTED_COLUMNS)


class ProjectValidationTests(unittest.TestCase):
    def test_notebook_code_cells_compile(self):
        with NOTEBOOK.open(encoding="utf-8") as handle:
            notebook = json.load(handle)

        compiled = 0
        for index, cell in enumerate(notebook.get("cells", []), start=1):
            if cell.get("cell_type") != "code":
                continue

            source = "".join(cell.get("source", []))
            if source.strip():
                compile(source, f"{NOTEBOOK.name}:cell-{index}", "exec")
                compiled += 1

        self.assertGreater(compiled, 0)

    def test_manifest_values_and_hash_format(self):
        manifest = load_manifest(DEFAULT_MANIFEST)

        self.assertEqual(manifest["version"], 5)
        self.assertEqual(manifest["doi"], "10.17632/hz2d6gz7pc.5")
        self.assertEqual(manifest["license"], "CC BY 4.0")
        self.assertEqual(manifest["csv"]["rows"], 1395)
        self.assertEqual(manifest["csv"]["columns"], 47)
        self.assertEqual(
            manifest["frozen_evaluation_rules"]["campaign_similarity_threshold"],
            CAMPAIGN_SIMILARITY_THRESHOLD,
        )
        self.assertEqual(
            manifest["frozen_evaluation_rules"]["prediction_fields"],
            ["subject", "body"],
        )
        self.assertEqual(
            manifest["frozen_evaluation_rules"]["word_tfidf_max_features"],
            15000,
        )
        self.assertEqual(
            manifest["frozen_evaluation_rules"]["decision_threshold"],
            0.5,
        )

        for item in manifest["files"]:
            self.assertRegex(item["sha256"], r"^[0-9a-f]{64}$")

    def test_expected_schema_and_valid_content(self):
        rows = [
            {
                "subject": "Aviso legítimo",
                "body": "Contenido válido",
                "date": "01/01/2024",
                "Label": 0,
            },
            {
                "subject": None,
                "body": "Verifique su cuenta",
                "date": "02/01/2024",
                "Label": 1,
            },
        ]
        df = make_test_frame(rows)

        validated = validate_spaphish(df, expected_rows=2)

        self.assertEqual(list(validated.columns), EXPECTED_COLUMNS)
        self.assertEqual(set(validated["Label"]), {0, 1})
        self.assertFalse(
            (
                validated["subject"].fillna("").str.strip().eq("")
                & validated["body"].fillna("").str.strip().eq("")
            ).any()
        )

    def test_invalid_label_and_empty_message_are_rejected(self):
        invalid_label = make_test_frame(
            [
                {
                    "subject": "Mensaje legítimo",
                    "body": "Contenido",
                    "date": "01/01/2024",
                    "Label": 0,
                },
                {
                    "subject": "Mensaje desconocido",
                    "body": "Contenido",
                    "date": "02/01/2024",
                    "Label": 2,
                },
            ]
        )
        with self.assertRaises(ValueError):
            validate_spaphish(invalid_label, expected_rows=2)

        empty_message = make_test_frame(
            [
                {
                    "subject": None,
                    "body": "   ",
                    "date": "01/01/2024",
                    "Label": 0,
                },
                {
                    "subject": "Mensaje de prueba",
                    "body": "Contenido",
                    "date": "02/01/2024",
                    "Label": 1,
                },
            ]
        )
        with self.assertRaises(ValueError):
            validate_spaphish(empty_message, expected_rows=2)

    def test_spanish_cleanup_preserves_accents_and_removes_html(self):
        cleaned = clean_visible_text(
            "Actualización académica",
            "<p>Información válida para mañana.</p>",
        )

        self.assertIn("Actualización", cleaned)
        self.assertIn("Información", cleaned)
        self.assertIn("mañana", cleaned)
        self.assertNotIn("<p>", cleaned)
        self.assertNotIn("</p>", cleaned)

    def test_normalized_duplicate_key_is_deterministic(self):
        first = normalized_duplicate_key(
            "Aviso número 123",
            "Visite https://example.test/uno",
        )
        second = normalized_duplicate_key(
            "AVISO NÚMERO 456",
            "Visite https://example.test/dos",
        )

        self.assertEqual(first, second)

    def test_duplicate_statistics_detect_conflicting_labels(self):
        stats = duplicate_statistics(
            pd.Series(["same", "same", "different"]),
            pd.Series([0, 1, 0]),
        )

        self.assertEqual(stats["duplicate_groups"], 1)
        self.assertEqual(stats["redundant_rows"], 1)
        self.assertEqual(stats["conflicting_label_groups"], 1)

    def test_campaign_grouping_is_deterministic(self):
        df = make_test_frame(
            [
                {
                    "subject": "Paquete pendiente",
                    "body": "Revise su paquete ahora",
                    "date": "01/01/2024",
                    "Label": 1,
                },
                {
                    "subject": "Paquete pendiente",
                    "body": "Revise su paquete ahora",
                    "date": "02/01/2024",
                    "Label": 1,
                },
                {
                    "subject": "Reunión académica",
                    "body": "La reunión será mañana",
                    "date": "03/01/2024",
                    "Label": 0,
                },
                {
                    "subject": "Reunión académica",
                    "body": "La reunión será mañana",
                    "date": "04/01/2024",
                    "Label": 0,
                },
            ]
        )

        first_groups, first_stats = build_campaign_groups(df)
        second_groups, second_stats = build_campaign_groups(df)

        self.assertEqual(first_groups.tolist(), second_groups.tolist())
        self.assertEqual(first_stats, second_stats)
        self.assertEqual(first_groups.iloc[0], first_groups.iloc[1])
        self.assertEqual(first_groups.iloc[2], first_groups.iloc[3])

    def test_conflicting_campaign_group_stops_split(self):
        df = make_test_frame(
            [
                {
                    "subject": "Uno",
                    "body": "Mensaje uno",
                    "date": "01/01/2024",
                    "Label": 0,
                },
                {
                    "subject": "Dos",
                    "body": "Mensaje dos",
                    "date": "02/01/2024",
                    "Label": 1,
                },
            ]
        )

        with self.assertRaises(ValueError):
            assign_temporal_splits(df, pd.Series(["same_group", "same_group"]))

    def test_temporal_split_has_no_group_overlap(self):
        rows = []
        groups = []
        for label in [0, 1]:
            for group_number in range(6):
                year = 2025 if group_number == 5 else 2024
                rows.append(
                    {
                        "subject": f"Mensaje {label} {group_number}",
                        "body": "Contenido de prueba",
                        "date": f"01/01/{year}",
                        "Label": label,
                    }
                )
                groups.append(f"group_{label}_{group_number}")

        df = make_test_frame(rows)
        split_frame = assign_temporal_splits(df, pd.Series(groups))

        development = split_frame[
            split_frame["split"].isin(["train", "validation"])
        ]
        overlap = development.groupby("campaign_group")["split"].nunique()

        self.assertTrue((overlap == 1).all())
        self.assertEqual(
            set(
                split_frame.loc[
                    split_frame["split"] == "locked_2025_holdout",
                    "date_year",
                ]
            ),
            {2025},
        )
        self.assertTrue(FINAL_HOLDOUT_LOCKED)

    def test_mixed_undated_campaign_group_is_completely_excluded(self):
        df = make_test_frame(
            [
                {
                    "subject": "Campaña relacionada",
                    "body": "Mensaje fechado",
                    "date": "01/01/2024",
                    "Label": 1,
                },
                {
                    "subject": "Campaña relacionada",
                    "body": "Mensaje sin fecha",
                    "date": None,
                    "Label": 1,
                },
                {
                    "subject": "Legítimo uno",
                    "body": "Contenido uno",
                    "date": "02/01/2024",
                    "Label": 0,
                },
                {
                    "subject": "Legítimo dos",
                    "body": "Contenido dos",
                    "date": "03/01/2024",
                    "Label": 0,
                },
                {
                    "subject": "Phishing uno",
                    "body": "Contenido uno",
                    "date": "04/01/2024",
                    "Label": 1,
                },
                {
                    "subject": "Phishing dos",
                    "body": "Contenido dos",
                    "date": "05/01/2024",
                    "Label": 1,
                },
                {
                    "subject": "Legítimo tres",
                    "body": "Contenido tres",
                    "date": "06/01/2024",
                    "Label": 0,
                },
                {
                    "subject": "Legítimo cuatro",
                    "body": "Contenido cuatro",
                    "date": "07/01/2024",
                    "Label": 0,
                },
                {
                    "subject": "Phishing tres",
                    "body": "Contenido tres",
                    "date": "08/01/2024",
                    "Label": 1,
                },
                {
                    "subject": "Phishing cuatro",
                    "body": "Contenido cuatro",
                    "date": "09/01/2024",
                    "Label": 1,
                },
                {
                    "subject": "Phishing final",
                    "body": "Contenido final",
                    "date": "01/01/2025",
                    "Label": 1,
                },
            ]
        )
        groups = pd.Series(
            [
                "mixed", "mixed", "legit_1", "legit_2", "phish_1", "phish_2",
                "legit_3", "legit_4", "phish_3", "phish_4", "holdout",
            ]
        )

        split_frame = assign_temporal_splits(df, groups)

        self.assertEqual(
            set(split_frame.loc[split_frame["campaign_group"] == "mixed", "split"]),
            {"excluded_undated"},
        )
        self.assertTrue(
            split_frame.groupby("campaign_group")["split"].nunique().eq(1).all()
        )

    def test_vectorizer_is_fitted_only_on_training_text(self):
        vectorizer, _, _ = vectorize_train_validation(
            pd.Series(["correo seguro común", "correo seguro común"]),
            pd.Series(["tokenunicosolovalidacion"]),
        )

        self.assertNotIn(
            "tokenunicosolovalidacion",
            vectorizer.vocabulary_,
        )

    def test_2025_holdout_is_excluded_from_model_fitting(self):
        df = make_test_frame(
            [
                {
                    "subject": "Correo común legítimo",
                    "body": "contenido legítimo compartido",
                    "date": "01/01/2024",
                    "Label": 0,
                },
                {
                    "subject": "Aviso común phishing",
                    "body": "contenido phishing compartido",
                    "date": "02/01/2024",
                    "Label": 1,
                },
                {
                    "subject": "Correo común legítimo",
                    "body": "contenido legítimo compartido",
                    "date": "03/01/2024",
                    "Label": 0,
                },
                {
                    "subject": "Aviso común phishing",
                    "body": "contenido phishing compartido",
                    "date": "04/01/2024",
                    "Label": 1,
                },
                {
                    "subject": "Validación legítima",
                    "body": "contenido legítimo",
                    "date": "05/01/2024",
                    "Label": 0,
                },
                {
                    "subject": "Validación phishing",
                    "body": "contenido phishing",
                    "date": "06/01/2024",
                    "Label": 1,
                },
                {
                    "subject": "tokenunicosoloholdout",
                    "body": "mensaje legítimo de 2025",
                    "date": "01/01/2025",
                    "Label": 0,
                },
                {
                    "subject": "tokenunicosoloholdout",
                    "body": "mensaje phishing de 2025",
                    "date": "02/01/2025",
                    "Label": 1,
                },
            ]
        )
        split_frame = pd.DataFrame(
            {
                "split": [
                    "train",
                    "train",
                    "train",
                    "train",
                    "validation",
                    "validation",
                    "locked_2025_holdout",
                    "locked_2025_holdout",
                ]
            }
        )

        _, artifacts = run_development_evaluation(df, split_frame)

        development_hashes = (
            artifacts["train_hashes"] | artifacts["validation_hashes"]
        )
        self.assertTrue(
            development_hashes.isdisjoint(artifacts["holdout_hashes"])
        )
        self.assertNotIn(
            "tokenunicosoloholdout",
            artifacts["vectorizer"].vocabulary_,
        )

    def test_p1a_loader_returns_only_development_rows(self):
        split = pd.DataFrame(
            [
                {
                    "hash": "train_hash",
                    "campaign_group": "train_group",
                    "Label": 0,
                    "date_year": 2024,
                    "split": "train",
                },
                {
                    "hash": "validation_hash",
                    "campaign_group": "validation_group",
                    "Label": 1,
                    "date_year": 2024,
                    "split": "validation",
                },
                {
                    "hash": "holdout_hash",
                    "campaign_group": "holdout_group",
                    "Label": 1,
                    "date_year": 2025,
                    "split": "locked_2025_holdout",
                },
            ]
        )
        raw = pd.DataFrame(
            [
                {
                    "hash": "train_hash",
                    "subject": "Mensaje de entrenamiento",
                    "body": "Contenido de entrenamiento",
                    "Label": 0,
                },
                {
                    "hash": "validation_hash",
                    "subject": "Mensaje de validación",
                    "body": "Contenido de validación",
                    "Label": 1,
                },
                {
                    "hash": "holdout_hash",
                    "subject": "holdout secret",
                    "body": "This text must not enter P1A.",
                    "Label": 1,
                },
            ]
        )

        with tempfile.TemporaryDirectory() as temp_dir:
            temp_path = Path(temp_dir)
            split_path = temp_path / "split_manifest.csv"
            data_path = temp_path / "emails.csv"
            split.to_csv(split_path, index=False)
            raw.to_csv(data_path, index=False)
            development_rows = load_development_rows(data_path, split_path)

        self.assertEqual(set(development_rows["split"]), {"train", "validation"})
        self.assertNotIn("holdout_hash", set(development_rows["hash"]))
        self.assertNotIn("holdout secret", " ".join(development_rows["subject"]))

    def test_p1a_primary_model_refuses_non_development_split(self):
        rows = make_test_frame(
            [
                {
                    "subject": "Texto bloqueado",
                    "body": "No debe entrar al modelo.",
                    "date": "01/01/2025",
                    "Label": 1,
                }
            ]
        )[["hash", "subject", "body", "Label"]]
        rows["split"] = "locked_2025_holdout"

        with self.assertRaises(ValueError):
            fit_primary_validation_model(rows)

    def test_sanitized_triage_has_no_raw_message_columns(self):
        validation_cases = pd.DataFrame(
            [
                {
                    "hash": f"{index:064x}",
                    "Label": 0 if index < 2 else 1,
                    "predicted_label": 1 if index < 2 else 0,
                    "model_review_score": index / 10,
                }
                for index in range(8)
            ]
        )

        triage = build_sanitized_validation_triage(validation_cases)

        self.assertEqual(list(triage.columns), SAFE_TRIAGE_COLUMNS)
        self.assertEqual(len(triage), 8)
        self.assertTrue(
            {"hash", "subject", "body", "urls"}.isdisjoint(triage.columns)
        )
        text = triage.astype(str).to_csv(index=False)
        self.assertNotRegex(text, r"https?://|www\.|[A-Za-z0-9._%+-]+@")

    def test_prediction_columns_exclude_metadata_and_annotations(self):
        self.assertEqual(PREDICTION_COLUMNS, ["subject", "body"])
        forbidden = {
            "date",
            "hash",
            "Label",
            "campaign_group",
            "split",
            "row_index",
        }

        self.assertTrue(forbidden.isdisjoint(PREDICTION_COLUMNS))
        self.assertTrue(set(ANNOTATION_COLUMNS).isdisjoint(PREDICTION_COLUMNS))

    def test_final_model_fits_only_development_text(self):
        rows = make_test_frame(
            [
                {"subject": "Aviso legítimo", "body": "mensaje seguro común", "date": "01/01/2024", "Label": 0},
                {"subject": "Aviso legítimo", "body": "mensaje seguro común", "date": "02/01/2024", "Label": 0},
                {"subject": "Aviso phishing", "body": "verifique cuenta urgente", "date": "03/01/2024", "Label": 1},
                {"subject": "Aviso phishing", "body": "verifique cuenta urgente", "date": "04/01/2024", "Label": 1},
                {"subject": "Validación legítima", "body": "mensaje seguro común", "date": "05/01/2024", "Label": 0},
                {"subject": "Validación phishing", "body": "verifique cuenta urgente", "date": "06/01/2024", "Label": 1},
                {"subject": "tokenunicosoloholdout", "body": "mensaje seguro", "date": "01/01/2025", "Label": 0},
                {"subject": "tokenunicosoloholdout", "body": "cuenta urgente", "date": "02/01/2025", "Label": 1},
            ]
        )[["hash", "subject", "body", "Label"]]
        rows["split"] = [
            "train", "train", "train", "train", "validation", "validation",
            "locked_2025_holdout", "locked_2025_holdout",
        ]

        metrics, predictions, _, _, artifacts = run_final_evaluation(rows)

        self.assertEqual(metrics.loc[0, "partition"], "locked_2025_holdout")
        self.assertEqual(len(predictions), 2)
        self.assertTrue(artifacts["development_hashes"].isdisjoint(artifacts["holdout_hashes"]))
        self.assertNotIn("tokenunicosoloholdout", artifacts["vectorizer"].vocabulary_)

    def test_safe_output_schemas(self):
        audit = pd.DataFrame([{"check": "dataset.rows", "value": 2}])
        split = pd.DataFrame(
            [
                {
                    "hash": "1" * 64,
                    "campaign_group": "campaign_test",
                    "Label": 0,
                    "date_year": 2024,
                    "split": "train",
                }
            ]
        )
        metrics = pd.DataFrame(
            [
                {
                    "model": "Logistic Regression",
                    "partition": "pre_2025_validation",
                    "accuracy": 1.0,
                    "balanced_accuracy": 1.0,
                    "precision": 1.0,
                    "recall": 1.0,
                    "f1": 1.0,
                    "roc_auc": 1.0,
                    "true_negative": 1,
                    "false_positive": 0,
                    "false_negative": 0,
                    "true_positive": 1,
                    "legitimate_support": 1,
                    "phishing_support": 1,
                }
            ],
            columns=SAFE_METRIC_COLUMNS,
        )

        with tempfile.TemporaryDirectory() as temp_dir:
            write_p0_results(audit, split, metrics, temp_dir)
            saved_split = pd.read_csv(Path(temp_dir) / "split_manifest.csv")
            saved_metrics = pd.read_csv(
                Path(temp_dir) / "development_metrics.csv"
            )

        self.assertEqual(list(saved_split.columns), SAFE_SPLIT_COLUMNS)
        self.assertEqual(list(saved_metrics.columns), SAFE_METRIC_COLUMNS)
        self.assertTrue(
            {"subject", "body", "urls", "model_review_score"}.isdisjoint(
                saved_split.columns
            )
        )

    @unittest.skipUnless(DEFAULT_DATASET.exists(), "SpaPhish external data not available")
    def test_local_spaphish_copy_and_audit_inputs(self):
        checks = verify_external_files(DEFAULT_DATASET.parent, DEFAULT_MANIFEST)
        df = load_spaphish(DEFAULT_DATASET)

        self.assertTrue(checks["matches"].all())
        self.assertEqual(df.shape, (1395, 47))
        self.assertEqual(df["Label"].value_counts().to_dict(), {1: 731, 0: 664})
        self.assertEqual(int(df["subject"].isna().sum()), 3)
        self.assertEqual(int(df["body"].isna().sum()), 0)
        self.assertEqual(int(df["date"].isna().sum()), 24)

    @unittest.skipUnless(DEFAULT_DATASET.exists(), "SpaPhish external data not available")
    def test_p1a_triage_is_development_only_and_sanitized(self):
        with tempfile.TemporaryDirectory() as temp_dir:
            _, metrics, triage, summary, confusion, artifacts = run_validation_triage(
                results_dir=temp_dir
            )

        holdout_hashes = set(
            pd.read_csv(ROOT / "results" / "split_manifest.csv")
            .query("split == 'locked_2025_holdout'")["hash"]
        )
        self.assertEqual(len(triage), 8)
        self.assertEqual(int(summary["error_count"].sum()), 8)
        self.assertEqual(int(confusion["count"].sum()), 170)
        self.assertTrue(artifacts["train_hashes"].isdisjoint(holdout_hashes))
        self.assertTrue(artifacts["validation_hashes"].isdisjoint(holdout_hashes))
        self.assertEqual(metrics.loc[0, "false_negative"], 6)

    def test_frozen_split_manifest_keeps_each_group_in_one_partition(self):
        split_frame = load_split_manifest(ROOT / "results" / "split_manifest.csv")

        self.assertTrue(
            split_frame.groupby("campaign_group")["split"].nunique().eq(1).all()
        )

    def test_manifest_contains_no_invalid_hashes(self):
        text = DEFAULT_MANIFEST.read_text(encoding="utf-8")
        hashes = re.findall(r'"sha256":\s*"([^"]+)"', text)

        self.assertGreater(len(hashes), 0)
        self.assertTrue(all(re.fullmatch(r"[0-9a-f]{64}", value) for value in hashes))


if __name__ == "__main__":
    unittest.main()
