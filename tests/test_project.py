import json
import unittest
from pathlib import Path

import pandas as pd
from sklearn.feature_extraction.text import CountVectorizer
from sklearn.linear_model import LogisticRegression
from sklearn.model_selection import train_test_split


ROOT = Path(__file__).resolve().parents[1]
NOTEBOOK = ROOT / "phishing_email_detection.ipynb"
DATASET = ROOT / "data" / "phishing_validation_emails.csv"


class ProjectValidationTests(unittest.TestCase):
    def test_notebook_code_cells_compile(self):
        with NOTEBOOK.open(encoding="utf-8") as handle:
            notebook = json.load(handle)

        compiled = 0
        for index, cell in enumerate(notebook.get("cells", []), start=1):
            if cell.get("cell_type") != "code":
                continue

            lines = [
                line
                for line in cell.get("source", [])
                if not line.lstrip().startswith(("!", "%"))
            ]
            source = "".join(lines)
            if source.strip():
                compile(source, f"{NOTEBOOK.name}:cell-{index}", "exec")
                compiled += 1

        self.assertGreater(compiled, 0)

    def test_dataset_schema_and_labels(self):
        data = pd.read_csv(DATASET)

        self.assertEqual(list(data.columns), ["Email Text", "Email Type"])
        self.assertEqual(len(data), 2000)
        self.assertEqual(
            set(data["Email Type"].dropna().unique()),
            {"Safe Email", "Phishing Email"},
        )

    def test_core_classifier_pipeline(self):
        data = pd.read_csv(DATASET).dropna(subset=["Email Text", "Email Type"])
        train_text, test_text, train_labels, test_labels = train_test_split(
            data["Email Text"],
            data["Email Type"],
            test_size=0.25,
            random_state=42,
            stratify=data["Email Type"],
        )

        vectorizer = CountVectorizer(max_features=5000)
        train_features = vectorizer.fit_transform(train_text)
        test_features = vectorizer.transform(test_text)

        model = LogisticRegression(max_iter=1000)
        model.fit(train_features, train_labels)
        predictions = model.predict(test_features)

        self.assertEqual(len(predictions), len(test_labels))
        self.assertTrue(set(predictions).issubset(set(train_labels)))


if __name__ == "__main__":
    unittest.main()

