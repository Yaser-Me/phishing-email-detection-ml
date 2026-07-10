# Phishing Email Detection with Machine Learning

A notebook-based machine learning project that classifies email text as either **Safe Email** or **Phishing Email**.

## Workflow

1. Load and inspect the labeled email dataset.
2. Clean and normalize email text with NLTK.
3. Convert text into numeric features with `CountVectorizer`.
4. Split the data into 75% training and 25% testing sets.
5. Train and compare four classifiers:
   - Logistic Regression
   - Multinomial Naive Bayes
   - Decision Tree
   - Support Vector Machine
6. Evaluate accuracy, precision, recall, F1 score, confusion matrices, and ROC curves.
7. Explore common words with visualizations.

## Dataset

The project uses the **Phishing Validation Emails Dataset** by Radoslav Miltchev, Dimitar Rangelov, and Evgeni Genchev.

- 2,000 labeled emails
- Safe Email and Phishing Email classes
- Combination of real-world and artificially generated samples
- License: CC BY 4.0
- DOI: [10.5281/zenodo.13474746](https://doi.org/10.5281/zenodo.13474746)

A copy used by the notebook is stored in `data/phishing_validation_emails.csv`.

## Recorded notebook results

The saved notebook output reports 1.00 accuracy, precision, recall, and F1 score for all four models on the 500-row test split.

These are dataset-specific academic results, not evidence of real-world deployment performance. The perfect scores may reflect the dataset's clean labels, generated samples, repeated patterns, or limited diversity. A production study should use an independent external dataset, inspect data leakage, tune models with cross-validation, and test adversarial or newly collected phishing emails.

## Repository contents

| File | Purpose |
|---|---|
| `phishing_email_detection.ipynb` | Data preparation, training, evaluation, and plots |
| `data/phishing_validation_emails.csv` | Dataset copy used by the project |
| `phishing_email_detection_report.pdf` | Written project report |
| `phishing_email_detection_presentation.pptx` | Presentation slides |
| `requirements.txt` | Python dependencies |

## Run locally

Create a virtual environment and install the dependencies:

```bash
python -m venv .venv
```

PowerShell:

```powershell
.\.venv\Scripts\Activate.ps1
pip install -r requirements.txt
jupyter notebook phishing_email_detection.ipynb
```

Bash:

```bash
source .venv/bin/activate
pip install -r requirements.txt
jupyter notebook phishing_email_detection.ipynb
```

The notebook can also be opened in Google Colab.
