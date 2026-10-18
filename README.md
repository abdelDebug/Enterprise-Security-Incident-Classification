# Enterprise Security Incident Classification

A postgraduate-level machine learning classification dataset and practical assessment focused on identifying which enterprise security alerts warrant investigation as **confirmed security incidents**.

## Objective

Predict `confirmed_incident` at the time an alert is created using information already available to the security operations center (SOC). This is a **binary classification** problem:

- **0:** Alert not confirmed as an incident.
- **1:** Confirmed security incident.

The dataset was **generated for educational use** and is not a collection of observed incidents from a real organization. It is intended for reproducible teaching experiments, not for operational security decisions or claims about real-world incident prevalence.

## Dataset summary

| Property | Value |
| --- | --- |
| File | `Enterprise_Security_Alerts_Classification.csv` |
| Records | **52,000** |
| Columns | **37**, including the target |
| Time coverage | January 1, 2024 to December 31, 2025 |
| Target | `confirmed_incident` |
| Negative class (`0`) | 49,050 alerts (**94.33%**) |
| Positive class (`1`) | 2,950 alerts (**5.67%**) |
| File format | UTF-8 CSV |
| Task type | Imbalanced binary classification |

The table combines alert metadata, account and asset context, network activity indicators, security scores, timestamps, and investigation outcome attributes. Some columns have missing values, and some become available **only after** the alert is investigated. This is intentional for teaching feature-availability checks, leakage prevention, and practical ML evaluation.

## Files

| Filename | Description |
| --- | --- |
| `Enterprise_Security_Alerts_Classification.csv` | Full 52,000-row classification dataset |
| `Enterprise_Security_Alerts_Data_Dictionary.md` | Definitions and prediction-time availability for all 37 columns |
| `Enterprise_Security_Incident_Classification_Assignment.docx` | Optional MSc practical assessment brief, if included in the repository |

## ML tasks

Students are expected to:

1. Investigate class imbalance, missingness, outliers, and time-dependent patterns.
2. Audit feature availability and explicitly remove target-related or post-investigation variables.
3. Implement leakage-safe preprocessing with training-fitted imputation, encoding, and scaling as appropriate.
4. Train and compare classification models against a `DummyClassifier` baseline.
5. Evaluate imbalance-aware learning with class weights and/or sampling **within training folds only**.
6. Tune models and, if appropriate, a classification threshold using validation data.
7. Evaluate the untouched final test period, interpret the model, and discuss operational trade-offs.

## Important: prevent data leakage

The following columns are **not legitimate input features** when predicting at alert creation time:

- `case_disposition`: analyst investigation outcome.
- `remediation_action`: action taken during or after the investigation.
- `forensic_score_after_review`: forensic assessment created after review.
- `case_closed_at`: case closure timestamp.
- `confirmed_incident`: the ground-truth outcome/label.

`alert_id`, `host_id`, `identity_id`, and `tenant_id` also require careful treatment. In particular, high-cardinality IDs may encourage memorization rather than generalizable patterns. Retain identifiers for grouping, auditing, or error investigation when justified, rather than blindly treating them as predictors.

**Never compute preprocessing statistics, perform feature selection, resample records, or choose model thresholds using the final test set.**

## Recommended chronological evaluation

Use **chronological splitting** to approximate deployment to future alerts:

| Split | Dates | Records | Confirmed incidents | Positive rate |
| --- | --- | ---: | ---: | ---: |
| Training | Jan–Dec 2024 | 25,978 | 1,454 | 5.60% |
| Validation | Jan–Jun 2025 | 13,028 | 726 | 5.57% |
| Final test | Jul–Dec 2025 | 12,994 | 770 | 5.93% |

To maintain a fair experiment:

- Fit encoders, imputers, scalers, and model selection steps **only** on the appropriate training partition.
- Use `Pipeline` and `ColumnTransformer`; fit any resampler solely inside training folds, not on validation or test rows.
- Select models, hyperparameters, and thresholds without consulting the final test labels.
- Monitor drift and repeated entities across partitions. A chronological split alone does not eliminate correlation among repeated hosts, identities, or organizations.

## Suggested metrics

Because just 5.67% of alerts are positive, a classifier that always predicts class `0` can achieve 94.33% accuracy **on the entire dataset** while finding no incidents. Report accuracy only as a secondary diagnostic.

Prioritize:

- **Average precision (PR-AUC)** and precision–recall curves.
- **Recall, precision, and F1** for class `1`.
- **Confusion matrix** and false-negative versus false-positive trade-offs.
- **Balanced accuracy**; optionally ROC-AUC and probability calibration.

Compare with `DummyClassifier(strategy="most_frequent")`. Tune classification thresholds on the validation set only and justify them in the context of an analyst workload.

## Quick start

```python
import pandas as pd

file_path = "Enterprise_Security_Alerts_Classification.csv"
df = pd.read_csv(file_path, parse_dates=["alert_created_at"])

print("Shape:", df.shape)
print("Class distribution:")
print(df["confirmed_incident"].value_counts(normalize=True))

train = df[df["alert_created_at"] < "2025-01-01"].copy()
validation = df[
    (df["alert_created_at"] >= "2025-01-01") &
    (df["alert_created_at"] < "2025-07-01")
].copy()
test = df[df["alert_created_at"] >= "2025-07-01"].copy()

POST_ALERT = [
    "case_disposition",
    "remediation_action",
    "forensic_score_after_review",
    "case_closed_at",
]
IDENTIFIERS = ["alert_id", "host_id", "identity_id", "tenant_id"]
TARGET = "confirmed_incident"

exclude = POST_ALERT + IDENTIFIERS + [TARGET, "alert_created_at"]
feature_names = [c for c in df.columns if c not in exclude]

X_train, y_train = train[feature_names], train[TARGET]
X_validation, y_validation = validation[feature_names], validation[TARGET]
X_test, y_test = test[feature_names], test[TARGET]

print("Training/validation/test:", len(train), len(validation), len(test))
```

**Note:** The snippet is an initial leakage audit and split, **not** a complete modeling pipeline. Subsequent transformations must be fitted safely on training data. Time-derived features can be designed from `alert_created_at` using only information available at alert creation, with a clear justification.

## Requirements

- Python 3.10 or later (a suitable environment).
- `pandas`, `numpy`, `scikit-learn`, and `matplotlib`.
- Optional: `imbalanced-learn` for training-only resampling; `shap` for explainability.
- No commercial or paid API is needed.

## Usage and limitations

This repository supports academic instruction in preprocessing, reproducibility, imbalanced classification, and leakage-safe model evaluation. Since the dataset is a **simulated educational case study**, conclusions cannot be generalized to real security operations without independent validation on appropriately governed operational data.

There are no personal real-user records in this teaching dataset. It should not be used to build or validate production incident-response systems.