# ml/train_xgb.py
# Run: python ml/train_xgb.py
# Trains two XGBoost models with class weighting and better hyperparameters.

import os, sys
import pandas as pd
import numpy as np
import joblib
from sklearn.model_selection import train_test_split, cross_val_score
from sklearn.metrics import classification_report, f1_score, accuracy_score
from sklearn.preprocessing import LabelEncoder
from sklearn.utils.class_weight import compute_sample_weight
import xgboost as xgb

sys.path.insert(0, os.path.dirname(os.path.dirname(__file__)))
from ml.features import extract_features, FEATURE_NAMES

CSV_PATH  = os.path.join(os.path.dirname(os.path.dirname(__file__)), "dataset_final.csv")
MODEL_DIR = os.path.join(os.path.dirname(__file__), "models")
os.makedirs(MODEL_DIR, exist_ok=True)


def load_data():
    print("Loading dataset...")
    df = pd.read_csv(CSV_PATH)
    print(f"  Total rows     : {len(df)}")
    print(f"  Safe           : {(df['label']=='safe').sum()}")
    print(f"  Vulnerable     : {(df['label']=='vulnerable').sum()}")
    print(f"  Vuln types     : {df['vuln_type'].nunique()}")

    print("\nExtracting features...")
    rows = []
    for i, row in df.iterrows():
        rows.append(extract_features(str(row["code"])))
        if (i + 1) % 200 == 0:
            print(f"  {i+1}/{len(df)} done...")

    X = pd.DataFrame(rows)[FEATURE_NAMES].values.astype(np.float32)
    print(f"  Feature matrix : {X.shape}")
    return df, X


def train_binary(df, X):
    print("\n== Model 1: Safe vs Vulnerable ==")
    y = (df["label"] == "vulnerable").astype(int).values

    X_tr, X_te, y_tr, y_te = train_test_split(
        X, y, test_size=0.2, random_state=42, stratify=y
    )

    # Class weights — gives more importance to whichever class is smaller
    sw = compute_sample_weight(class_weight="balanced", y=y_tr)

    model = xgb.XGBClassifier(
        n_estimators=500,
        max_depth=7,
        learning_rate=0.03,
        subsample=0.85,
        colsample_bytree=0.85,
        min_child_weight=2,
        gamma=0.1,
        reg_alpha=0.1,
        reg_lambda=1.0,
        eval_metric="logloss",
        random_state=42,
        n_jobs=-1,
    )
    model.fit(X_tr, y_tr,
              sample_weight=sw,
              eval_set=[(X_te, y_te)],
              verbose=False)

    y_pred = model.predict(X_te)
    acc = accuracy_score(y_te, y_pred)
    f1  = f1_score(y_te, y_pred)

    # 5-fold cross-validation for a robust estimate
    print("  Running 5-fold cross-validation...")
    cv = cross_val_score(model, X, y, cv=5, scoring="accuracy", n_jobs=-1)

    print(f"\n  Test Accuracy : {acc*100:.1f}%")
    print(f"  Test F1       : {f1:.3f}")
    print(f"  5-fold CV Acc : {cv.mean()*100:.1f}% (+/- {cv.std()*100:.1f}%)")
    print()
    print(classification_report(y_te, y_pred, target_names=["safe", "vulnerable"]))

    print("  Top features:")
    imp = sorted(zip(FEATURE_NAMES, model.feature_importances_), key=lambda x: -x[1])
    for name, score in imp[:5]:
        print(f"    {name:35s}  {score:.4f}")

    joblib.dump(model, os.path.join(MODEL_DIR, "xgb_binary.pkl"))
    print("\n  Saved -> models/xgb_binary.pkl")


def train_type(df, X):
    print("\n== Model 2: Vulnerability Type ==")

    mask = (df["label"] == "vulnerable") & \
           (df["vuln_type"] != "unknown") & \
           (df["vuln_type"] != "none")
    df_v = df[mask].reset_index(drop=True)
    X_v  = X[mask]

    # Drop tiny classes
    counts = df_v["vuln_type"].value_counts()
    keep = counts[counts >= 10].index
    df_v = df_v[df_v["vuln_type"].isin(keep)].reset_index(drop=True)
    X_v  = X[mask][df["vuln_type"][mask].isin(keep).values]

    print(f"  Training on {len(df_v)} samples, {df_v['vuln_type'].nunique()} types")
    print("  Class distribution:")
    for vt, c in df_v["vuln_type"].value_counts().items():
        print(f"    {vt:32s} {c}")

    le = LabelEncoder()
    y = le.fit_transform(df_v["vuln_type"])

    X_tr, X_te, y_tr, y_te = train_test_split(
        X_v, y, test_size=0.2, random_state=42, stratify=y
    )

    sw = compute_sample_weight(class_weight="balanced", y=y_tr)

    model = xgb.XGBClassifier(
        n_estimators=500,
        max_depth=7,
        learning_rate=0.03,
        subsample=0.85,
        colsample_bytree=0.85,
        min_child_weight=2,
        gamma=0.1,
        reg_alpha=0.1,
        reg_lambda=1.0,
        eval_metric="mlogloss",
        random_state=42,
        n_jobs=-1,
        num_class=len(le.classes_),
    )
    model.fit(X_tr, y_tr,
              sample_weight=sw,
              eval_set=[(X_te, y_te)],
              verbose=False)

    y_pred = model.predict(X_te)
    acc = accuracy_score(y_te, y_pred)
    f1  = f1_score(y_te, y_pred, average="macro", zero_division=0)

    print(f"\n  Test Accuracy : {acc*100:.1f}%")
    print(f"  Macro F1      : {f1:.3f}")
    print()
    print(classification_report(
        y_te, y_pred,
        labels=list(range(len(le.classes_))),
        target_names=le.classes_,
        zero_division=0,
    ))

    joblib.dump(model, os.path.join(MODEL_DIR, "xgb_type.pkl"))
    joblib.dump(le,    os.path.join(MODEL_DIR, "label_encoder.pkl"))
    print("  Saved -> models/xgb_type.pkl")
    print("  Saved -> models/label_encoder.pkl")


if __name__ == "__main__":
    df, X = load_data()
    train_binary(df, X)
    train_type(df, X)
    print("\nAll XGBoost models trained.")