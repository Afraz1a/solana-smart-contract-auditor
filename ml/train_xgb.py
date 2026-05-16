# ml/train_xgb.py
# Run: python ml/train_xgb.py
# Trains TWO XGBoost models from your dataset_final.csv:
#   1. Binary model  — safe vs vulnerable
#   2. Type model    — which vulnerability type

import os, sys
import pandas as pd
import numpy as np
import joblib
from sklearn.model_selection import train_test_split
from sklearn.metrics import classification_report, f1_score, accuracy_score
from sklearn.preprocessing import LabelEncoder
import xgboost as xgb

sys.path.insert(0, os.path.dirname(os.path.dirname(__file__)))
from ml.features import extract_features, FEATURE_NAMES

# ── Paths ─────────────────────────────────────────────────────────────────────

CSV_PATH  = os.path.join(os.path.dirname(os.path.dirname(__file__)), "dataset_final.csv")
MODEL_DIR = os.path.join(os.path.dirname(__file__), "models")
os.makedirs(MODEL_DIR, exist_ok=True)

# ── Load & prepare data ───────────────────────────────────────────────────────

def load_data():
    print("Loading dataset...")
    df = pd.read_csv(CSV_PATH)
    print(f"  Total rows     : {len(df)}")
    print(f"  Safe           : {(df['label'] == 'safe').sum()}")
    print(f"  Vulnerable     : {(df['label'] == 'vulnerable').sum()}")
    print(f"  Vuln types     : {df['vuln_type'].nunique()}")
    print()

    print("Extracting features (this takes a minute)...")
    feature_rows = []
    for i, row in df.iterrows():
        feats = extract_features(str(row["code"]))
        feature_rows.append(feats)
        if (i + 1) % 50 == 0:
            print(f"  {i+1}/{len(df)} done...")

    X = pd.DataFrame(feature_rows)[FEATURE_NAMES].values.astype(np.float32)
    print(f"  Feature matrix : {X.shape}")
    return df, X


# ── Model 1: Binary (safe vs vulnerable) ─────────────────────────────────────

def train_binary(df, X):
    print("\n── Model 1: Safe vs Vulnerable ──────────────────────────")

    y = (df["label"] == "vulnerable").astype(int).values

    X_tr, X_te, y_tr, y_te = train_test_split(
        X, y, test_size=0.2, random_state=42, stratify=y
    )

    model = xgb.XGBClassifier(
        n_estimators     = 300,
        max_depth        = 5,
        learning_rate    = 0.05,
        subsample        = 0.8,
        colsample_bytree = 0.8,
        eval_metric      = "logloss",
        random_state     = 42,
        n_jobs           = -1,
    )
    model.fit(
        X_tr, y_tr,
        eval_set = [(X_te, y_te)],
        verbose  = False,
    )

    y_pred = model.predict(X_te)
    acc    = accuracy_score(y_te, y_pred)
    f1     = f1_score(y_te, y_pred)

    print(f"  Accuracy : {acc*100:.1f}%")
    print(f"  F1 Score : {f1:.3f}")
    print()
    print(classification_report(y_te, y_pred, target_names=["safe", "vulnerable"]))

    print("  Top features:")
    imp = sorted(zip(FEATURE_NAMES, model.feature_importances_), key=lambda x: -x[1])
    for name, score in imp[:5]:
        print(f"    {name:35s}  {score:.4f}")

    joblib.dump(model, os.path.join(MODEL_DIR, "xgb_binary.pkl"))
    print(f"\n  Saved -> models/xgb_binary.pkl")
    return model


# ── Model 2: Vulnerability type classifier ────────────────────────────────────

def train_type(df, X):
    print("\n── Model 2: Vulnerability Type ──────────────────────────")

    # Only train on vulnerable rows, skip "unknown"
    mask = (df["label"] == "vulnerable") & (df["vuln_type"] != "unknown")
    df_v = df[mask].reset_index(drop=True)
    X_v  = X[mask]

    print(f"  Training on {len(df_v)} vulnerable samples (excluding 'unknown')")
    print(f"  Types: {df_v['vuln_type'].value_counts().to_dict()}")

    le = LabelEncoder()
    y  = le.fit_transform(df_v["vuln_type"])

    X_tr, X_te, y_tr, y_te = train_test_split(
        X_v, y, test_size=0.2, random_state=42,
        stratify=y if len(np.unique(y)) > 1 else None
    )

    model = xgb.XGBClassifier(
        n_estimators     = 300,
        max_depth        = 6,
        learning_rate    = 0.05,
        subsample        = 0.8,
        colsample_bytree = 0.8,
        eval_metric      = "mlogloss",
        random_state     = 42,
        n_jobs           = -1,
        num_class        = len(le.classes_),
    )
    model.fit(
        X_tr, y_tr,
        eval_set = [(X_te, y_te)],
        verbose  = False,
    )

    y_pred = model.predict(X_te)
    acc    = accuracy_score(y_te, y_pred)
    f1     = f1_score(y_te, y_pred, average="macro", zero_division=0)

    print(f"\n  Accuracy : {acc*100:.1f}%")
    print(f"  F1 Macro : {f1:.3f}")
    print()

    # FIX: pass labels= so it works even if some classes missing from test set
    print(classification_report(
        y_te, y_pred,
        labels        = list(range(len(le.classes_))),
        target_names  = le.classes_,
        zero_division = 0
    ))

    joblib.dump(model, os.path.join(MODEL_DIR, "xgb_type.pkl"))
    joblib.dump(le,    os.path.join(MODEL_DIR, "label_encoder.pkl"))
    print(f"  Saved -> models/xgb_type.pkl")
    print(f"  Saved -> models/label_encoder.pkl")
    return model, le


# ── Run ───────────────────────────────────────────────────────────────────────

if __name__ == "__main__":
    df, X = load_data()
    train_binary(df, X)
    train_type(df, X)
    print("\n All XGBoost models trained and saved.")