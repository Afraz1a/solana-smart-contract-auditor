# ml/train_codebert_type.py
# Fine-tunes a second CodeBERT model specifically for vulnerability TYPE classification.
# This complements train_codebert.py which only does binary (safe vs vulnerable).
#
# Run: python ml/train_codebert_type.py

import os, sys
import pandas as pd
import numpy as np
import torch
from torch.optim import AdamW
from torch.utils.data import Dataset, DataLoader
from transformers import (
    RobertaTokenizer,
    RobertaForSequenceClassification,
    get_linear_schedule_with_warmup,
)
from sklearn.model_selection import train_test_split
from sklearn.metrics import f1_score, accuracy_score, classification_report
from sklearn.preprocessing import LabelEncoder
import joblib

CSV_PATH  = os.path.join(os.path.dirname(os.path.dirname(__file__)), "dataset_final.csv")
MODEL_DIR = os.path.join(os.path.dirname(__file__), "models", "codebert_type")
LE_PATH   = os.path.join(os.path.dirname(__file__), "models", "type_label_encoder.pkl")
os.makedirs(MODEL_DIR, exist_ok=True)

EPOCHS  = 6      # one more than binary since type is harder
MAX_LEN = 384    # bigger window — type detection needs more context
LR      = 2e-5


def get_device():
    if torch.cuda.is_available():
        d = torch.device("cuda")
        print(f"  GPU detected: {torch.cuda.get_device_name(0)}")
        return d, 8     # smaller batch for type, longer sequences
    print("  No GPU found. Will train on CPU (slower).")
    return torch.device("cpu"), 4


class TypeDataset(Dataset):
    def __init__(self, codes, labels, tokenizer):
        self.codes = codes
        self.labels = labels
        self.tok = tokenizer

    def __len__(self):
        return len(self.codes)

    def __getitem__(self, idx):
        enc = self.tok(
            str(self.codes[idx]).replace("\\n", "\n"),
            max_length=MAX_LEN, padding="max_length",
            truncation=True, return_tensors="pt",
        )
        return {
            "input_ids":      enc["input_ids"].squeeze(),
            "attention_mask": enc["attention_mask"].squeeze(),
            "labels":         torch.tensor(self.labels[idx], dtype=torch.long),
        }


def train():
    print("=" * 55)
    print("  CodeBERT TYPE classifier — 9 vulnerability classes")
    print("=" * 55)

    device, BATCH = get_device()
    if device.type == "cuda":
        torch.backends.cudnn.benchmark = True

    print("\nLoading dataset...")
    df = pd.read_csv(CSV_PATH)

    # Only vulnerable rows with real types
    df = df[(df["label"] == "vulnerable") &
            (df["vuln_type"] != "unknown") &
            (df["vuln_type"] != "none")].reset_index(drop=True)

    # Drop classes with too few samples
    counts = df["vuln_type"].value_counts()
    keep = counts[counts >= 15].index
    df = df[df["vuln_type"].isin(keep)].reset_index(drop=True)

    print(f"  {len(df)} samples across {df['vuln_type'].nunique()} types")
    for vt, c in df["vuln_type"].value_counts().items():
        print(f"    {vt:32s} {c}")

    le = LabelEncoder()
    y_all = le.fit_transform(df["vuln_type"])
    joblib.dump(le, LE_PATH)

    # Class weights for imbalance
    class_counts = np.bincount(y_all)
    class_weights = torch.tensor(
        (len(y_all) / (len(class_counts) * class_counts)).astype(np.float32)
    ).to(device)
    print(f"\n  Class weights: {dict(zip(le.classes_, class_weights.cpu().numpy().round(2)))}")

    # Stratified split
    tr_codes, te_codes, tr_y, te_y = train_test_split(
        df["code"].tolist(), y_all,
        test_size=0.2, random_state=42, stratify=y_all
    )

    print("\nLoading CodeBERT...")
    tokenizer = RobertaTokenizer.from_pretrained("microsoft/codebert-base")
    model = RobertaForSequenceClassification.from_pretrained(
        "microsoft/codebert-base",
        num_labels=len(le.classes_),
    ).to(device)

    nw = 2 if device.type == "cuda" else 0
    train_loader = DataLoader(TypeDataset(tr_codes, tr_y, tokenizer),
                              batch_size=BATCH, shuffle=True,
                              num_workers=nw, pin_memory=device.type == "cuda")
    val_loader = DataLoader(TypeDataset(te_codes, te_y, tokenizer),
                            batch_size=BATCH, num_workers=nw,
                            pin_memory=device.type == "cuda")

    optimizer = AdamW(model.parameters(), lr=LR, weight_decay=0.01)
    total_steps = len(train_loader) * EPOCHS
    scheduler = get_linear_schedule_with_warmup(
        optimizer,
        num_warmup_steps=max(1, total_steps // 10),
        num_training_steps=total_steps,
    )

    # Class-weighted loss
    loss_fn = torch.nn.CrossEntropyLoss(weight=class_weights)

    use_amp = device.type == "cuda"
    scaler = torch.amp.GradScaler('cuda') if use_amp else None

    print(f"\nTraining for {EPOCHS} epochs on {str(device).upper()}...\n")
    best_f1 = 0.0
    patience_left = 2     # early stop counter

    for epoch in range(EPOCHS):
        # Train
        model.train()
        tr_loss = 0.0
        for batch in train_loader:
            ids = batch["input_ids"].to(device, non_blocking=True)
            mask = batch["attention_mask"].to(device, non_blocking=True)
            y = batch["labels"].to(device, non_blocking=True)

            optimizer.zero_grad()
            if use_amp:
                with torch.amp.autocast('cuda'):
                    out = model(input_ids=ids, attention_mask=mask)
                    loss = loss_fn(out.logits, y)
                scaler.scale(loss).backward()
                scaler.unscale_(optimizer)
                torch.nn.utils.clip_grad_norm_(model.parameters(), 1.0)
                scaler.step(optimizer)
                scaler.update()
            else:
                out = model(input_ids=ids, attention_mask=mask)
                loss = loss_fn(out.logits, y)
                loss.backward()
                torch.nn.utils.clip_grad_norm_(model.parameters(), 1.0)
                optimizer.step()
            scheduler.step()
            tr_loss += loss.item()

        # Validate
        model.eval()
        preds, trues = [], []
        v_loss = 0.0
        with torch.no_grad():
            for batch in val_loader:
                ids = batch["input_ids"].to(device, non_blocking=True)
                mask = batch["attention_mask"].to(device, non_blocking=True)
                y = batch["labels"].to(device, non_blocking=True)
                out = model(input_ids=ids, attention_mask=mask)
                v_loss += loss_fn(out.logits, y).item()
                preds.extend(out.logits.argmax(dim=1).cpu().tolist())
                trues.extend(batch["labels"].tolist())

        acc = accuracy_score(trues, preds)
        f1  = f1_score(trues, preds, average="macro", zero_division=0)

        mem_str = f"  gpu_mem={torch.cuda.memory_reserved(0)/1e9:.1f}GB" if device.type=="cuda" else ""
        print(f"  Epoch {epoch+1}/{EPOCHS}  "
              f"train_loss={tr_loss/len(train_loader):.4f}  "
              f"val_loss={v_loss/len(val_loader):.4f}  "
              f"acc={acc*100:.1f}%  macro_f1={f1:.3f}{mem_str}")

        if f1 > best_f1:
            best_f1 = f1
            model.save_pretrained(MODEL_DIR)
            tokenizer.save_pretrained(MODEL_DIR)
            print(f"    -> Best model saved (f1={best_f1:.3f})")
            patience_left = 2
        else:
            patience_left -= 1
            if patience_left <= 0 and epoch >= 3:
                print("    Early stopping — validation F1 stopped improving")
                break

    # Final report
    print(f"\n{'='*55}")
    print(f"TYPE MODEL DONE")
    print(f"  Best Macro F1 : {best_f1:.3f}")
    print(f"  Saved to       : {MODEL_DIR}")
    print(f"{'='*55}")

    print("\nFinal classification report:")
    print(classification_report(trues, preds,
                                target_names=le.classes_,
                                zero_division=0))


if __name__ == "__main__":
    train()
