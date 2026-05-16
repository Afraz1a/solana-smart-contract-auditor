# ml/train_codebert.py
# Run: python ml/train_codebert.py
# GPU accelerated - automatically uses CUDA if available

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
from sklearn.metrics import f1_score, accuracy_score

# ── Config ────────────────────────────────────────────────────────────────────

CSV_PATH  = os.path.join(os.path.dirname(os.path.dirname(__file__)), "dataset_final.csv")
MODEL_DIR = os.path.join(os.path.dirname(__file__), "models", "codebert")
os.makedirs(MODEL_DIR, exist_ok=True)

EPOCHS     = 5
MAX_LEN    = 256
LR         = 2e-5

# ── Auto device setup ─────────────────────────────────────────────────────────

def get_device():
    if torch.cuda.is_available():
        device = torch.device("cuda")
        gpu    = torch.cuda.get_device_name(0)
        mem    = torch.cuda.get_device_properties(0).total_memory / 1e9
        print(f"\n  GPU detected: {gpu} ({mem:.1f} GB VRAM)")
        # Use larger batch size on GPU for speed
        batch_size = 16
    else:
        device     = torch.device("cpu")
        batch_size = 8
        print("\n  No GPU found. Training on CPU (will be slower).")
        print("  To use GPU install: pip install torch --index-url https://download.pytorch.org/whl/cu118")
    return device, batch_size

# ── Dataset ───────────────────────────────────────────────────────────────────

class ContractDataset(Dataset):
    def __init__(self, codes, labels, tokenizer):
        self.codes     = codes
        self.labels    = labels
        self.tokenizer = tokenizer

    def __len__(self):
        return len(self.codes)

    def __getitem__(self, idx):
        enc = self.tokenizer(
            str(self.codes[idx]).replace("\\n", "\n"),
            max_length     = MAX_LEN,
            padding        = "max_length",
            truncation     = True,
            return_tensors = "pt",
        )
        return {
            "input_ids":      enc["input_ids"].squeeze(),
            "attention_mask": enc["attention_mask"].squeeze(),
            "labels":         torch.tensor(self.labels[idx], dtype=torch.long),
        }

# ── Training ──────────────────────────────────────────────────────────────────

def train():
    print("=" * 55)
    print("  CodeBERT Fine-tuning — Solana Vulnerability Scanner")
    print("=" * 55)

    device, BATCH_SIZE = get_device()

    # Enable cuDNN benchmark for faster GPU training
    if device.type == "cuda":
        torch.backends.cudnn.benchmark = True

    print("\nLoading dataset...")
    df     = pd.read_csv(CSV_PATH)
    codes  = df["code"].tolist()
    labels = (df["label"] == "vulnerable").astype(int).tolist()
    print(f"  Total   : {len(codes)} samples")
    print(f"  Vuln    : {sum(labels)}")
    print(f"  Safe    : {len(labels) - sum(labels)}")
    print(f"  Batch   : {BATCH_SIZE}")

    tr_codes, te_codes, tr_labels, te_labels = train_test_split(
        codes, labels, test_size=0.2, random_state=42, stratify=labels
    )

    print("\nLoading CodeBERT (downloads ~500MB on first run)...")
    tokenizer = RobertaTokenizer.from_pretrained("microsoft/codebert-base")
    model     = RobertaForSequenceClassification.from_pretrained(
        "microsoft/codebert-base",
        num_labels = 2,
    ).to(device)

    # Use multiple GPU workers on CUDA, 0 on CPU
    num_workers = 2 if device.type == "cuda" else 0

    train_loader = DataLoader(
        ContractDataset(tr_codes, tr_labels, tokenizer),
        batch_size  = BATCH_SIZE,
        shuffle     = True,
        num_workers = num_workers,
        pin_memory  = device.type == "cuda",
    )
    val_loader = DataLoader(
        ContractDataset(te_codes, te_labels, tokenizer),
        batch_size  = BATCH_SIZE,
        num_workers = num_workers,
        pin_memory  = device.type == "cuda",
    )

    optimizer   = AdamW(model.parameters(), lr=LR, weight_decay=0.01)
    total_steps = len(train_loader) * EPOCHS
    scheduler   = get_linear_schedule_with_warmup(
        optimizer,
        num_warmup_steps   = max(1, total_steps // 10),
        num_training_steps = total_steps,
    )

    # Mixed precision scaler for faster GPU training
    use_amp = device.type == "cuda"
    scaler  = torch.cuda.amp.GradScaler() if use_amp else None
    if use_amp:
        print("  Mixed precision (AMP) enabled for faster training")

    print(f"\nTraining for {EPOCHS} epochs on {str(device).upper()}...\n")
    best_f1 = 0.0

    for epoch in range(EPOCHS):
        # ── Train ──────────────────────────────────────────────
        model.train()
        train_loss = 0.0

        for batch in train_loader:
            input_ids      = batch["input_ids"].to(device, non_blocking=True)
            attention_mask = batch["attention_mask"].to(device, non_blocking=True)
            labels_batch   = batch["labels"].to(device, non_blocking=True)

            optimizer.zero_grad()

            if use_amp:
                with torch.cuda.amp.autocast():
                    out = model(input_ids=input_ids, attention_mask=attention_mask, labels=labels_batch)
                scaler.scale(out.loss).backward()
                scaler.unscale_(optimizer)
                torch.nn.utils.clip_grad_norm_(model.parameters(), 1.0)
                scaler.step(optimizer)
                scaler.update()
            else:
                out = model(input_ids=input_ids, attention_mask=attention_mask, labels=labels_batch)
                out.loss.backward()
                torch.nn.utils.clip_grad_norm_(model.parameters(), 1.0)
                optimizer.step()

            scheduler.step()
            train_loss += out.loss.item()

        # ── Validate ────────────────────────────────────────────
        model.eval()
        all_preds, all_true = [], []
        val_loss = 0.0

        with torch.no_grad():
            for batch in val_loader:
                input_ids      = batch["input_ids"].to(device, non_blocking=True)
                attention_mask = batch["attention_mask"].to(device, non_blocking=True)
                labels_batch   = batch["labels"].to(device, non_blocking=True)

                if use_amp:
                    with torch.cuda.amp.autocast():
                        out = model(input_ids=input_ids, attention_mask=attention_mask, labels=labels_batch)
                else:
                    out = model(input_ids=input_ids, attention_mask=attention_mask, labels=labels_batch)

                val_loss += out.loss.item()
                preds = out.logits.argmax(dim=1).cpu().tolist()
                all_preds.extend(preds)
                all_true.extend(batch["labels"].tolist())

        acc = accuracy_score(all_true, all_preds)
        f1  = f1_score(all_true, all_preds, zero_division=0)

        if device.type == "cuda":
            mem_used = torch.cuda.memory_reserved(0) / 1e9
            print(f"  Epoch {epoch+1}/{EPOCHS}  "
                  f"train_loss={train_loss/len(train_loader):.4f}  "
                  f"val_loss={val_loss/len(val_loader):.4f}  "
                  f"acc={acc*100:.1f}%  f1={f1:.3f}  "
                  f"gpu_mem={mem_used:.1f}GB")
        else:
            print(f"  Epoch {epoch+1}/{EPOCHS}  "
                  f"train_loss={train_loss/len(train_loader):.4f}  "
                  f"val_loss={val_loss/len(val_loader):.4f}  "
                  f"acc={acc*100:.1f}%  f1={f1:.3f}")

        if f1 > best_f1:
            best_f1 = f1
            model.save_pretrained(MODEL_DIR)
            tokenizer.save_pretrained(MODEL_DIR)
            print(f"    -> Best model saved (f1={best_f1:.3f})")

    print(f"\nTraining complete.")
    print(f"Best F1  : {best_f1:.3f}")
    print(f"Saved to : {MODEL_DIR}")


if __name__ == "__main__":
    train()