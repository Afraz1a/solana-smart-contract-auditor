# get_demo_contracts.py
# Pulls one real vulnerable contract per vulnerability type from dataset_final.csv
# and saves them as numbered text files for demo use.
# Run from solana-auditor folder: python get_demo_contracts.py

import os
import pandas as pd

CSV_PATH = "dataset_final.csv"
OUT_DIR  = "demo_contracts"

os.makedirs(OUT_DIR, exist_ok=True)

df = pd.read_csv(CSV_PATH)

# Get vulnerable rows only, exclude unknown and none
vuln_df = df[(df["label"] == "vulnerable") &
             (df["vuln_type"] != "unknown") &
             (df["vuln_type"] != "none")]

print(f"Found {len(vuln_df)} vulnerable samples across {vuln_df['vuln_type'].nunique()} types\n")

# For each vulnerability type, pick one good example
selected = []
for vtype in sorted(vuln_df["vuln_type"].unique()):
    # Get all examples of this type
    candidates = vuln_df[vuln_df["vuln_type"] == vtype].copy()
    # Filter to medium-length ones (not too short, not too long)
    candidates["_len"] = candidates["code"].str.len()
    candidates = candidates[(candidates["_len"] > 200) & (candidates["_len"] < 2000)]

    if len(candidates) == 0:
        # Fall back to any sample
        candidates = vuln_df[vuln_df["vuln_type"] == vtype]

    if len(candidates) == 0:
        print(f"  WARNING: no samples for {vtype}")
        continue

    # Pick the median-length one (most representative)
    candidates = candidates.sort_values("_len" if "_len" in candidates.columns else "code")
    chosen = candidates.iloc[len(candidates) // 2]
    selected.append((vtype, chosen["code"]))

# Also add one safe example
safe_df = df[df["label"] == "safe"].copy()
safe_df["_len"] = safe_df["code"].str.len()
safe_df = safe_df[(safe_df["_len"] > 200) & (safe_df["_len"] < 2000)]
if len(safe_df) > 0:
    safe_df = safe_df.sort_values("_len")
    safe_chosen = safe_df.iloc[len(safe_df) // 2]
    selected.append(("safe", safe_chosen["code"]))

# Write to files
print(f"\nSaving {len(selected)} demo contracts to {OUT_DIR}/\n")
for i, (vtype, code) in enumerate(selected, 1):
    filename = f"{i:02d}_{vtype}.txt"
    filepath = os.path.join(OUT_DIR, filename)
    with open(filepath, "w", encoding="utf-8") as f:
        f.write(f"// DEMO CONTRACT: {vtype}\n")
        f.write(f"// Pulled from training dataset — model should classify correctly\n")
        f.write("// " + "=" * 60 + "\n\n")
        f.write(str(code))
    print(f"  [{i}] {filename}  ({len(code)} chars)")

print(f"\nDone. Open {OUT_DIR}/ folder, copy each .txt content, paste into scanner.")
print("These are real contracts from the training distribution — the model")
print("should classify them correctly with high confidence.")
