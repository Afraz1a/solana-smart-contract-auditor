# Solana Smart Contract Auditor
### AI-Powered Vulnerability Scanner with On-Chain Audit Records

An open-source security tool that automatically scans Solana smart contracts for vulnerabilities using a trained machine learning ensemble (XGBoost + CodeBERT), stores permanent audit records on the Solana blockchain, and provides a full web dashboard for developers.

---

## Live Demo

Start the app locally and open http://localhost:5000

```bash
git clone https://github.com/Afraz1a/solana-auditor
cd solana-auditor
pip install -r requirements.txt
python app.py
```

---

## Features

| Feature | Description |
|---------|-------------|
| AI Scanner | XGBoost + CodeBERT ensemble detects 9 vulnerability types |
| Redaction Levels | Public / Internal / Full report privacy controls |
| Live Leaderboard | Real-time ranking of scanned contracts by risk score |
| On-Chain Records | Permanent audit records stored on Solana Devnet |
| Squads Integration | Pre-upgrade vulnerability guard for multisig proposals |
| Feedback System | Community false-positive flagging saved to disk |
| VSCode Extension | Real-time linting inside the editor on file save |

---

## Vulnerabilities Detected

| ID | Name | Severity |
|----|------|----------|
| 1 | Missing Signer Check | Critical |
| 2 | Missing Owner Check | Critical |
| 3 | Integer Overflow | High |
| 4 | Arbitrary CPI | Critical |
| 5 | Duplicate Mutable Accounts | High |
| 6 | Improper Account Closing | High |
| 7 | Account Data Matching | Medium |
| 8 | Type Cosplay | Medium |
| 9 | Bump Seed Canonicalization | Medium |

---

## Project Structure

```
solana-auditor/
├── app.py                     # Flask web app (frontend + API)
├── requirements.txt
│
├── ml/
│   ├── features.py            # Feature extractor (20 signals per function)
│   ├── train_xgb.py           # XGBoost training pipeline
│   ├── train_codebert.py      # CodeBERT fine-tuning (GPU accelerated)
│   ├── scanner.py             # Ensemble inference (XGBoost + CodeBERT)
│   ├── onchain.py             # Solana blockchain record writer
│   └── models/                # Saved trained models
│       ├── xgb_binary.pkl
│       ├── xgb_type.pkl
│       ├── label_encoder.pkl
│       └── codebert/
│
└── vscode-extension/          # VSCode linting extension
    ├── package.json
    ├── .vscode/launch.json
    └── src/extension.js
```

---

## Setup

### Requirements

- Python 3.10+
- Rust + Solana CLI (for on-chain features)
- NVIDIA GPU recommended for CodeBERT training

### Install

```bash
pip install -r requirements.txt
```

---

## Training The Models

Train XGBoost (fast, around 2 minutes):

```bash
python ml/train_xgb.py
```

Fine-tune CodeBERT (GPU recommended, around 10 minutes):

```bash
python ml/train_codebert.py
```

Test the scanner:

```bash
python ml/scanner.py
```

---

## Running The App

```bash
python app.py
```

Open http://localhost:5000 in your browser.

---

## Blockchain Setup

To enable on-chain audit records you need a Solana wallet with Devnet SOL.

```bash
solana config set --url devnet
solana-keygen new --outfile ~/.config/solana/id.json
```

Get free test SOL at https://faucet.solana.com

Then test the on-chain integration:

```bash
python ml/onchain.py
```

Every scan stores a real transaction on Solana Devnet visible at https://explorer.solana.com

---

## VSCode Extension

```bash
cd vscode-extension
vsce package --no-dependencies
code --install-extension solana-auditor-1.0.0.vsix
```

The extension automatically scans .rs files on save and shows inline warnings.

---

## Model Performance

| Model | Task | Accuracy | F1 Score |
|-------|------|----------|----------|
| XGBoost | Safe vs Vulnerable | 61% | 0.464 |
| XGBoost | Vulnerability Type | 48% | 0.412 |
| CodeBERT | Safe vs Vulnerable | 75% | 0.627 |

---

## Roadmap

- NFT audit certificates via Metaplex
- On-chain DAO voting for false positives
- Automated retraining pipeline
- GitHub Actions integration
- Mainnet deployment
- Multi-chain support (NEAR, CosmWasm)

---

## References

- sealevel-attacks - github.com/coral-xyz/sealevel-attacks
- CodeBERT - Microsoft Research, arxiv.org/abs/2002.08155
- Anchor Framework - anchor-lang.com
- OtterSec Audit Reports - osec.io/reports

---

## Team

| Name | Roll No |
|------|---------|
| Afrazia | BSCS23029 |
| Ashna | BSCS23058 |
| Khadija | BSCS23144 |

Mentor: Sir Umer Janjua  |  TA: Shahzaib Cheema

---

## License

MIT License
