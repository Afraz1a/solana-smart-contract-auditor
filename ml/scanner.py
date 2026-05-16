# ml/scanner.py
# The main scanner used by the API.
# Combines XGBoost + CodeBERT results into one final report.

import os, sys
import numpy as np
import joblib

sys.path.insert(0, os.path.dirname(os.path.dirname(__file__)))
from ml.features import extract_features, FEATURE_NAMES

MODEL_DIR = os.path.join(os.path.dirname(__file__), "models")

# Human-readable display for each vuln type
VULN_DISPLAY = {
    "missing_signer_check":        "Missing Signer Check",
    "missing_owner_check":         "Missing Owner Check",
    "integer_overflow":            "Integer Overflow",
    "arbitrary_cpi":               "Arbitrary CPI (Risky External Call)",
    "duplicate_mutable_accounts":  "Duplicate Mutable Accounts",
    "improper_account_closing":    "Improper Account Closing",
    "account_data_matching":       "Account Data Mismatch",
    "type_cosplay":                "Type Cosplay",
    "bump_seed_canonicalization":  "Bump Seed Not Canonical",
    "unknown":                     "Unknown Vulnerability",
    "none":                        "None",
}

VULN_SEVERITY = {
    "missing_signer_check":       "Critical",
    "missing_owner_check":        "Critical",
    "arbitrary_cpi":              "Critical",
    "integer_overflow":           "High",
    "duplicate_mutable_accounts": "High",
    "improper_account_closing":   "High",
    "account_data_matching":      "Medium",
    "type_cosplay":               "Medium",
    "bump_seed_canonicalization": "Medium",
    "unknown":                    "Medium",
}

VULN_ADVICE = {
    "missing_signer_check":
        "Use 'Signer<info>' in your Accounts struct, or add require!(ctx.accounts.authority.is_signer).",
    "missing_owner_check":
        "Add 'has_one = authority' in your #[account(...)] constraint to verify ownership.",
    "integer_overflow":
        "Replace '+', '-', '*' with .checked_add(), .checked_sub(), .checked_mul() and handle the None case.",
    "arbitrary_cpi":
        "Use CpiContext::new() with a typed Program account instead of raw invoke().",
    "duplicate_mutable_accounts":
        "Add a constraint to ensure two mutable accounts are not the same: constraint = account_a.key() != account_b.key()",
    "improper_account_closing":
        "Use the 'close = recipient' constraint in Anchor instead of manually zeroing lamports.",
    "account_data_matching":
        "Add constraints to verify account fields match expected values before use.",
    "type_cosplay":
        "Use Anchor's typed Account<'info, T> instead of AccountInfo to enforce type checking.",
    "bump_seed_canonicalization":
        "Always use find_program_address() rather than create_program_address() to ensure canonical bump.",
    "unknown":
        "Review this code carefully with a security expert.",
}


class Scanner:
    def __init__(self):
        self.xgb_binary  = None
        self.xgb_type    = None
        self.label_enc   = None
        self.bert_model  = None
        self.bert_tok    = None
        self._load_models()

    def _load_models(self):
        # XGBoost binary
        path = os.path.join(MODEL_DIR, "xgb_binary.pkl")
        if os.path.exists(path):
            self.xgb_binary = joblib.load(path)
            print("XGBoost binary model loaded.")
        else:
            print("XGBoost binary model not found. Run ml/train_xgb.py first.")

        # XGBoost type
        path = os.path.join(MODEL_DIR, "xgb_type.pkl")
        if os.path.exists(path):
            self.xgb_type  = joblib.load(path)
            self.label_enc = joblib.load(os.path.join(MODEL_DIR, "label_encoder.pkl"))
            print("XGBoost type model loaded.")

        # CodeBERT (optional — loads only if trained)
        bert_path = os.path.join(MODEL_DIR, "codebert")
        if os.path.exists(bert_path):
            try:
                import torch
                from transformers import RobertaTokenizer, RobertaForSequenceClassification
                self.bert_tok   = RobertaTokenizer.from_pretrained(bert_path)
                self.bert_model = RobertaForSequenceClassification.from_pretrained(bert_path)
                self.bert_model.eval()
                self._device = torch.device("cuda" if torch.cuda.is_available() else "cpu")
                self.bert_model.to(self._device)
                print("CodeBERT model loaded.")
            except Exception as e:
                print(f"CodeBERT not loaded: {e}")

    def _xgb_predict(self, code: str):
        """Returns (is_vulnerable: bool, prob: float, vuln_type: str)"""
        feats = extract_features(code)
        X     = np.array([[feats[f] for f in FEATURE_NAMES]], dtype=np.float32)

        prob      = float(self.xgb_binary.predict_proba(X)[0][1])
        is_vuln   = prob >= 0.5
        vuln_type = "none"

        if is_vuln and self.xgb_type is not None:
            type_pred = self.xgb_type.predict(X)[0]
            vuln_type = self.label_enc.inverse_transform([type_pred])[0]

        return is_vuln, prob, vuln_type

    def _bert_predict(self, code: str):
        """Returns prob of being vulnerable (0-1)"""
        if self.bert_model is None:
            return None
        import torch
        enc = self.bert_tok(
            code.replace("\\n", "\n"),
            max_length=256, padding="max_length",
            truncation=True, return_tensors="pt",
        )
        with torch.no_grad():
            logits = self.bert_model(
                input_ids      = enc["input_ids"].to(self._device),
                attention_mask = enc["attention_mask"].to(self._device),
            ).logits
        probs = torch.softmax(logits, dim=1).squeeze().cpu().tolist()
        return float(probs[1])  # prob of class 1 (vulnerable)

    def scan(self, code: str, program_name: str = "contract") -> dict:
        if self.xgb_binary is None:
            return {"error": "Models not loaded. Run ml/train_xgb.py first."}

        # XGBoost prediction
        is_vuln_xgb, prob_xgb, vuln_type = self._xgb_predict(code)

        # CodeBERT prediction (if available)
        prob_bert = self._bert_predict(code)

        # Blend
        if prob_bert is not None:
            final_prob = 0.4 * prob_xgb + 0.6 * prob_bert
            models_used = ["XGBoost", "CodeBERT"]
        else:
            final_prob  = prob_xgb
            models_used = ["XGBoost"]

        is_vulnerable = final_prob >= 0.5

        # Risk score 0-100
        risk_score = int(min(100, final_prob * 100))

        # Build finding
        findings = []
        if is_vulnerable and vuln_type not in ("none", "unknown"):
            findings.append({
                "type":     vuln_type,
                "name":     VULN_DISPLAY.get(vuln_type, vuln_type),
                "severity": VULN_SEVERITY.get(vuln_type, "Medium"),
                "advice":   VULN_ADVICE.get(vuln_type, "Review this area carefully."),
                "confidence": round(final_prob, 3),
            })
        elif is_vulnerable:
            findings.append({
                "type":     "unknown",
                "name":     "Potential Vulnerability Detected",
                "severity": "Medium",
                "advice":   "The model flagged this contract but could not identify the specific type. Manual review recommended.",
                "confidence": round(final_prob, 3),
            })

        return {
            "program_name":  program_name,
            "is_vulnerable": is_vulnerable,
            "risk_score":    risk_score,
            "confidence":    round(final_prob, 3),
            "vuln_type":     vuln_type if is_vulnerable else "none",
            "findings":      findings,
            "models_used":   models_used,
        }


# Singleton
_scanner = None
def get_scanner() -> Scanner:
    global _scanner
    if _scanner is None:
        _scanner = Scanner()
    return _scanner


# ── Quick test ────────────────────────────────────────────────────────────────
if __name__ == "__main__":
    TEST_VULN = """
use anchor_lang::prelude::*;
#[program]
pub mod test {
    use super::*;
    pub fn withdraw(ctx: Context<Withdraw>, amount: u64) -> Result<()> {
        let vault = &mut ctx.accounts.vault;
        vault.balance = vault.balance - amount;
        **ctx.accounts.vault.to_account_info().try_borrow_mut_lamports()? -= amount;
        **ctx.accounts.recipient.to_account_info().try_borrow_mut_lamports()? += amount;
        Ok(())
    }
}
#[derive(Accounts)]
pub struct Withdraw<'info> {
    #[account(mut)]
    pub vault: Account<'info, Vault>,
    pub authority: AccountInfo<'info>,
    #[account(mut)]
    pub recipient: AccountInfo<'info>,
}
"""
    TEST_SAFE = """
use anchor_lang::prelude::*;
#[program]
pub mod test {
    use super::*;
    pub fn deposit(ctx: Context<Deposit>, amount: u64) -> Result<()> {
        let vault = &mut ctx.accounts.vault;
        vault.balance = vault.balance.checked_add(amount).ok_or(ErrorCode::Overflow)?;
        Ok(())
    }
}
#[derive(Accounts)]
pub struct Deposit<'info> {
    #[account(mut, has_one = authority)]
    pub vault: Account<'info, Vault>,
    pub authority: Signer<'info>,
}
"""

    s = get_scanner()

    print("\n--- Vulnerable contract ---")
    r = s.scan(TEST_VULN, "test_vault")
    print(f"  Risk score   : {r['risk_score']}/100")
    print(f"  Vulnerable   : {r['is_vulnerable']}")
    print(f"  Vuln type    : {r['vuln_type']}")
    print(f"  Models used  : {r['models_used']}")
    for f in r["findings"]:
        print(f"  [{f['severity']}] {f['name']}")
        print(f"    Advice: {f['advice']}")

    print("\n--- Safe contract ---")
    r = s.scan(TEST_SAFE, "safe_vault")
    print(f"  Risk score   : {r['risk_score']}/100")
    print(f"  Vulnerable   : {r['is_vulnerable']}")
    print(f"  Models used  : {r['models_used']}")
