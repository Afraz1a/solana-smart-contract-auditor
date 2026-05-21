# ml/scanner.py
# HYBRID scanner: rule-based detection + ML ensemble.
# Rules fire first on clear patterns. ML handles the rest.

import os, sys, re
import numpy as np
import joblib

sys.path.insert(0, os.path.dirname(os.path.dirname(__file__)))
from ml.features import extract_features, FEATURE_NAMES
from ml.rules import get_top_rule_match, run_rules

MODEL_DIR  = os.path.join(os.path.dirname(__file__), "models")
BERT_DIR   = os.path.join(MODEL_DIR, "codebert")
TYPE_DIR   = os.path.join(MODEL_DIR, "codebert_type")

DETECTION_THRESHOLD = 0.4
RULE_CONFIDENCE_MIN = 0.80   # rules override ML at or above this confidence
W_XGB  = 0.30
W_BERT = 0.70

VULN_DISPLAY = {
    "missing_signer_check":       "Missing Signer Check",
    "missing_owner_check":        "Missing Owner Check",
    "integer_overflow":           "Integer Overflow",
    "arbitrary_cpi":              "Arbitrary CPI",
    "duplicate_mutable_accounts": "Duplicate Mutable Accounts",
    "improper_account_closing":   "Improper Account Closing",
    "account_data_matching":      "Account Data Mismatch",
    "type_cosplay":               "Type Cosplay",
    "bump_seed_canonicalization": "Bump Seed Not Canonical",
    "unknown":                    "Unknown Vulnerability",
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
        "Use Signer<'info> in the Accounts struct or add require!(ctx.accounts.authority.is_signer).",
    "missing_owner_check":
        "Add has_one = authority in the #[account(...)] constraint to verify ownership.",
    "integer_overflow":
        "Replace +, -, * with checked_add(), checked_sub(), checked_mul() and handle the None case.",
    "arbitrary_cpi":
        "Use CpiContext::new() with a typed Program account instead of raw invoke().",
    "duplicate_mutable_accounts":
        "Add constraint = account_a.key() != account_b.key() to prevent the same account being passed twice.",
    "improper_account_closing":
        "Use the close = recipient constraint in Anchor instead of manually zeroing lamports.",
    "account_data_matching":
        "Add constraints to verify account fields match expected values before use.",
    "type_cosplay":
        "Use Anchor's typed Account<'info, T> instead of AccountInfo to enforce type checking.",
    "bump_seed_canonicalization":
        "Always use find_program_address() rather than create_program_address() to ensure canonical bump.",
    "unknown":
        "Manual security review recommended.",
}


def split_into_functions(source: str):
    funcs = []
    for m in re.finditer(r'(pub\s+fn\s+\w+[^{]*\{)', source):
        start = m.start()
        i = source.find('{', start)
        if i == -1:
            continue
        brace, j = 0, i
        while j < len(source):
            if source[j] == '{': brace += 1
            elif source[j] == '}':
                brace -= 1
                if brace == 0: break
            j += 1
        block = source[start:j+1]
        if 50 < len(block) < 5000:
            funcs.append(block)
    return funcs if funcs else [source]


class Scanner:
    def __init__(self):
        self.xgb_binary  = None
        self.xgb_type    = None
        self.xgb_le      = None
        self.bert_model  = None
        self.bert_tok    = None
        self.type_model  = None
        self.type_tok    = None
        self.type_le     = None
        self._device     = None
        self._load_models()

    def _load_models(self):
        p = os.path.join(MODEL_DIR, "xgb_binary.pkl")
        if os.path.exists(p):
            self.xgb_binary = joblib.load(p)
            print("XGBoost binary loaded.")

        p = os.path.join(MODEL_DIR, "xgb_type.pkl")
        if os.path.exists(p):
            self.xgb_type = joblib.load(p)
            self.xgb_le   = joblib.load(os.path.join(MODEL_DIR, "label_encoder.pkl"))
            print("XGBoost type loaded.")

        if os.path.exists(BERT_DIR):
            try:
                import torch
                from transformers import RobertaTokenizer, RobertaForSequenceClassification
                self.bert_tok = RobertaTokenizer.from_pretrained(BERT_DIR)
                self.bert_model = RobertaForSequenceClassification.from_pretrained(BERT_DIR)
                self.bert_model.eval()
                self._device = torch.device("cuda" if torch.cuda.is_available() else "cpu")
                self.bert_model.to(self._device)
                print(f"CodeBERT binary loaded on {self._device}.")
            except Exception as e:
                print(f"CodeBERT binary not loaded: {e}")

        if os.path.exists(TYPE_DIR):
            try:
                import torch
                from transformers import RobertaTokenizer, RobertaForSequenceClassification
                self.type_tok = RobertaTokenizer.from_pretrained(TYPE_DIR)
                self.type_model = RobertaForSequenceClassification.from_pretrained(TYPE_DIR)
                self.type_model.eval()
                if self._device is None:
                    self._device = torch.device("cuda" if torch.cuda.is_available() else "cpu")
                self.type_model.to(self._device)
                p = os.path.join(MODEL_DIR, "type_label_encoder.pkl")
                if os.path.exists(p):
                    self.type_le = joblib.load(p)
                print("CodeBERT TYPE classifier loaded.")
            except Exception as e:
                print(f"CodeBERT type not loaded: {e}")

        print("Rule-based detector loaded (9 rules).")

    def _xgb_binary_prob(self, code):
        feats = extract_features(code)
        X = np.array([[feats[f] for f in FEATURE_NAMES]], dtype=np.float32)
        return float(self.xgb_binary.predict_proba(X)[0][1])

    def _xgb_type_pred(self, code):
        if not self.xgb_type:
            return "unknown"
        feats = extract_features(code)
        X = np.array([[feats[f] for f in FEATURE_NAMES]], dtype=np.float32)
        pred = self.xgb_type.predict(X)[0]
        return self.xgb_le.inverse_transform([pred])[0]

    def _bert_binary_prob(self, code):
        if self.bert_model is None:
            return None
        import torch
        enc = self.bert_tok(code.replace("\\n", "\n"),
                            max_length=256, padding="max_length",
                            truncation=True, return_tensors="pt")
        with torch.no_grad():
            logits = self.bert_model(
                input_ids=enc["input_ids"].to(self._device),
                attention_mask=enc["attention_mask"].to(self._device),
            ).logits
        probs = torch.softmax(logits, dim=1).squeeze().cpu().tolist()
        return float(probs[1])

    def _bert_type_pred(self, code):
        if self.type_model is None or self.type_le is None:
            return None, None
        import torch
        enc = self.type_tok(code.replace("\\n", "\n"),
                            max_length=384, padding="max_length",
                            truncation=True, return_tensors="pt")
        with torch.no_grad():
            logits = self.type_model(
                input_ids=enc["input_ids"].to(self._device),
                attention_mask=enc["attention_mask"].to(self._device),
            ).logits
        probs = torch.softmax(logits, dim=1).squeeze().cpu().tolist()
        if isinstance(probs, float):
            probs = [probs]
        idx = int(np.argmax(probs))
        return self.type_le.inverse_transform([idx])[0], float(probs[idx])

    def _scan_one(self, code: str):
        """Scan single block — returns prob, type, type_conf, source_label."""

        # STEP 1: RULES FIRST
        rule_match = get_top_rule_match(code, min_confidence=RULE_CONFIDENCE_MIN)
        if rule_match is not None:
            vtype, conf, reason = rule_match
            return {
                "prob": conf,
                "type": vtype,
                "type_conf": conf,
                "models": ["RuleEngine"],
                "rule_reason": reason,
            }

        # STEP 2: ML ENSEMBLE
        p_xgb  = self._xgb_binary_prob(code) if self.xgb_binary else 0.0
        p_bert = self._bert_binary_prob(code)

        if p_bert is not None:
            final = W_XGB * p_xgb + W_BERT * p_bert
            models = ["XGBoost", "CodeBERT"]
        else:
            final = p_xgb
            models = ["XGBoost"]

        # Type from CodeBERT if confident, else XGBoost
        bert_type, bert_conf = self._bert_type_pred(code)
        if bert_type is not None and bert_conf >= 0.30:
            vuln_type = bert_type
            type_conf = bert_conf
            models.append("CodeBERT-type")
        else:
            vuln_type = self._xgb_type_pred(code)
            type_conf = 0.5

        return {
            "prob": final,
            "type": vuln_type,
            "type_conf": type_conf,
            "models": models,
            "rule_reason": None,
        }

    def scan(self, code: str, program_name: str = "contract") -> dict:
        if not self.xgb_binary:
            return {"error": "Models not loaded. Run train_xgb.py first."}

        # ALL RULE MATCHES across whole file (catches multiple issues)
        all_rule_hits = run_rules(code)
        high_conf_hits = [r for r in all_rule_hits if r[1] >= RULE_CONFIDENCE_MIN]

        # Split into functions and scan each
        functions = split_into_functions(code)
        per_fn_results = [self._scan_one(fn) for fn in functions]
        max_idx = int(np.argmax([r["prob"] for r in per_fn_results]))
        worst = per_fn_results[max_idx]

        # Scan whole code as one
        whole_result = self._scan_one(code[:8000])

        # Final probability is max of per-function worst and whole-file
        final_prob = max(worst["prob"], whole_result["prob"])

        # If any rule fired with high confidence, lift probability to that level
        if high_conf_hits:
            top_rule = high_conf_hits[0]
            final_prob = max(final_prob, top_rule[1])
            vuln_type = top_rule[0]
            type_conf = top_rule[1]
            models_used = ["RuleEngine"]
            if worst["models"] != ["RuleEngine"]:
                models_used += [m for m in worst["models"] if m != "RuleEngine"]
        else:
            # Take type from whichever scan was more confident
            if worst["type_conf"] >= whole_result["type_conf"]:
                vuln_type = worst["type"]
                type_conf = worst["type_conf"]
            else:
                vuln_type = whole_result["type"]
                type_conf = whole_result["type_conf"]
            models_used = list(set(worst["models"] + whole_result["models"]))

        is_vulnerable = final_prob >= DETECTION_THRESHOLD

        findings = []
        # Add all high-confidence rule hits as separate findings
        seen_types = set()
        for vtype, conf, reason in high_conf_hits:
            if vtype in seen_types:
                continue
            seen_types.add(vtype)
            findings.append({
                "type":       vtype,
                "name":       VULN_DISPLAY.get(vtype, vtype),
                "severity":   VULN_SEVERITY.get(vtype, "Medium"),
                "advice":     VULN_ADVICE.get(vtype, "Review carefully."),
                "confidence": round(conf, 3),
                "type_confidence": round(conf, 3),
                "source":     "rule",
                "reason":     reason,
            })

        # If no rules fired but ML thinks vulnerable, add ML finding
        if not findings and is_vulnerable and vuln_type not in ("none", "unknown"):
            findings.append({
                "type":       vuln_type,
                "name":       VULN_DISPLAY.get(vuln_type, vuln_type),
                "severity":   VULN_SEVERITY.get(vuln_type, "Medium"),
                "advice":     VULN_ADVICE.get(vuln_type, "Review carefully."),
                "confidence": round(final_prob, 3),
                "type_confidence": round(type_conf, 3),
                "source":     "ml",
            })
        elif not findings and is_vulnerable:
            findings.append({
                "type":       "unknown",
                "name":       "Potential Vulnerability",
                "severity":   "Medium",
                "advice":     "ML model flagged this but could not identify the specific type.",
                "confidence": round(final_prob, 3),
                "type_confidence": round(type_conf, 3),
                "source":     "ml",
            })

        return {
            "program_name":  program_name,
            "is_vulnerable": is_vulnerable,
            "risk_score":    int(min(100, final_prob * 100)),
            "confidence":    round(final_prob, 3),
            "vuln_type":     vuln_type if is_vulnerable else "none",
            "findings":      findings,
            "models_used":   models_used,
            "functions_scanned": len(functions),
            "rules_fired":   len(high_conf_hits),
        }


_scanner = None
def get_scanner() -> Scanner:
    global _scanner
    if _scanner is None:
        _scanner = Scanner()
    return _scanner


if __name__ == "__main__":
    TEST_VULN = """
pub fn withdraw(ctx: Context<Withdraw>, amount: u64) -> Result<()> {
    let vault = &mut ctx.accounts.vault;
    vault.balance = vault.balance - amount;
    **ctx.accounts.vault.to_account_info().try_borrow_mut_lamports()? -= amount;
    **ctx.accounts.recipient.to_account_info().try_borrow_mut_lamports()? += amount;
    Ok(())
}
#[derive(Accounts)]
pub struct Withdraw<'info> {
    #[account(mut)] pub vault: Account<'info, Vault>,
    pub authority: AccountInfo<'info>,
    #[account(mut)] pub recipient: AccountInfo<'info>,
}
"""
    s = get_scanner()
    r = s.scan(TEST_VULN, "test_vault")
    print(f"\n  Risk score  : {r['risk_score']}/100")
    print(f"  Vulnerable  : {r['is_vulnerable']}")
    print(f"  Type        : {r['vuln_type']}")
    print(f"  Models used : {r['models_used']}")
    print(f"  Rules fired : {r['rules_fired']}")
    for f in r["findings"]:
        src = f.get("source", "?")
        print(f"  [{f['severity']}] {f['name']} (source={src}, conf {f['confidence']})")
        if "reason" in f:
            print(f"     Reason: {f['reason']}")