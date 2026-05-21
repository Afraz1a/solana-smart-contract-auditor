# debug_scan.py
# Shows what each individual model predicts so we know who is wrong.
# Run from solana-auditor folder:  python debug_scan.py

import os, sys
sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))

from ml.scanner import get_scanner
import torch

TEST = """
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

print("\n" + "=" * 60)
print("INDIVIDUAL MODEL PREDICTIONS")
print("=" * 60)

# XGBoost binary
prob_xgb = s._xgb_binary_prob(TEST)
print(f"\nXGBoost BINARY  : vulnerable_prob = {prob_xgb:.3f}")

# XGBoost type
xgb_type = s._xgb_type_pred(TEST)
print(f"XGBoost TYPE    : {xgb_type}")

# CodeBERT binary
prob_bert = s._bert_binary_prob(TEST)
print(f"CodeBERT BINARY : vulnerable_prob = {prob_bert:.3f}")

# CodeBERT type — show full probabilities
print(f"\nCodeBERT TYPE — full breakdown:")
if s.type_model and s.type_le:
    enc = s.type_tok(TEST.replace("\\n", "\n"),
                     max_length=384, padding="max_length",
                     truncation=True, return_tensors="pt")
    with torch.no_grad():
        logits = s.type_model(
            input_ids=enc["input_ids"].to(s._device),
            attention_mask=enc["attention_mask"].to(s._device),
        ).logits
    probs = torch.softmax(logits, dim=1).squeeze().cpu().tolist()
    pairs = list(zip(s.type_le.classes_, probs))
    pairs.sort(key=lambda x: -x[1])
    for name, p in pairs:
        bar = "#" * int(p * 50)
        print(f"  {name:32s} {p*100:5.1f}%  {bar}")
else:
    print("  CodeBERT type model not loaded!")

print("\n" + "=" * 60)
print("Expected: missing_signer_check (recipient.lamports increased without authority being a signer)")
print("=" * 60)
