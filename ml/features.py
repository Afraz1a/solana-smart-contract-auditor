# ml/features.py
# Reads raw Rust source code and extracts 20 yes/no signals.
# Used by both the training pipeline and the live scanner.

import re

def extract_features(code: str) -> dict:
    """
    Takes a raw Rust/Anchor contract string.
    Returns a dict of 20 binary/numeric features.
    """
    src = code.replace("\\n", "\n")  # handle escaped newlines from CSV

    return {
        # ── Arithmetic safety ────────────────────────────────────
        "has_checked_math": int(bool(re.search(
            r'\.(checked_add|checked_sub|checked_mul|checked_div)\s*\(', src))),

        "has_unchecked_math": int(
            bool(re.search(r'\b(u64|u128|u32|i64|i32)\b', src)) and
            bool(re.search(r'[\+\-\*]\s', src)) and
            not bool(re.search(r'\.(checked_add|checked_sub|checked_mul)\s*\(', src))
        ),

        "has_saturating_math": int(bool(re.search(
            r'\.(saturating_add|saturating_sub|saturating_mul)\s*\(', src))),

        # ── Signer / permission checks ───────────────────────────
        "has_signer_type": int(bool(re.search(
            r':\s*Signer\s*<', src))),

        "has_is_signer": int(bool(re.search(
            r'\.is_signer\b', src))),

        "has_require_signer": int(bool(re.search(
            r'require!\s*\(.*is_signer|MissingRequiredSignature', src))),

        # ── Account validation ───────────────────────────────────
        "has_has_one": int(bool(re.search(
            r'has_one\s*=', src))),

        "has_constraint": int(bool(re.search(
            r'constraint\s*=', src))),

        "has_owner_check": int(bool(re.search(
            r'\.owner\s*==|has_one\s*=.*authority|require!.*\.key\(\)', src))),

        "has_key_check": int(bool(re.search(
            r'\.key\(\)\s*==|\.key\(\)\s*!=', src))),

        "uses_unchecked_account": int(bool(re.search(
            r'UncheckedAccount|AccountInfo\s*<|/// CHECK:', src))),

        "has_account_macro": int(bool(re.search(
            r'#\[account\(', src))),

        # ── CPI (cross-program calls) ────────────────────────────
        "has_invoke": int(bool(re.search(
            r'\binvoke\s*\(', src))),

        "has_invoke_signed": int(bool(re.search(
            r'\binvoke_signed\s*\(', src))),

        "has_cpi_context": int(bool(re.search(
            r'CpiContext::new\b', src))),

        "cpi_call_count": (
            len(re.findall(r'\binvoke\s*\(', src)) +
            len(re.findall(r'CpiContext::new\b', src))
        ),

        "cpi_without_signer": int(
            bool(re.search(r'\binvoke\s*\(', src)) and
            not bool(re.search(r'\binvoke_signed\s*\(', src)) and
            not bool(re.search(r':\s*Signer\s*<', src))
        ),

        # ── Token / lamports ─────────────────────────────────────
        "has_mint_constraint": int(bool(re.search(
            r'constraint.*mint\s*==|mint\s*=\s*\w+\.mint', src))),

        "has_lamport_transfer": int(bool(re.search(
            r'try_borrow_mut_lamports|system_instruction::transfer', src))),

        # ── State mutation order relative to CPI ─────────────────
        "state_before_cpi": int(_state_before_cpi(src)),
    }


def _state_before_cpi(src: str) -> bool:
    cpi_pos    = [m.start() for m in re.finditer(r'\binvoke\s*\(|CpiContext::new\b', src)]
    assign_pos = [m.start() for m in re.finditer(r'\.\w+\s*=\s*[^=]', src)]
    if not cpi_pos or not assign_pos:
        return False
    return any(a < cpi_pos[0] for a in assign_pos)


FEATURE_NAMES = list(extract_features(""))
