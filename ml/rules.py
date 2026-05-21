# ml/rules.py
# Deterministic rule-based vulnerability detector.
# Catches obvious cases that should never be missed regardless of ML accuracy.
# Each rule returns a confidence score (0.0 to 1.0).

import re


def has_pattern(code: str, pattern: str) -> bool:
    """True if pattern is found in code (case-insensitive, multiline)."""
    return bool(re.search(pattern, code, re.IGNORECASE | re.MULTILINE))


def count_pattern(code: str, pattern: str) -> int:
    return len(re.findall(pattern, code, re.IGNORECASE | re.MULTILINE))


# ── Individual rule functions ─────────────────────────────────────────────────
# Each returns (confidence_0_to_1, reason_string)

def rule_missing_signer_check(code: str):
    """
    Triggers when:
      - Function modifies state or moves lamports
      - AccountInfo (not Signer) is used for an authority-like account
      - No is_signer check exists
    """
    # Indicators of state changes / value movement that need authorization
    moves_value = (
        has_pattern(code, r'try_borrow_mut_lamports') or
        has_pattern(code, r'\.balance\s*[\+\-]') or
        has_pattern(code, r'token::transfer') or
        has_pattern(code, r'system_instruction::transfer')
    )
    if not moves_value:
        return 0.0, None

    # Authority-like account is AccountInfo not Signer
    has_unchecked_auth = has_pattern(
        code,
        r'(pub\s+(?:authority|owner|admin|signer|user|payer|caller)\s*:\s*AccountInfo)'
    )
    has_unchecked_account_type = has_pattern(code, r'UncheckedAccount')

    if not (has_unchecked_auth or has_unchecked_account_type):
        return 0.0, None

    # No is_signer check anywhere
    has_signer_check = (
        has_pattern(code, r'\.is_signer\b') or
        has_pattern(code, r'Signer\s*<') or
        has_pattern(code, r'require!\s*\(.*is_signer') or
        has_pattern(code, r'has_one\s*=\s*authority')
    )
    if has_signer_check:
        return 0.0, None

    return 0.92, "Account modifies state/lamports but authority is AccountInfo without Signer check"


def rule_missing_owner_check(code: str):
    """
    Triggers when:
      - Account is being modified (mut, write)
      - No has_one or owner constraint exists
      - Uses UncheckedAccount or AccountInfo for the modified account
    """
    modifies_account = (
        has_pattern(code, r'&mut\s+ctx\.accounts\.\w+') or
        has_pattern(code, r'#\[account\(\s*mut\s*\)\]')
    )
    if not modifies_account:
        return 0.0, None

    uses_unchecked = (
        has_pattern(code, r'UncheckedAccount') or
        has_pattern(code, r'pub\s+\w+\s*:\s*AccountInfo')
    )
    if not uses_unchecked:
        return 0.0, None

    has_owner_check = (
        has_pattern(code, r'has_one\s*=') or
        has_pattern(code, r'constraint\s*=.*owner') or
        has_pattern(code, r'\.owner\s*==') or
        has_pattern(code, r'#\[account\([^)]*owner\s*=')
    )
    if has_owner_check:
        return 0.0, None

    return 0.85, "Account modified without owner verification (no has_one or owner constraint)"


def rule_integer_overflow(code: str):
    """
    Triggers when:
      - Integer arithmetic on u64/u128/i64 fields
      - Uses raw +, -, * instead of checked_*
    """
    # Find arithmetic operations on numeric fields
    has_raw_arith = (
        has_pattern(code, r'(?:balance|amount|total|supply|count|value)\s*[\+\-\*]\s*\w+') or
        has_pattern(code, r'\w+\.\w+\s*=\s*\w+\.\w+\s*[\+\-\*]\s*\w+') or
        has_pattern(code, r'=\s*\w+\s*[\+\-\*]\s*\w+\s*;')
    )
    if not has_raw_arith:
        return 0.0, None

    # Must involve integer types
    has_int_type = has_pattern(code, r'\bu(?:8|16|32|64|128)\b|\bi(?:8|16|32|64|128)\b')
    if not has_int_type:
        return 0.0, None

    # If checked arithmetic is used everywhere, no issue
    raw_arith_count = (
        count_pattern(code, r'\w+\s*[\+\-\*]\s*\w+\s*;') +
        count_pattern(code, r'=\s*\w+\s*[\+\-\*]')
    )
    checked_count = (
        count_pattern(code, r'\.checked_add') +
        count_pattern(code, r'\.checked_sub') +
        count_pattern(code, r'\.checked_mul') +
        count_pattern(code, r'\.saturating_')
    )

    # If most arithmetic is checked, probably safe
    if checked_count > 0 and raw_arith_count <= checked_count:
        return 0.0, None

    return 0.88, "Raw arithmetic on integer fields without checked_add/sub/mul"


def rule_arbitrary_cpi(code: str):
    """
    Triggers when:
      - Uses raw invoke() to call external programs
      - Does NOT verify the target program ID
      - Does NOT use invoke_signed with proper seeds
    """
    has_invoke = has_pattern(code, r'\binvoke\s*\(')
    if not has_invoke:
        return 0.0, None

    # If they use invoke_signed properly, lower risk
    uses_invoke_signed = has_pattern(code, r'\binvoke_signed\s*\(')
    if uses_invoke_signed and not has_pattern(code, r'\binvoke\s*\([^)]*&[\s\S]{0,100}invoke_signed'):
        # Only invoke_signed used, no raw invoke
        if not re.search(r'\binvoke\s*\(', re.sub(r'\binvoke_signed\s*\(', '', code)):
            return 0.0, None

    # If using CpiContext with typed Program account, safer
    uses_cpi_context = has_pattern(code, r'CpiContext::new\s*\(')
    has_typed_program = has_pattern(code, r'Program\s*<\s*.\s*info\s*,\s*\w+\s*>')
    if uses_cpi_context and has_typed_program:
        return 0.0, None

    # Verify program ID being checked
    has_program_check = (
        has_pattern(code, r'program_id\s*==') or
        has_pattern(code, r'\.key\s*\(\s*\)\s*==.*program') or
        has_pattern(code, r'require!\s*\(.*program_id')
    )
    if has_program_check:
        return 0.0, None

    return 0.90, "Raw invoke() call without program ID verification or typed Program account"


def rule_duplicate_mutable_accounts(code: str):
    """
    Triggers when:
      - Two or more #[account(mut)] of similar/same type
      - No constraint preventing them from being the same account
    """
    # Count mut accounts
    mut_accounts = re.findall(
        r'#\[account\(\s*mut\s*\)\]\s*pub\s+(\w+)\s*:\s*Account\s*<\s*.\s*info\s*,\s*(\w+)\s*>',
        code, re.IGNORECASE
    )
    if len(mut_accounts) < 2:
        return 0.0, None

    # Check if any pair has the same struct type
    types_seen = {}
    for name, type_name in mut_accounts:
        types_seen.setdefault(type_name, []).append(name)

    has_duplicate_type = any(len(names) >= 2 for names in types_seen.values())
    if not has_duplicate_type:
        return 0.0, None

    # Check for constraint preventing same key
    has_key_constraint = (
        has_pattern(code, r'constraint\s*=.*\.key\s*\(\s*\)\s*!=') or
        has_pattern(code, r'require!\s*\(.*\.key\s*\(\s*\)\s*!=')
    )
    if has_key_constraint:
        return 0.0, None

    return 0.87, "Multiple mutable accounts of same type without key-inequality constraint"


def rule_improper_account_closing(code: str):
    """
    Triggers when:
      - Manual lamport zeroing on an account
      - Does NOT use the Anchor close = constraint
    """
    has_manual_zero = (
        has_pattern(code, r'try_borrow_mut_lamports\s*\(\s*\)\s*\?\s*=\s*0') or
        has_pattern(code, r'lamports\s*\(\s*\)\s*=\s*0') or
        (has_pattern(code, r'try_borrow_mut_lamports') and
         has_pattern(code, r'lamports\s*\(\s*\)\s*-\s*'))
    )
    if not has_manual_zero:
        return 0.0, None

    # If using Anchor close = recipient, safer
    has_close_constraint = has_pattern(code, r'close\s*=\s*\w+')
    if has_close_constraint:
        return 0.0, None

    return 0.85, "Manual lamport zeroing instead of Anchor's close = recipient constraint"


def rule_account_data_matching(code: str):
    """
    Triggers when:
      - Borrows data from AccountInfo
      - Parses bytes directly without account type validation
    """
    has_raw_borrow = (
        has_pattern(code, r'\.try_borrow_data\s*\(') or
        has_pattern(code, r'\.data\.borrow\s*\(')
    )
    if not has_raw_borrow:
        return 0.0, None

    # Must be on AccountInfo (not typed Account)
    has_account_info = has_pattern(code, r'pub\s+\w+\s*:\s*AccountInfo')
    if not has_account_info:
        return 0.0, None

    # Parses bytes (sign of manual deserialization)
    parses_bytes = (
        has_pattern(code, r'from_le_bytes') or
        has_pattern(code, r'from_be_bytes') or
        has_pattern(code, r'try_from_slice')
    )
    if not parses_bytes:
        return 0.0, None

    return 0.80, "Manual data parsing from AccountInfo without type/discriminator validation"


def rule_type_cosplay(code: str):
    """
    Triggers when:
      - Modifies an AccountInfo using try_borrow_mut_data
      - No discriminator or type check
    """
    has_mut_data = has_pattern(code, r'try_borrow_mut_data')
    if not has_mut_data:
        return 0.0, None

    # Operating on AccountInfo not typed Account
    has_account_info_mut = has_pattern(
        code,
        r'#\[account\(\s*mut\s*\)\]\s*pub\s+\w+\s*:\s*AccountInfo'
    ) or has_pattern(code, r'///\s*CHECK')

    if not has_account_info_mut:
        return 0.0, None

    # No discriminator check
    has_discriminator_check = (
        has_pattern(code, r'discriminator') or
        has_pattern(code, r'try_deserialize') or
        has_pattern(code, r'account_data\[\s*0\s*\.\.\s*8\s*\]')
    )
    if has_discriminator_check:
        return 0.0, None

    return 0.82, "Writing to AccountInfo data without type or discriminator validation"


def rule_bump_seed_canonicalization(code: str):
    """
    Triggers when:
      - Uses create_program_address (not find_program_address)
      - Or accepts bump as input parameter without re-deriving
    """
    uses_create_pda = has_pattern(code, r'create_program_address')
    uses_find_pda = has_pattern(code, r'find_program_address')

    if not uses_create_pda:
        return 0.0, None

    if uses_find_pda:
        # Both used — probably re-derives, less risk
        return 0.0, None

    return 0.93, "Uses create_program_address without find_program_address (non-canonical bump)"


# ── Main rule runner ──────────────────────────────────────────────────────────

ALL_RULES = [
    ("missing_signer_check",       rule_missing_signer_check),
    ("missing_owner_check",        rule_missing_owner_check),
    ("integer_overflow",           rule_integer_overflow),
    ("arbitrary_cpi",              rule_arbitrary_cpi),
    ("duplicate_mutable_accounts", rule_duplicate_mutable_accounts),
    ("improper_account_closing",   rule_improper_account_closing),
    ("account_data_matching",      rule_account_data_matching),
    ("type_cosplay",               rule_type_cosplay),
    ("bump_seed_canonicalization", rule_bump_seed_canonicalization),
]


def run_rules(code: str):
    """
    Run all rules. Returns list of (vuln_type, confidence, reason) for fired rules,
    sorted by confidence descending.
    """
    results = []
    for vtype, fn in ALL_RULES:
        try:
            conf, reason = fn(code)
            if conf > 0:
                results.append((vtype, conf, reason))
        except Exception:
            pass

    results.sort(key=lambda x: -x[1])
    return results


def get_top_rule_match(code: str, min_confidence: float = 0.80):
    """Returns the highest-confidence rule match above threshold, or None."""
    matches = run_rules(code)
    if matches and matches[0][1] >= min_confidence:
        return matches[0]   # (vtype, confidence, reason)
    return None


# ── Quick test ────────────────────────────────────────────────────────────────

if __name__ == "__main__":
    test_cases = {
        "missing_signer_check": """
            pub fn withdraw(ctx: Context<W>, amount: u64) -> Result<()> {
                let vault = &mut ctx.accounts.vault;
                vault.balance = vault.balance - amount;
                **ctx.accounts.recipient.to_account_info()
                    .try_borrow_mut_lamports()? += amount;
                Ok(())
            }
            #[derive(Accounts)]
            pub struct W<'info> {
                #[account(mut)] pub vault: Account<'info, Vault>,
                pub authority: AccountInfo<'info>,
                #[account(mut)] pub recipient: AccountInfo<'info>,
            }
        """,
        "integer_overflow": """
            pub fn deposit(ctx: Context<D>, amount: u64) -> Result<()> {
                let user = &mut ctx.accounts.user;
                user.balance = user.balance + amount;
                user.total_deposits = user.total_deposits + amount;
                Ok(())
            }
        """,
        "bump_seed_canonicalization": """
            pub fn create_pda(ctx: Context<C>, bump: u8) -> Result<()> {
                let seeds = &[b"vault", ctx.accounts.user.key.as_ref(), &[bump]];
                let pda = Pubkey::create_program_address(seeds, ctx.program_id)?;
                Ok(())
            }
        """,
    }

    for expected, code in test_cases.items():
        matches = run_rules(code)
        if matches:
            top = matches[0]
            status = "OK" if top[0] == expected else "WRONG"
            print(f"[{status}] Expected {expected:30s} Got {top[0]:30s} ({top[1]:.0%})")
            print(f"        Reason: {top[2]}")
        else:
            print(f"[MISS] Expected {expected}, no rule fired")
