# ml/onchain.py
# Stores a memo transaction on Solana Devnet after each scan.
# Uses the Memo program — no Anchor or custom program needed.
# The memo contains the scan result as JSON, permanently on-chain.

import os
import json
import base64
from datetime import datetime, timezone

try:
    from solders.keypair import Keypair
    from solders.pubkey import Pubkey
    from solders.transaction import Transaction
    from solders.instruction import Instruction, AccountMeta
    from solders.message import Message
    from solders.hash import Hash
    import urllib.request
    import urllib.parse
    SOLDERS_AVAILABLE = True
except ImportError:
    SOLDERS_AVAILABLE = False
    print("[WARN] solders not installed. Run: pip install solders")

# ── Constants ─────────────────────────────────────────────────────────────────

DEVNET_RPC    = "https://api.devnet.solana.com"
MEMO_PROGRAM  = "MemoSq4gqABAXKb96qnH8TysNcWxMyWCqXgDLGmfcHr"
KEYPAIR_PATH  = os.path.expanduser("~/.config/solana/id.json")

# ── Load wallet ───────────────────────────────────────────────────────────────

def load_keypair():
    if not os.path.exists(KEYPAIR_PATH):
        print(f"[WARN] Wallet not found at {KEYPAIR_PATH}")
        return None
    with open(KEYPAIR_PATH) as f:
        secret = json.load(f)
    return Keypair.from_bytes(bytes(secret))


# ── RPC helper ────────────────────────────────────────────────────────────────

def rpc_call(method, params):
    payload = json.dumps({
        "jsonrpc": "2.0",
        "id":      1,
        "method":  method,
        "params":  params,
    }).encode()

    req = urllib.request.Request(
        DEVNET_RPC,
        data    = payload,
        headers = {"Content-Type": "application/json"},
    )
    with urllib.request.urlopen(req, timeout=15) as res:
        return json.loads(res.read())


def get_latest_blockhash():
    resp = rpc_call("getLatestBlockhash", [{"commitment": "confirmed"}])
    return resp["result"]["value"]["blockhash"]


def send_transaction(tx_bytes):
    encoded = base64.b64encode(tx_bytes).decode()
    resp    = rpc_call("sendTransaction", [
        encoded,
        {"encoding": "base64", "preflightCommitment": "confirmed"}
    ])
    if "error" in resp:
        raise Exception(str(resp["error"]))
    return resp["result"]   # transaction signature


# ── Main function ─────────────────────────────────────────────────────────────

def store_audit_record(scan_result: dict) -> dict:
    """
    Stores a scan result as a memo on Solana Devnet.
    Returns dict with signature and explorer URL.
    """
    if not SOLDERS_AVAILABLE:
        return {"error": "solders not installed", "stored": False}

    keypair = load_keypair()
    if keypair is None:
        return {"error": "Wallet not found", "stored": False}

    # Build compact memo (keep it small to save fees)
    memo_data = {
        "app":     "SolanaAuditor",
        "program": scan_result.get("program_name", "unknown"),
        "risk":    scan_result.get("risk_score", 0),
        "vuln":    scan_result.get("is_vulnerable", False),
        "type":    scan_result.get("vuln_type", "none"),
        "scan_id": scan_result.get("scan_id", ""),
        "time":    datetime.now(timezone.utc).strftime("%Y-%m-%dT%H:%M:%SZ"),
    }
    memo_str  = json.dumps(memo_data, separators=(',', ':'))
    memo_bytes = memo_str.encode("utf-8")

    try:
        # Get recent blockhash
        blockhash_str = get_latest_blockhash()
        blockhash     = Hash.from_string(blockhash_str)

        # Build memo instruction
        memo_program_id = Pubkey.from_string(MEMO_PROGRAM)
        instruction     = Instruction(
            program_id = memo_program_id,
            accounts   = [AccountMeta(pubkey=keypair.pubkey(), is_signer=True, is_writable=False)],
            data       = memo_bytes,
        )

        # Build and sign transaction
        message = Message.new_with_blockhash(
            [instruction],
            keypair.pubkey(),
            blockhash,
        )
        tx = Transaction.new_unsigned(message)
        tx.sign([keypair], blockhash)

        # Send to Devnet
        signature = send_transaction(bytes(tx))

        explorer_url = f"https://explorer.solana.com/tx/{signature}?cluster=devnet"

        print(f"  On-chain record stored: {signature[:20]}...")
        return {
            "stored":       True,
            "signature":    signature,
            "explorer_url": explorer_url,
            "memo":         memo_data,
        }

    except Exception as e:
        print(f"  [WARN] On-chain storage failed: {e}")
        return {"stored": False, "error": str(e)}


# ── Test ──────────────────────────────────────────────────────────────────────

if __name__ == "__main__":
    test_result = {
        "scan_id":       "test1234",
        "program_name":  "dummy_vault",
        "risk_score":    85,
        "is_vulnerable": True,
        "vuln_type":     "missing_signer_check",
    }
    print("Storing test audit record on Solana Devnet...")
    result = store_audit_record(test_result)
    if result["stored"]:
        print(f"\nSuccess!")
        print(f"Signature : {result['signature']}")
        print(f"Explorer  : {result['explorer_url']}")
    else:
        print(f"Failed: {result.get('error')}")
