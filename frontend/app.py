# app.py
# Run: python app.py
# Open: http://localhost:5000

import os, sys, hashlib, time, json
from datetime import datetime, timezone
from flask import Flask, request, jsonify, render_template_string

sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))
from ml.scanner import get_scanner

app     = Flask(__name__)
scanner = get_scanner()

SCANS         = {}
LEADERBOARD   = []
FEEDBACK      = []
FEEDBACK_FILE = "feedback.json"

def save_feedback():
    with open(FEEDBACK_FILE, "w") as f:
        json.dump(FEEDBACK, f, indent=2)

def load_feedback():
    global FEEDBACK
    if os.path.exists(FEEDBACK_FILE):
        with open(FEEDBACK_FILE) as f:
            FEEDBACK = json.load(f)

load_feedback()

# ── HTML ──────────────────────────────────────────────────────────────────────

HTML = """
<!DOCTYPE html>
<html lang="en">
<head>
<meta charset="UTF-8"/>
<title>Solana Auditor</title>
<style>
  * { box-sizing: border-box; margin: 0; padding: 0; }
  body { background: #0b0e17; color: #e2e8f0; font-family: Arial, sans-serif; font-size: 14px; }

  header {
    display: flex; align-items: center; gap: 16px;
    padding: 0 28px; height: 52px;
    background: #111827; border-bottom: 1px solid #1f2d47;
    position: sticky; top: 0; z-index: 10;
  }
  .logo { font-family: monospace; font-weight: 700; font-size: 16px; color: #3b82f6; }
  .spacer { flex: 1; }
  .nav-btn {
    background: transparent; border: none; color: #64748b;
    font-size: 13px; font-weight: 500; padding: 6px 14px;
    border-radius: 6px; cursor: pointer;
  }
  .nav-btn.active { background: #1a2236; color: #e2e8f0; border: 1px solid #1f2d47; }

  main { max-width: 1080px; margin: 0 auto; padding: 24px; }
  .view { display: none; }
  .view.active { display: block; }

  .grid { display: grid; grid-template-columns: 1fr 1fr; gap: 18px; }

  .panel { background: #111827; border: 1px solid #1f2d47; border-radius: 10px; padding: 18px; }
  .panel-label {
    font-size: 10px; font-weight: 600; color: #64748b;
    letter-spacing: 1.5px; text-transform: uppercase; margin-bottom: 12px;
  }

  .top-bar { display: flex; gap: 10px; margin-bottom: 12px; }
  .name-input {
    flex: 1; background: #1a2236; border: 1px solid #1f2d47;
    border-radius: 6px; color: #e2e8f0; font-size: 13px; padding: 7px 12px; outline: none;
  }
  .scan-btn {
    background: #3b82f6; color: #fff; border: none;
    border-radius: 6px; font-weight: 600; font-size: 13px;
    padding: 7px 22px; cursor: pointer;
  }
  .scan-btn:disabled { background: #1f2d47; color: #64748b; cursor: not-allowed; }

  textarea {
    width: 100%; height: 440px; background: #0d1117;
    border: 1px solid #1f2d47; border-radius: 8px;
    color: #c9d1d9; font-family: monospace; font-size: 12px;
    line-height: 1.65; padding: 14px; resize: none; outline: none;
  }

  #result-empty {
    height: 440px; display: flex; flex-direction: column;
    align-items: center; justify-content: center;
    color: #64748b; border: 1px dashed #1f2d47;
    border-radius: 8px; gap: 10px;
  }

  #result-content { display: none; flex-direction: column; gap: 12px; }

  .score-card {
    display: flex; gap: 16px; align-items: center;
    background: #1a2236; border: 1px solid #1f2d47;
    border-radius: 10px; padding: 16px;
  }
  .score-circle {
    width: 88px; height: 88px; border-radius: 50%;
    border: 8px solid #1f2d47; display: flex; flex-direction: column;
    align-items: center; justify-content: center; flex-shrink: 0;
  }
  .score-num  { font-family: monospace; font-size: 22px; font-weight: 700; }
  .score-den  { font-size: 10px; color: #64748b; }
  .score-name { font-weight: 700; font-size: 15px; margin-bottom: 8px; }
  .tags { display: flex; gap: 8px; flex-wrap: wrap; margin-bottom: 8px; }
  .tag { font-size: 11px; font-weight: 600; padding: 2px 10px; border-radius: 20px; border: 1px solid; }
  .tag-vuln { color:#ef4444; background:#ef444415; border-color:#ef444440; }
  .tag-safe { color:#10b981; background:#10b98115; border-color:#10b98140; }
  .tag-type { color:#3b82f6; background:#3b82f615; border-color:#3b82f640; }
  .score-meta { font-size: 11px; color: #64748b; }

  .finding { border-radius: 8px; padding: 14px; border: 1px solid; border-left-width: 3px; margin-bottom: 10px; }
  .finding-critical { background:#ef44440a; border-color:#ef444440; border-left-color:#ef4444; }
  .finding-high     { background:#f59e0b0a; border-color:#f59e0b40; border-left-color:#f59e0b; }
  .finding-medium   { background:#eab3080a; border-color:#eab30840; border-left-color:#eab308; }
  .finding-header { display:flex; justify-content:space-between; align-items:center; margin-bottom:8px; }
  .finding-name   { font-weight:600; font-size:14px; }
  .sev-badge { font-size:11px; font-weight:700; padding:2px 10px; border-radius:12px; border:1px solid; }
  .sev-critical { color:#ef4444; background:#ef444415; border-color:#ef444450; }
  .sev-high     { color:#f59e0b; background:#f59e0b15; border-color:#f59e0b50; }
  .sev-medium   { color:#eab308; background:#eab30815; border-color:#eab30850; }
  .finding-advice { font-size:12.5px; color:#94a3b8; line-height:1.6; }

  .feedback-box { background:#1a2236; border:1px solid #1f2d47; border-radius:8px; padding:14px; }
  .fb-label { font-size:11px; color:#64748b; margin-bottom:8px; }
  .fb-row { display:flex; gap:8px; }
  .fb-input {
    flex:1; background:#0b0e17; border:1px solid #1f2d47;
    border-radius:6px; color:#e2e8f0; font-size:12px; padding:6px 10px; outline:none;
  }
  .fb-btn {
    background:#111827; border:1px solid #1f2d47;
    border-radius:6px; color:#e2e8f0; font-size:12px; padding:6px 14px; cursor:pointer;
  }

  .error-box {
    background:#ef444410; border:1px solid #ef444440;
    border-radius:8px; padding:14px; color:#ef4444; font-size:12px; line-height:1.6;
  }

  /* leaderboard */
  .lb-header { display:flex; justify-content:space-between; align-items:center; margin-bottom:16px; }
  .lb-title  { font-family:monospace; font-size:14px; font-weight:700; }
  .lb-count  { font-size:12px; color:#64748b; }
  .lb-row {
    display:flex; align-items:center; gap:14px;
    background:#1a2236; border:1px solid #1f2d47;
    border-radius:8px; padding:12px 16px; margin-bottom:8px;
  }
  .lb-rank  { font-size:16px; min-width:28px; }
  .lb-info  { flex:1; }
  .lb-name  { font-weight:600; font-size:13px; }
  .lb-sub   { font-size:11px; color:#64748b; margin-top:2px; }
  .lb-score { font-family:monospace; font-weight:700; font-size:18px; min-width:36px; text-align:right; }
  .lb-empty { text-align:center; color:#64748b; padding:60px 0; }

  /* feedback table */
  .fb-table { width:100%; border-collapse:collapse; font-size:13px; }
  .fb-table th {
    text-align:left; padding:10px 14px; background:#1a2236;
    border-bottom:1px solid #1f2d47; color:#64748b; font-size:11px; text-transform:uppercase;
  }
  .fb-table td { padding:10px 14px; border-bottom:1px solid #1f2d47; color:#e2e8f0; }
  .fb-table tr:last-child td { border-bottom:none; }

  ::-webkit-scrollbar { width:6px; }
  ::-webkit-scrollbar-thumb { background:#1f2d47; border-radius:3px; }
</style>
</head>
<body>

<header>
  <div class="logo">&#128737; SolanaAuditor</div>
  <div class="spacer"></div>
  <button class="nav-btn active" id="btn-scanner"     onclick="showView('scanner')">&#128269; Scanner</button>
  <button class="nav-btn"        id="btn-leaderboard" onclick="showView('leaderboard')">&#127942; Leaderboard</button>
  <button class="nav-btn"        id="btn-feedback"    onclick="showView('feedback')">&#128203; Feedback</button>
</header>

<main>

  <!-- SCANNER -->
  <div id="view-scanner" class="view active">
    <div class="grid">

      <!-- Left: input -->
      <div class="panel">
        <div class="panel-label">Contract Input</div>
        <div class="top-bar">
          <input id="prog-name" class="name-input" placeholder="Program name" value="my_contract"/>
          <button class="scan-btn" id="scan-btn" onclick="runScan()">&#9654; Scan</button>
        </div>
        <textarea id="code-input" spellcheck="false">use anchor_lang::prelude::*;

declare_id!("Fg6PaFpoGXkYsidMpWTK6W2BeZ7FEfcYkg476zPFsLnS");

#[program]
pub mod vault {
    use super::*;

    pub fn withdraw(ctx: Context<Withdraw>, amount: u64) -> Result<()> {
        // BUG: no signer check
        let vault = &mut ctx.accounts.vault;
        vault.balance = vault.balance - amount;
        **ctx.accounts.vault.to_account_info()
            .try_borrow_mut_lamports()? -= amount;
        **ctx.accounts.recipient.to_account_info()
            .try_borrow_mut_lamports()? += amount;
        Ok(())
    }
}

#[derive(Accounts)]
pub struct Withdraw<'info> {
    #[account(mut)]
    pub vault: Account<'info, Vault>,
    /// CHECK: no owner check
    pub authority: AccountInfo<'info>,
    #[account(mut)]
    pub recipient: AccountInfo<'info>,
}

#[account]
pub struct Vault { pub balance: u64, pub authority: Pubkey }</textarea>
      </div>

      <!-- Right: results -->
      <div class="panel">
        <div class="panel-label">Audit Results</div>

        <div id="result-empty">
          <div style="font-size:36px">&#128269;</div>
          <p>Paste your contract and click Scan</p>
        </div>

        <div id="error-box" class="error-box" style="display:none"></div>

        <div id="result-content">
          <div class="score-card">
            <div class="score-circle" id="score-circle">
              <span class="score-num" id="score-num">0</span>
              <span class="score-den">/100</span>
            </div>
            <div style="flex:1">
              <div class="score-name" id="res-name"></div>
              <div class="tags"       id="res-tags"></div>
              <div class="score-meta" id="res-meta"></div>
            </div>
          </div>

          <div id="findings-list"></div>

          <div class="feedback-box">
            <div class="fb-label">Think the result is wrong? Flag it:</div>
            <div class="fb-row">
              <input id="fb-input" class="fb-input" placeholder="Explain why this result is incorrect..."/>
              <button class="fb-btn" onclick="sendFeedback()">Submit</button>
            </div>
            <div id="fb-sent" style="display:none;color:#10b981;font-size:12px;margin-top:8px">
              &#10003; Feedback submitted and saved. Thank you!
            </div>
          </div>
        </div>
      </div>
    </div>
  </div>

  <!-- LEADERBOARD -->
  <div id="view-leaderboard" class="view">
    <div class="panel">
      <div class="lb-header">
        <div class="lb-title">&#127942; Vulnerability Leaderboard</div>
        <div class="lb-count" id="lb-count"></div>
      </div>
      <div id="lb-list">
        <div class="lb-empty">No scans yet. Run your first scan to see it here.</div>
      </div>
    </div>
  </div>

  <!-- FEEDBACK LOG -->
  <div id="view-feedback" class="view">
    <div class="panel">
      <div class="lb-header">
        <div class="lb-title">&#128203; Submitted Feedback</div>
        <div class="lb-count" id="fb-count"></div>
      </div>
      <div id="fb-table-wrap">
        <div class="lb-empty">No feedback submitted yet.</div>
      </div>
    </div>
  </div>

</main>

<script>
  let currentScanId = null;

  // ── navigation ──────────────────────────────────────────────────────────────
  function showView(name) {
    document.querySelectorAll('.view').forEach(v => v.classList.remove('active'));
    document.querySelectorAll('.nav-btn').forEach(b => b.classList.remove('active'));
    document.getElementById('view-' + name).classList.add('active');
    document.getElementById('btn-' + name).classList.add('active');
    if (name === 'leaderboard') loadLeaderboard();
    if (name === 'feedback')    loadFeedback();
  }

  // ── helpers ─────────────────────────────────────────────────────────────────
  function riskColor(s) {
    return s >= 70 ? '#ef4444' : s >= 40 ? '#f59e0b' : s >= 15 ? '#eab308' : '#10b981';
  }

  // ── scan ────────────────────────────────────────────────────────────────────
  async function runScan() {
    const code = document.getElementById('code-input').value.trim();
    const name = document.getElementById('prog-name').value.trim() || 'contract';
    if (!code) { alert('Please paste some contract code first.'); return; }

    const btn = document.getElementById('scan-btn');
    btn.disabled    = true;
    btn.textContent = 'Scanning...';

    document.getElementById('result-empty').style.display   = 'flex';
    document.getElementById('result-content').style.display = 'none';
    document.getElementById('error-box').style.display      = 'none';
    document.getElementById('fb-sent').style.display        = 'none';

    try {
      const res = await fetch('/scan', {
        method:  'POST',
        headers: { 'Content-Type': 'application/json' },
        body:    JSON.stringify({ source_code: code, program_name: name, public: true }),
      });

      const data = await res.json();
      if (data.error) throw new Error(data.error);

      currentScanId = data.scan_id;
      showResult(data);

    } catch(e) {
      document.getElementById('error-box').style.display = 'block';
      document.getElementById('error-box').textContent =
        'Error: ' + e.message + '\n\nMake sure the server is running with: python app.py';
    } finally {
      btn.disabled    = false;
      btn.textContent = 'Scan';
    }
  }

  // ── render result ───────────────────────────────────────────────────────────
  function showResult(d) {
    const score = d.risk_score;
    const col   = riskColor(score);

    document.getElementById('result-empty').style.display   = 'none';
    document.getElementById('result-content').style.display = 'flex';

    // score circle
    document.getElementById('score-circle').style.borderColor = col;
    document.getElementById('score-num').textContent  = score;
    document.getElementById('score-num').style.color  = col;

    // name
    document.getElementById('res-name').textContent = d.program_name;

    // tags
    let tags = '';
    if (d.is_vulnerable) {
      tags += '<span class="tag tag-vuln">Vulnerable</span>';
      if (d.vuln_type && d.vuln_type !== 'none') {
        tags += '<span class="tag tag-type">' + d.vuln_type.replace(/_/g,' ') + '</span>';
      }
    } else {
      tags += '<span class="tag tag-safe">Safe</span>';
    }
    document.getElementById('res-tags').innerHTML = tags;

    // meta
    document.getElementById('res-meta').textContent =
      'Confidence: ' + (d.confidence * 100).toFixed(1) + '%' +
      '  |  Models: ' + (d.models_used || []).join(' + ') +
      '  |  ID: ' + d.scan_id;

    // findings
    let html = '';
    if (d.findings && d.findings.length > 0) {
      d.findings.forEach(f => {
        const sev = f.severity.toLowerCase();
        html += `
          <div class="finding finding-${sev}">
            <div class="finding-header">
              <span class="finding-name">${f.name}</span>
              <span class="sev-badge sev-${sev}">${f.severity}</span>
            </div>
            <div class="finding-advice">&#128161; ${f.advice}</div>
          </div>`;
      });
    } else if (d.is_vulnerable) {
      html = `<div class="finding finding-medium">
        <div class="finding-advice">Vulnerability detected but specific type could not be identified. Manual review recommended.</div>
      </div>`;
    } else {
      html = `<div style="text-align:center;color:#10b981;padding:20px;font-size:14px">
        &#10003; No vulnerabilities detected. This contract looks safe.
      </div>`;
    }
    document.getElementById('findings-list').innerHTML = html;
  }

  // ── leaderboard ─────────────────────────────────────────────────────────────
  async function loadLeaderboard() {
    const res     = await fetch('/leaderboard');
    const data    = await res.json();
    const entries = data.entries || [];
    const medals  = ['&#127945;','&#127946;','&#127947;'];

    document.getElementById('lb-count').textContent =
      entries.length + ' contract' + (entries.length !== 1 ? 's' : '') + ' scanned';

    if (!entries.length) {
      document.getElementById('lb-list').innerHTML =
        '<div class="lb-empty">No scans yet. Run your first scan to see it here.</div>';
      return;
    }

    document.getElementById('lb-list').innerHTML = entries.map((e, i) => {
      const col  = riskColor(e.risk_score);
      const type = (e.vuln_type && e.vuln_type !== 'none')
        ? e.vuln_type.replace(/_/g,' ') : 'safe';
      const date = new Date(e.scanned_at).toLocaleDateString();
      return `
        <div class="lb-row">
          <span class="lb-rank">${medals[i] || '#' + (i+1)}</span>
          <div class="lb-info">
            <div class="lb-name">${e.program_name}</div>
            <div class="lb-sub">${type} &middot; ${date}</div>
          </div>
          <span class="tag ${e.is_vulnerable ? 'tag-vuln' : 'tag-safe'}">
            ${e.is_vulnerable ? 'Vulnerable' : 'Safe'}
          </span>
          <span class="lb-score" style="color:${col}">${e.risk_score}</span>
        </div>`;
    }).join('');
  }

  // ── feedback log ─────────────────────────────────────────────────────────────
  async function loadFeedback() {
    const res  = await fetch('/feedback/list');
    const data = await res.json();
    const items = data.items || [];

    document.getElementById('fb-count').textContent =
      items.length + ' report' + (items.length !== 1 ? 's' : '');

    if (!items.length) {
      document.getElementById('fb-table-wrap').innerHTML =
        '<div class="lb-empty">No feedback submitted yet.</div>';
      return;
    }

    let rows = items.map(item => `
      <tr>
        <td>${item.id}</td>
        <td>${item.scan_id}</td>
        <td>${item.reason}</td>
        <td>${new Date(item.submitted_at).toLocaleString()}</td>
      </tr>`).join('');

    document.getElementById('fb-table-wrap').innerHTML = `
      <table class="fb-table">
        <thead><tr><th>#</th><th>Scan ID</th><th>Reason</th><th>Submitted</th></tr></thead>
        <tbody>${rows}</tbody>
      </table>`;
  }

  // ── send feedback ────────────────────────────────────────────────────────────
  async function sendFeedback() {
    const reason = document.getElementById('fb-input').value.trim();
    if (!reason)         { alert('Please type a reason.'); return; }
    if (!currentScanId)  { alert('Run a scan first.'); return; }

    const res = await fetch('/feedback', {
      method:  'POST',
      headers: { 'Content-Type': 'application/json' },
      body:    JSON.stringify({
        scan_id:  currentScanId,
        vuln_type: 'unknown',
        reason:    reason,
      }),
    });
    const data = await res.json();
    if (data.error) { alert('Error: ' + data.error); return; }

    document.getElementById('fb-sent').style.display = 'block';
    document.getElementById('fb-input').value = '';
  }
</script>
</body>
</html>
"""

# ── Routes ────────────────────────────────────────────────────────────────────

@app.route("/")
def index():
    return render_template_string(HTML)


@app.route("/scan", methods=["POST"])
def scan():
    data = request.get_json(force=True)
    if not data or not data.get("source_code", "").strip():
        return jsonify({"error": "source_code is empty"}), 400

    scan_id = hashlib.md5(
        (data["source_code"] + str(time.time())).encode()
    ).hexdigest()[:10]

    result = scanner.scan(data["source_code"], data.get("program_name", "contract"))

    record = {
        "scan_id":      scan_id,
        "program_name": data.get("program_name", "contract"),
        "scanned_at":   datetime.now(timezone.utc).isoformat(),
        **result,
    }
    SCANS[scan_id] = record

    if data.get("public", True):
        LEADERBOARD.append({
            "scan_id":       scan_id,
            "program_name":  data.get("program_name", "contract"),
            "risk_score":    result["risk_score"],
            "is_vulnerable": result["is_vulnerable"],
            "vuln_type":     result["vuln_type"],
            "scanned_at":    record["scanned_at"],
        })

    return jsonify(record)


@app.route("/leaderboard")
def leaderboard():
    limit   = int(request.args.get("limit", 20))
    sorted_ = sorted(LEADERBOARD, key=lambda x: x["risk_score"], reverse=True)
    return jsonify({"total": len(sorted_), "entries": sorted_[:limit]})


@app.route("/feedback", methods=["POST"])
def feedback():
    data = request.get_json(force=True)
    if not data:
        return jsonify({"error": "No data received"}), 400
    if data.get("scan_id") not in SCANS:
        return jsonify({"error": "Scan not found"}), 404

    item = {
        "id":           len(FEEDBACK) + 1,
        "scan_id":      data["scan_id"],
        "vuln_type":    data.get("vuln_type", ""),
        "reason":       data.get("reason", ""),
        "submitted_at": datetime.now(timezone.utc).isoformat(),
    }
    FEEDBACK.append(item)
    save_feedback()   # saves to feedback.json permanently
    return jsonify({"message": "Feedback saved!", "id": item["id"]})


@app.route("/feedback/list")
def feedback_list():
    return jsonify({"total": len(FEEDBACK), "items": FEEDBACK})


@app.route("/health")
def health():
    return jsonify({"status": "ok", "scans": len(SCANS), "feedback": len(FEEDBACK)})


# ── Run ───────────────────────────────────────────────────────────────────────

if __name__ == "__main__":
    print("\n Solana Auditor is running!")
    print(" Open this in your browser: http://localhost:5000\n")
    app.run(debug=True, port=5000)