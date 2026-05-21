# app.py
# Run: python app.py
# Open: http://localhost:5000

import os, sys, hashlib, time, json
from datetime import datetime, timezone
from flask import Flask, request, jsonify, render_template_string

sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))
from ml.scanner import get_scanner

try:
    from ml.onchain import store_audit_record
except ImportError:
    store_audit_record = None
    print("Warning: ml.onchain not found — on-chain audit storage disabled.")

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

HTML = '''<!DOCTYPE html>
<html>
<head>
<meta charset="UTF-8">
<title>Solana Auditor</title>
<style>
* { box-sizing:border-box; margin:0; padding:0; }
body { background:#0b0e17; color:#e2e8f0; font-family:Arial,sans-serif; font-size:14px; }
header { display:flex; align-items:center; padding:0 24px; height:52px; background:#111827; border-bottom:1px solid #1f2d47; }
.logo { font-family:monospace; font-weight:700; font-size:16px; color:#3b82f6; margin-right:auto; }
.nbtn { background:none; border:1px solid transparent; color:#64748b; font-size:13px; padding:6px 14px; border-radius:6px; cursor:pointer; margin-left:8px; }
.nbtn.on { background:#1a2236; color:#e2e8f0; border-color:#1f2d47; }
.page { display:none; max-width:1080px; margin:0 auto; padding:24px; }
.page.on { display:block; }
.grid { display:grid; grid-template-columns:1fr 1fr; gap:18px; }
.card { background:#111827; border:1px solid #1f2d47; border-radius:10px; padding:18px; }
.lbl { font-size:10px; font-weight:700; color:#64748b; letter-spacing:1.5px; text-transform:uppercase; margin-bottom:12px; }
.row { display:flex; gap:10px; margin-bottom:12px; align-items:center; }
input.nm { flex:1; background:#1a2236; border:1px solid #1f2d47; border-radius:6px; color:#e2e8f0; font-size:13px; padding:7px 12px; outline:none; }
button.sb { background:#3b82f6; color:#fff; border:none; border-radius:6px; font-weight:700; font-size:13px; padding:7px 22px; cursor:pointer; }
button.sb:disabled { background:#374151; color:#6b7280; cursor:not-allowed; }
textarea { width:100%; height:400px; background:#0d1117; border:1px solid #1f2d47; border-radius:8px; color:#c9d1d9; font-family:monospace; font-size:12px; line-height:1.65; padding:14px; resize:none; outline:none; }
#empty { height:400px; display:flex; flex-direction:column; align-items:center; justify-content:center; color:#64748b; border:1px dashed #1f2d47; border-radius:8px; gap:10px; font-size:13px; }
#results { display:none; }
.scard { display:flex; gap:16px; align-items:center; background:#1a2236; border:1px solid #1f2d47; border-radius:10px; padding:16px; margin-bottom:12px; }
.circle { width:88px; height:88px; border-radius:50%; border:8px solid #1f2d47; display:flex; flex-direction:column; align-items:center; justify-content:center; flex-shrink:0; }
.snum { font-family:monospace; font-size:22px; font-weight:700; }
.sden { font-size:10px; color:#64748b; }
.sname { font-weight:700; font-size:15px; margin-bottom:8px; }
.tags { display:flex; gap:8px; flex-wrap:wrap; margin-bottom:6px; }
.tag { font-size:11px; font-weight:600; padding:2px 10px; border-radius:20px; border:1px solid; }
.tv { color:#ef4444; background:#ef444415; border-color:#ef444440; }
.ts { color:#10b981; background:#10b98115; border-color:#10b98140; }
.tt { color:#3b82f6; background:#3b82f615; border-color:#3b82f640; }
.smeta { font-size:11px; color:#64748b; }
.finding { border-radius:8px; padding:14px; border:1px solid; border-left-width:3px; margin-bottom:10px; }
.fc { background:#ef44440a; border-color:#ef444440; border-left-color:#ef4444; }
.fh { background:#f59e0b0a; border-color:#f59e0b40; border-left-color:#f59e0b; }
.fm { background:#eab3080a; border-color:#eab30840; border-left-color:#eab308; }
.frow { display:flex; justify-content:space-between; align-items:center; margin-bottom:8px; }
.fname { font-weight:600; font-size:14px; }
.sbadge { font-size:11px; font-weight:700; padding:2px 10px; border-radius:12px; border:1px solid; }
.bc { color:#ef4444; background:#ef444415; border-color:#ef444450; }
.bh { color:#f59e0b; background:#f59e0b15; border-color:#f59e0b50; }
.bm { color:#eab308; background:#eab30815; border-color:#eab30850; }
.adv { font-size:12.5px; color:#94a3b8; line-height:1.6; }

/* redaction levels */
.rdct-bar { display:flex; gap:6px; margin-bottom:12px; }
.rdct-btn { flex:1; padding:7px; border:1px solid #1f2d47; border-radius:6px; background:#1a2236; color:#64748b; font-size:12px; cursor:pointer; text-align:center; }
.rdct-btn.on { border-color:#3b82f6; color:#3b82f6; background:#3b82f610; font-weight:700; }
.rdact-note { font-size:11px; color:#64748b; background:#1a2236; border:1px solid #1f2d47; border-radius:6px; padding:10px 12px; margin-bottom:12px; line-height:1.7; }

.fbbox { background:#1a2236; border:1px solid #1f2d47; border-radius:8px; padding:14px; margin-top:4px; }
.fblbl { font-size:11px; color:#64748b; margin-bottom:8px; }
.fbrow { display:flex; gap:8px; }
.fbin { flex:1; background:#0b0e17; border:1px solid #1f2d47; border-radius:6px; color:#e2e8f0; font-size:12px; padding:6px 10px; outline:none; }
.fbbtn { background:#111827; border:1px solid #1f2d47; border-radius:6px; color:#e2e8f0; font-size:12px; padding:6px 14px; cursor:pointer; }
.errbx { background:#ef444410; border:1px solid #ef444440; border-radius:8px; padding:14px; color:#ef4444; font-size:12px; margin-bottom:12px; }

/* leaderboard */
.lbhdr { display:flex; justify-content:space-between; align-items:center; margin-bottom:16px; }
.lbtitle { font-family:monospace; font-size:14px; font-weight:700; }
.live-dot { width:8px; height:8px; border-radius:50%; background:#10b981; display:inline-block; margin-right:6px; animation:pulse 2s infinite; }
@keyframes pulse { 0%,100%{opacity:1} 50%{opacity:.3} }
.lbrow { display:flex; align-items:center; gap:14px; background:#1a2236; border:1px solid #1f2d47; border-radius:8px; padding:12px 16px; margin-bottom:8px; transition:border-color .2s; }
.lbrow:hover { border-color:#3b82f6; }
.lbrank { font-size:16px; min-width:28px; }
.lbinfo { flex:1; }
.lbname { font-weight:600; font-size:13px; }
.lbsub { font-size:11px; color:#64748b; margin-top:2px; }
.lbscore { font-family:monospace; font-weight:700; font-size:18px; min-width:36px; text-align:right; }
.empty { text-align:center; color:#64748b; padding:60px 0; }
.last-updated { font-size:11px; color:#64748b; text-align:right; margin-bottom:10px; }
.onchain-box { background:#0f2027; border:1px solid #10b98140; border-radius:8px; padding:14px; margin-top:10px; }
.onchain-title { font-size:11px; font-weight:700; color:#10b981; letter-spacing:1.5px; text-transform:uppercase; margin-bottom:10px; }
.onchain-row { display:flex; justify-content:space-between; font-size:12px; padding:4px 0; border-bottom:1px solid #1f2d47; }
.onchain-row:last-child { border-bottom:none; }
.onchain-key { color:#64748b; }
.onchain-val { color:#e2e8f0; font-family:monospace; font-size:11px; }
.explorer-btn { display:block; text-align:center; margin-top:10px; padding:8px; background:#10b98115; border:1px solid #10b98140; border-radius:6px; color:#10b981; font-size:12px; font-weight:700; text-decoration:none; cursor:pointer; }
.explorer-btn:hover { background:#10b98125; }
table { width:100%; border-collapse:collapse; font-size:13px; }
th { text-align:left; padding:10px 14px; background:#1a2236; border-bottom:1px solid #1f2d47; color:#64748b; font-size:11px; text-transform:uppercase; }
td { padding:10px 14px; border-bottom:1px solid #1f2d47; }
tr:last-child td { border-bottom:none; }
</style>
</head>
<body>

<header>
  <div class="logo">Solana Auditor</div>
  <button class="nbtn on" id="n0" onclick="go(0)">Scanner</button>
  <button class="nbtn"    id="n1" onclick="go(1)">Leaderboard</button>
  <button class="nbtn"    id="n2" onclick="go(2)">Squads</button>
  <button class="nbtn"    id="n3" onclick="go(3)">Feedback Log</button>
</header>

<!-- SCANNER -->
<div class="page on" id="p0">
  <div class="grid">

    <!-- Left: input -->
    <div class="card">
      <div class="lbl">Contract Input</div>
      <div class="row">
        <input class="nm" id="pname" value="my_contract" placeholder="Program name"/>
        <button class="sb" id="sbtn" onclick="doScan()">Scan</button>
      </div>
      <textarea id="code" spellcheck="false">use anchor_lang::prelude::*;

declare_id!("Fg6PaFpoGXkYsidMpWTK6W2BeZ7FEfcYkg476zPFsLnS");

#[program]
pub mod vault {
    use super::*;

    pub fn withdraw(ctx: Context<Withdraw>, amount: u64) -> Result<()> {
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
    pub authority: AccountInfo<'info>,
    #[account(mut)]
    pub recipient: AccountInfo<'info>,
}

#[account]
pub struct Vault { pub balance: u64, pub authority: Pubkey }</textarea>
    </div>

    <!-- Right: results -->
    <div class="card">
      <div class="lbl">Audit Results</div>
      <div id="errbx" class="errbx" style="display:none"></div>

      <div id="empty">
        <div style="font-size:36px">&#128269;</div>
        <div>Paste your contract and click Scan</div>
      </div>

      <div id="results">

        <!-- Redaction level selector -->
        <div class="lbl" style="margin-bottom:8px">Report Privacy Level</div>
        <div class="rdct-bar">
          <div class="rdct-btn on" id="r0" onclick="setRedact(0)">Public</div>
          <div class="rdct-btn"    id="r1" onclick="setRedact(1)">Internal</div>
          <div class="rdct-btn"    id="r2" onclick="setRedact(2)">Full</div>
        </div>
        <div class="rdact-note" id="rdact-note"></div>

        <!-- Score card -->
        <div class="scard">
          <div class="circle" id="circ">
            <span class="snum" id="snum">0</span>
            <span class="sden">/100</span>
          </div>
          <div style="flex:1">
            <div class="sname" id="sname"></div>
            <div class="tags"  id="stags"></div>
            <div class="smeta" id="smeta"></div>
          </div>
        </div>

        <div id="findings"></div>

        <!-- Feedback -->
        <div id="onchain-box" class="onchain-box" style="display:none">
          <div class="onchain-title">&#128279; Blockchain Audit Record</div>
          <div id="onchain-rows"></div>
          <a id="explorer-link" class="explorer-btn" target="_blank">View on Solana Explorer &#8599;</a>
        </div>

        <div class="fbbox">
          <div class="fblbl">Think the result is wrong? Flag it:</div>
          <div class="fbrow">
            <input class="fbin" id="fbin" placeholder="Explain why..."/>
            <button class="fbbtn" onclick="doFeedback()">Submit</button>
          </div>
          <div id="fbsent" style="display:none;color:#10b981;font-size:12px;margin-top:8px">
            Feedback saved. Thank you!
          </div>
        </div>
      </div>
    </div>
  </div>
</div>

<!-- LEADERBOARD -->
<div class="page" id="p1">
  <div class="card">
    <div class="lbhdr">
      <div class="lbtitle">
        <span class="live-dot"></span>Live Leaderboard
      </div>
      <div id="lbcount" style="font-size:12px;color:#64748b"></div>
    </div>
    <div class="last-updated">Last updated: <span id="last-upd">—</span></div>
    <div id="lblist"><div class="empty">No scans yet.</div></div>
  </div>
</div>


<!-- SQUADS -->
<div class="page" id="p2">
  <div class="card">
    <div class="lbhdr">
      <div class="lbtitle">&#9876; Squads Upgrade Guard</div>
      <div style="font-size:12px;color:#64748b">Pre-upgrade vulnerability scanner</div>
    </div>
    <div style="font-size:12px;color:#64748b;margin-bottom:16px;line-height:1.7;background:#1a2236;border:1px solid #1f2d47;border-radius:8px;padding:12px">
      Simulates a Squads multisig upgrade proposal. Before the upgrade is approved, the contract is scanned. If critical vulnerabilities are found the upgrade is BLOCKED.
    </div>
    <div style="display:grid;grid-template-columns:1fr 1fr;gap:18px">
      <div>
        <div class="lbl">Proposal Details</div>
        <div style="display:flex;flex-direction:column;gap:10px;margin-bottom:14px">
          <input class="nm" id="sq-program" placeholder="Program name" value="my_program"/>
          <input class="nm" id="sq-proposal" placeholder="Proposal ID" value="PROP-001"/>
          <input class="nm" id="sq-multisig" placeholder="Multisig address" value="7xKXtg2CW87d97TXJSDpbD5jBkheTqA83TZRuJosgAsU"/>
          <input class="nm" id="sq-threshold" placeholder="Approval threshold" value="3"/>
        </div>
        <div class="lbl">Contract Code to Deploy</div>
        <textarea id="sq-code" style="height:260px" spellcheck="false">use anchor_lang::prelude::*;

declare_id!("Fg6PaFpoGXkYsidMpWTK6W2BeZ7FEfcYkg476zPFsLnS");

#[program]
pub mod upgrade_v2 {
    use super::*;
    pub fn withdraw(ctx: Context<Withdraw>, amount: u64) -> Result<()> {
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
    pub authority: AccountInfo<'info>,
    #[account(mut)]
    pub recipient: AccountInfo<'info>,
}
#[account]
pub struct Vault { pub balance: u64, pub authority: Pubkey }</textarea>
        <button class="sb" style="width:100%;margin-top:12px" onclick="doSquadsScan()">Submit Upgrade Proposal</button>
      </div>
      <div>
        <div class="lbl">Scan Result</div>
        <div id="sq-empty" style="height:420px;display:flex;flex-direction:column;align-items:center;justify-content:center;color:#64748b;border:1px dashed #1f2d47;border-radius:8px;gap:10px;font-size:13px">
          <div style="font-size:36px">&#9876;</div>
          <div>Submit a proposal to run pre-upgrade scan</div>
        </div>
        <div id="sq-result" style="display:none;flex-direction:column;gap:12px"></div>
      </div>
    </div>

    <!-- History -->
    <div style="margin-top:24px">
      <div class="lbl">Proposal History</div>
      <div id="sq-history"><div class="empty">No proposals submitted yet.</div></div>
    </div>
  </div>
</div>

<!-- FEEDBACK LOG -->
<div class="page" id="p3">
  <div class="card">
    <div class="lbhdr">
      <div class="lbtitle">Feedback Log</div>
      <div id="fbcount" style="font-size:12px;color:#64748b"></div>
    </div>
    <div id="fblog"><div class="empty">No feedback yet.</div></div>
  </div>
</div>

<script>
var scanId   = null;
var lastData = null;
var redactLv = 0;
var lbTimer  = null;

// ── navigation ─────────────────────────────────────────────────────────────
function go(n) {
  for (var i=0;i<4;i++) {
    document.getElementById('p'+i).className = 'page'+(i===n?' on':'');
    document.getElementById('n'+i).className = 'nbtn'+(i===n?' on':'');
  }
  if (n===1) { loadLB(); startLBRefresh(); }
  else        { stopLBRefresh(); }
  if (n===3) loadFB();
}

// ── helpers ─────────────────────────────────────────────────────────────────
function rc(s) {
  return s>=70?'#ef4444':s>=40?'#f59e0b':s>=15?'#eab308':'#10b981';
}

function maskAddr(addr) {
  if (!addr || addr === 'N/A') return 'N/A';
  return addr.slice(0,4) + '...' + addr.slice(-4);
}

function maskName(name) {
  return 'fn_' + name.split('').reduce(function(a,c){return a+c.charCodeAt(0)},0).toString(16).slice(0,6);
}

// ── redaction ───────────────────────────────────────────────────────────────
var RDCT_NOTES = [
  'PUBLIC — Program name masked · Vulnerability type hidden · Fix advice hidden · Scan ID hidden. Safe to share with anyone publicly.',
  'INTERNAL — Program name visible · Vulnerability type visible · Fix advice visible · Confidence score hidden · Scan ID hidden. For your team only.',
  'FULL — Everything visible: program name, scan ID, confidence score, models used, vulnerability type, fix advice, and raw detection signals. For verified auditors only.'
];

function setRedact(n) {
  redactLv = n;
  for (var i=0;i<3;i++) {
    document.getElementById('r'+i).className = 'rdct-btn'+(i===n?' on':'');
  }
  document.getElementById('rdact-note').textContent = RDCT_NOTES[n];
  if (lastData) applyRedact(lastData);
}

function applyRedact(d) {
  var findings = d.findings || [];
  var html = '';

  // ── PUBLIC: maximum redaction ──────────────────────────────────
  if (redactLv === 0) {
    document.getElementById('sname').textContent =
      '[REDACTED-' + (d.program_name ? d.program_name.slice(0,2).toUpperCase() : 'XX') + ']';
    document.getElementById('smeta').textContent =
      'Risk level: ' + (d.risk_score >= 70 ? 'HIGH' : d.risk_score >= 40 ? 'MEDIUM' : 'LOW') +
      '  |  Status: ' + (d.is_vulnerable ? 'Vulnerable' : 'Safe');

    if (findings.length > 0) {
      for (var i=0;i<findings.length;i++) {
        var f  = findings[i];
        var sev = f.severity.toLowerCase();
        var fc = sev==='critical'?'fc':sev==='high'?'fh':'fm';
        var bc = sev==='critical'?'bc':sev==='high'?'bh':'bm';
        html += '<div class="finding '+fc+'">' +
          '<div class="frow">' +
          '<span class="fname">[VULNERABILITY DETECTED]</span>' +
          '<span class="sbadge '+bc+'">'+f.severity+'</span>' +
          '</div>' +
          '<div class="adv" style="color:#64748b;font-style:italic">Switch to Internal or Full report to see vulnerability details and fix advice.</div>' +
          '</div>';
      }
    } else {
      html = '<div style="text-align:center;color:#10b981;padding:20px">No vulnerabilities found.</div>';
    }

  // ── INTERNAL: team level ───────────────────────────────────────
  } else if (redactLv === 1) {
    document.getElementById('sname').textContent = d.program_name;
    document.getElementById('smeta').textContent =
      'Status: ' + (d.is_vulnerable ? 'Vulnerable' : 'Safe') +
      '  |  Type: ' + (d.vuln_type !== 'none' ? d.vuln_type.replace(/_/g,' ') : 'none') +
      '  |  Models: ' + (d.models_used||[]).join(' + ');

    if (findings.length > 0) {
      for (var i=0;i<findings.length;i++) {
        var f  = findings[i];
        var sev = f.severity.toLowerCase();
        var fc = sev==='critical'?'fc':sev==='high'?'fh':'fm';
        var bc = sev==='critical'?'bc':sev==='high'?'bh':'bm';
        html += '<div class="finding '+fc+'">' +
          '<div class="frow">' +
          '<span class="fname">'+f.name+'</span>' +
          '<span class="sbadge '+bc+'">'+f.severity+'</span>' +
          '</div>' +
          '<div class="adv">'+f.advice+'</div>' +
          '</div>';
      }
    } else if (d.is_vulnerable) {
      html = '<div class="finding fm"><div class="adv">Vulnerability detected but type could not be identified. Manual review recommended.</div></div>';
    } else {
      html = '<div style="text-align:center;color:#10b981;padding:20px">No vulnerabilities found. Contract looks safe.</div>';
    }

  // ── FULL: auditor level ────────────────────────────────────────
  } else {
    document.getElementById('sname').textContent = d.program_name;
    document.getElementById('smeta').textContent =
      'Scan ID: ' + d.scan_id +
      '  |  Confidence: ' + (d.confidence*100).toFixed(1) + '%' +
      '  |  Risk Score: ' + d.risk_score + '/100' +
      '  |  Models: ' + (d.models_used||[]).join(' + ');

    if (findings.length > 0) {
      for (var i=0;i<findings.length;i++) {
        var f  = findings[i];
        var sev = f.severity.toLowerCase();
        var fc = sev==='critical'?'fc':sev==='high'?'fh':'fm';
        var bc = sev==='critical'?'bc':sev==='high'?'bh':'bm';
        html += '<div class="finding '+fc+'">' +
          '<div class="frow">' +
          '<span class="fname">'+f.name+'</span>' +
          '<span class="sbadge '+bc+'">'+f.severity+'</span>' +
          '</div>' +
          '<div class="adv">'+f.advice+'</div>' +
          '<div style="margin-top:8px;font-size:11px;color:#475569;border-top:1px solid #1f2d47;padding-top:8px">' +
          'Type: <code style="color:#7dd3fc">'+f.type+'</code>' +
          '  &nbsp;|&nbsp;  Confidence: <code style="color:#7dd3fc">'+(f.confidence*100).toFixed(1)+'%</code>' +
          '</div>' +
          '</div>';
      }
    } else if (d.is_vulnerable) {
      html = '<div class="finding fm"><div class="adv">Vulnerability detected. Confidence: '+(d.confidence*100).toFixed(1)+'%. Type classifier returned no specific match. Manual review recommended.</div></div>';
    } else {
      html = '<div style="text-align:center;color:#10b981;padding:20px">No vulnerabilities found.<br><span style="font-size:11px;color:#64748b">Confidence: '+(d.confidence*100).toFixed(1)+'% safe &nbsp;|&nbsp; Models: '+(d.models_used||[]).join(' + ')+'</span></div>';
    }
  }

  document.getElementById('findings').innerHTML = html;
}

// ── scan ────────────────────────────────────────────────────────────────────
function doScan() {
  var code = document.getElementById('code').value.trim();
  var name = document.getElementById('pname').value.trim() || 'contract';
  if (!code) { alert('Please paste contract code first'); return; }

  var btn = document.getElementById('sbtn');
  btn.textContent = 'Scanning...';
  btn.disabled    = true;

  document.getElementById('empty').style.display   = 'flex';
  document.getElementById('results').style.display = 'none';
  document.getElementById('errbx').style.display   = 'none';
  document.getElementById('fbsent').style.display  = 'none';

  var xhr = new XMLHttpRequest();
  xhr.open('POST', '/scan', true);
  xhr.setRequestHeader('Content-Type', 'application/json');
  xhr.onreadystatechange = function() {
    if (xhr.readyState !== 4) return;
    btn.textContent = 'Scan';
    btn.disabled    = false;
    if (xhr.status === 200) {
      var d  = JSON.parse(xhr.responseText);
      scanId   = d.scan_id;
      lastData = d;
      showResult(d);
    } else {
      document.getElementById('errbx').style.display = 'block';
      document.getElementById('errbx').textContent   = 'Server error. Make sure python app.py is running.';
    }
  };
  xhr.onerror = function() {
    btn.textContent = 'Scan';
    btn.disabled    = false;
    document.getElementById('errbx').style.display = 'block';
    document.getElementById('errbx').textContent   = 'Cannot connect. Run: python app.py';
  };
  xhr.send(JSON.stringify({source_code:code, program_name:name, public:true}));
}

function showResult(d) {
  var score = d.risk_score;
  var col   = rc(score);

  document.getElementById('empty').style.display   = 'none';
  document.getElementById('results').style.display = 'block';

  document.getElementById('circ').style.borderColor = col;
  document.getElementById('snum').textContent       = score;
  document.getElementById('snum').style.color       = col;

  var tags = d.is_vulnerable
    ? '<span class="tag tv">Vulnerable</span>' + (d.vuln_type && d.vuln_type!=='none' ? '<span class="tag tt">'+d.vuln_type.replace(/_/g,' ')+'</span>' : '')
    : '<span class="tag ts">Safe</span>';
  document.getElementById('stags').innerHTML = tags;

  // set redaction note and apply current level
  document.getElementById('rdact-note').textContent = RDCT_NOTES[redactLv];
  applyRedact(d);

  // Show onchain record
  var ob = document.getElementById('onchain-box');
  if (d.onchain && d.onchain.stored) {
    ob.style.display = 'block';
    var sig = d.onchain.signature;
    var shortSig = sig.slice(0,8)+'...'+sig.slice(-8);
    document.getElementById('onchain-rows').innerHTML =
      '<div class="onchain-row"><span class="onchain-key">Status</span><span class="onchain-val" style="color:#10b981">Stored on Solana Devnet</span></div>' +
      '<div class="onchain-row"><span class="onchain-key">Program</span><span class="onchain-val">'+d.program_name+'</span></div>' +
      '<div class="onchain-row"><span class="onchain-key">Risk Score</span><span class="onchain-val">'+d.risk_score+'/100</span></div>' +
      '<div class="onchain-row"><span class="onchain-key">Result</span><span class="onchain-val">'+(d.is_vulnerable?'Vulnerable':'Safe')+'</span></div>' +
      '<div class="onchain-row"><span class="onchain-key">Transaction</span><span class="onchain-val">'+shortSig+'</span></div>';
    document.getElementById('explorer-link').href = d.onchain.explorer_url;
  } else if (d.onchain && !d.onchain.stored) {
    ob.style.display = 'block';
    document.getElementById('onchain-rows').innerHTML =
      '<div class="onchain-row"><span class="onchain-key">Status</span><span class="onchain-val" style="color:#f59e0b">Could not store on-chain: '+(d.onchain.error||'unknown error')+'</span></div>';
    document.getElementById('explorer-link').style.display = 'none';
  }
}

// ── leaderboard with auto refresh ────────────────────────────────────────────
function loadLB() {
  var xhr = new XMLHttpRequest();
  xhr.open('GET', '/leaderboard', true);
  xhr.onreadystatechange = function() {
    if (xhr.readyState !== 4 || xhr.status !== 200) return;
    var data    = JSON.parse(xhr.responseText);
    var entries = data.entries || [];
    var medals  = ['1.','2.','3.'];

    document.getElementById('lbcount').textContent  = entries.length + ' scanned';
    document.getElementById('last-upd').textContent = new Date().toLocaleTimeString();

    if (!entries.length) {
      document.getElementById('lblist').innerHTML = '<div class="empty">No scans yet. Run your first scan.</div>';
      return;
    }

    var html = '';
    for (var i=0;i<entries.length;i++) {
      var e   = entries[i];
      var col = rc(e.risk_score);
      var typ = (e.vuln_type && e.vuln_type!=='none') ? e.vuln_type.replace(/_/g,' ') : 'safe';
      var dt  = new Date(e.scanned_at).toLocaleString();
      html += '<div class="lbrow">' +
        '<span class="lbrank">'+(medals[i]||'#'+(i+1))+'</span>' +
        '<div class="lbinfo">' +
        '<div class="lbname">'+e.program_name+'</div>' +
        '<div class="lbsub">'+typ+' &middot; '+dt+'</div>' +
        '</div>' +
        '<span class="tag '+(e.is_vulnerable?'tv':'ts')+'">'+(e.is_vulnerable?'Vulnerable':'Safe')+'</span>' +
        '<span class="lbscore" style="color:'+col+'">'+e.risk_score+'</span>' +
        '</div>';
    }
    document.getElementById('lblist').innerHTML = html;
  };
  xhr.send();
}

function startLBRefresh() {
  stopLBRefresh();
  lbTimer = setInterval(loadLB, 10000);  // refresh every 10 seconds
}

function stopLBRefresh() {
  if (lbTimer) { clearInterval(lbTimer); lbTimer = null; }
}

// ── feedback log ─────────────────────────────────────────────────────────────
function loadFB() {
  var xhr = new XMLHttpRequest();
  xhr.open('GET', '/feedback/list', true);
  xhr.onreadystatechange = function() {
    if (xhr.readyState !== 4 || xhr.status !== 200) return;
    var data  = JSON.parse(xhr.responseText);
    var items = data.items || [];
    document.getElementById('fbcount').textContent = items.length + ' reports';
    if (!items.length) {
      document.getElementById('fblog').innerHTML = '<div class="empty">No feedback yet.</div>';
      return;
    }
    var rows = '';
    for (var i=0;i<items.length;i++) {
      var it = items[i];
      rows += '<tr><td>'+it.id+'</td><td>'+it.scan_id+'</td><td>'+it.reason+'</td><td>'+new Date(it.submitted_at).toLocaleString()+'</td></tr>';
    }
    document.getElementById('fblog').innerHTML =
      '<table><thead><tr><th>#</th><th>Scan ID</th><th>Reason</th><th>Date</th></tr></thead><tbody>'+rows+'</tbody></table>';
  };
  xhr.send();
}

// ── send feedback ─────────────────────────────────────────────────────────────
function doFeedback() {
  var reason = document.getElementById('fbin').value.trim();
  if (!reason)  { alert('Please type a reason'); return; }
  if (!scanId)  { alert('Run a scan first'); return; }

  var xhr = new XMLHttpRequest();
  xhr.open('POST', '/feedback', true);
  xhr.setRequestHeader('Content-Type', 'application/json');
  xhr.onreadystatechange = function() {
    if (xhr.readyState !== 4) return;
    if (xhr.status === 200) {
      document.getElementById('fbsent').style.display = 'block';
      document.getElementById('fbin').value = '';
    } else {
      alert('Error submitting feedback.');
    }
  };
  xhr.send(JSON.stringify({scan_id:scanId, vuln_type:'unknown', reason:reason}));
}

// ── squads ────────────────────────────────────────────────────────────────────
var sqHistory = [];

function doSquadsScan() {
  var code      = document.getElementById('sq-code').value.trim();
  var program   = document.getElementById('sq-program').value.trim() || 'my_program';
  var proposal  = document.getElementById('sq-proposal').value.trim() || 'PROP-001';
  var multisig  = document.getElementById('sq-multisig').value.trim();
  var threshold = document.getElementById('sq-threshold').value.trim();

  if (!code) { alert('Please paste contract code'); return; }

  document.getElementById('sq-empty').style.display  = 'flex';
  document.getElementById('sq-result').style.display = 'none';
  document.getElementById('sq-empty').innerHTML = '<div style="font-size:24px">&#9203;</div><div>Scanning proposal...</div>';

  var xhr = new XMLHttpRequest();
  xhr.open('POST', '/squads/check', true);
  xhr.setRequestHeader('Content-Type', 'application/json');
  xhr.onreadystatechange = function() {
    if (xhr.readyState !== 4) return;
    if (xhr.status === 200) {
      var d = JSON.parse(xhr.responseText);
      showSquadsResult(d, proposal, multisig, threshold);
    } else {
      document.getElementById('sq-empty').innerHTML = '<div style="color:#ef4444">Server error. Make sure python app.py is running.</div>';
    }
  };
  xhr.send(JSON.stringify({
    source_code:  code,
    program_name: program,
    proposal_id:  proposal,
    multisig:     multisig,
    threshold:    threshold,
  }));
}

function showSquadsResult(d, proposal, multisig, threshold) {
  document.getElementById('sq-empty').style.display  = 'none';
  document.getElementById('sq-result').style.display = 'flex';

  var passed  = d.decision === 'PASS';
  var color   = passed ? '#10b981' : '#ef4444';
  var icon    = passed ? '&#10003;' : '&#10007;';
  var label   = passed ? 'UPGRADE APPROVED' : 'UPGRADE BLOCKED';
  var bgcolor = passed ? '#10b98115' : '#ef444415';
  var border  = passed ? '#10b98140' : '#ef444440';

  var findingsHtml = '';
  if (d.findings && d.findings.length > 0) {
    for (var i=0;i<d.findings.length;i++) {
      var f  = d.findings[i];
      var sc = f.severity==='Critical'?'#ef4444':f.severity==='High'?'#f59e0b':'#eab308';
      findingsHtml += '<div style="background:'+sc+'10;border:1px solid '+sc+'40;border-left:3px solid '+sc+';border-radius:6px;padding:10px 12px;margin-top:8px;font-size:12px">' +
        '<span style="color:'+sc+';font-weight:700">['+f.severity+']</span> '+f.name+'<br>' +
        '<span style="color:#94a3b8">'+f.advice+'</span>' +
        '</div>';
    }
  }

  document.getElementById('sq-result').innerHTML =
    '<div style="background:'+bgcolor+';border:2px solid '+border+';border-radius:10px;padding:20px;text-align:center">' +
    '<div style="font-size:48px;color:'+color+'">'+icon+'</div>' +
    '<div style="font-size:20px;font-weight:700;color:'+color+';margin:8px 0">'+label+'</div>' +
    '<div style="font-size:13px;color:#94a3b8">Risk Score: '+d.risk_score+'/100</div>' +
    '</div>' +
    '<div style="background:#1a2236;border:1px solid #1f2d47;border-radius:8px;padding:14px;font-size:12px">' +
    '<div style="display:grid;grid-template-columns:1fr 1fr;gap:8px;color:#64748b">' +
    '<div>Proposal: <span style="color:#e2e8f0">'+proposal+'</span></div>' +
    '<div>Threshold: <span style="color:#e2e8f0">'+threshold+' signers</span></div>' +
    '<div>Multisig: <span style="color:#e2e8f0">'+multisig.slice(0,8)+'...</span></div>' +
    '<div>Decision: <span style="color:'+color+';font-weight:700">'+d.decision+'</span></div>' +
    '</div>' +
    (findingsHtml ? '<div style="margin-top:10px;font-size:11px;font-weight:700;color:#64748b;letter-spacing:1px">ISSUES FOUND</div>'+findingsHtml : '<div style="margin-top:10px;color:#10b981;font-size:12px">No vulnerabilities found. Safe to upgrade.</div>') +
    '</div>';

  // Add to history
  sqHistory.unshift({
    proposal:  proposal,
    program:   d.program_name,
    decision:  d.decision,
    risk:      d.risk_score,
    time:      new Date().toLocaleString(),
    color:     color,
  });
  renderSquadsHistory();
}

function renderSquadsHistory() {
  if (!sqHistory.length) return;
  var html = '';
  for (var i=0;i<sqHistory.length;i++) {
    var h = sqHistory[i];
    html += '<div class="lbrow">' +
      '<span style="font-size:16px">'+(h.decision==='PASS'?'&#10003;':'&#10007;')+'</span>' +
      '<div class="lbinfo">' +
      '<div class="lbname">'+h.proposal+' — '+h.program+'</div>' +
      '<div class="lbsub">'+h.time+'</div>' +
      '</div>' +
      '<span class="tag" style="color:'+h.color+';background:'+h.color+'15;border-color:'+h.color+'40">'+h.decision+'</span>' +
      '<span class="lbscore" style="color:'+h.color+'">'+h.risk+'</span>' +
      '</div>';
  }
  document.getElementById('sq-history').innerHTML = html;
}
</script>
</body>
</html>'''


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
    # Store on Solana blockchain (optional — skipped if ml.onchain not available)
    onchain = None
    if store_audit_record is not None:
        try:
            onchain = store_audit_record({**record, "scan_id": scan_id})
        except Exception as e:
            print(f"Warning: on-chain storage failed: {e}")
    record["onchain"] = onchain

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
        return jsonify({"error": "No data"}), 400
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
    save_feedback()
    return jsonify({"message": "Saved!", "id": item["id"]})



@app.route("/squads/check", methods=["POST"])
def squads_check():
    data = request.get_json(force=True)
    if not data or not data.get("source_code", "").strip():
        return jsonify({"error": "source_code is empty"}), 400

    result = scanner.scan(data["source_code"], data.get("program_name", "contract"))

    # BLOCK if risk score >= 60 or any Critical finding
    has_critical = any(
        f.get("severity") == "Critical"
        for f in result.get("findings", [])
    )
    decision = "BLOCK" if (result["risk_score"] >= 60 or has_critical) else "PASS"

    return jsonify({
        "decision":     decision,
        "program_name": data.get("program_name", "contract"),
        "proposal_id":  data.get("proposal_id", ""),
        "multisig":     data.get("multisig", ""),
        "risk_score":   result["risk_score"],
        "is_vulnerable": result["is_vulnerable"],
        "vuln_type":    result["vuln_type"],
        "findings":     result.get("findings", []),
        "recommendation": (
            "Safe to proceed with upgrade."
            if decision == "PASS"
            else "BLOCKED — Fix vulnerabilities before upgrade."
        ),
        "scanned_at": datetime.now(timezone.utc).isoformat(),
    })

@app.route("/feedback/list")
def feedback_list():
    return jsonify({"total": len(FEEDBACK), "items": FEEDBACK})


@app.route("/health")
def health():
    return jsonify({"status": "ok", "scans": len(SCANS), "feedback": len(FEEDBACK)})


if __name__ == "__main__":
    print("\nSolana Auditor running at http://localhost:5000\n")
    app.run(debug=True, port=5000)