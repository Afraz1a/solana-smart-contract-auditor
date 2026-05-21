import { useState, useEffect } from "react";

const API = "http://localhost:8000";

// ── Design tokens ─────────────────────────────────────────────────────────────
const C = {
  bg:       "#05060f",
  surface:  "#0c0e1a",
  surface2: "#111326",
  border:   "#1a1d30",
  border2:  "#252840",
  purple:   "#9945FF",
  green:    "#14F195",
  textPri:  "#e8eaf6",
  textSec:  "#8b8fa8",
  textMut:  "#454762",
  crit:     "#ef4444",
  high:     "#f97316",
  med:      "#eab308",
  mono:     "'JetBrains Mono', 'Fira Code', monospace",
  sans:     "'Inter', system-ui, sans-serif",
};

const SEV = {
  Critical: { color: C.crit, bg: "rgba(239,68,68,0.08)",  border: "rgba(239,68,68,0.25)"  },
  High:     { color: C.high, bg: "rgba(249,115,22,0.08)", border: "rgba(249,115,22,0.25)" },
  Medium:   { color: C.med,  bg: "rgba(234,179,8,0.08)",  border: "rgba(234,179,8,0.25)"  },
};

function riskColor(s) {
  if (s >= 70) return C.crit;
  if (s >= 40) return C.high;
  if (s >= 15) return C.med;
  return C.green;
}

const SAMPLE = `use anchor_lang::prelude::*;

declare_id!("Fg6PaFpoGXkYsidMpWTK6W2BeZ7FEfcYkg476zPFsLnS");

#[program]
pub mod vault {
    use super::*;

    pub fn withdraw(ctx: Context<Withdraw>, amount: u64) -> Result<()> {
        // BUG: no signer check on authority
        let vault = &mut ctx.accounts.vault;
        // BUG: unchecked subtraction
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
pub struct Vault { pub balance: u64, pub authority: Pubkey }`;

// ── SVG Icons ─────────────────────────────────────────────────────────────────
const IconShield = ({ size = 20 }) => (
  <svg width={size} height={size} viewBox="0 0 24 24" fill="none">
    <path d="M12 2L3 7v5c0 5.25 3.75 10.15 9 11.35C17.25 22.15 21 17.25 21 12V7L12 2z"
      stroke={C.purple} strokeWidth="1.5" fill="rgba(153,69,255,0.12)" strokeLinejoin="round"/>
    <path d="M9 12l2 2 4-4" stroke={C.green} strokeWidth="1.5" strokeLinecap="round" strokeLinejoin="round"/>
  </svg>
);

const IconSearch = ({ size = 13 }) => (
  <svg width={size} height={size} viewBox="0 0 24 24" fill="none" stroke="currentColor" strokeWidth="2" strokeLinecap="round">
    <circle cx="11" cy="11" r="8"/><path d="m21 21-4.35-4.35"/>
  </svg>
);

const IconAlert = ({ size = 12, color = "currentColor" }) => (
  <svg width={size} height={size} viewBox="0 0 24 24" fill="none" stroke={color} strokeWidth="2" strokeLinecap="round" strokeLinejoin="round">
    <path d="M10.29 3.86L1.82 18a2 2 0 0 0 1.71 3h16.94a2 2 0 0 0 1.71-3L13.71 3.86a2 2 0 0 0-3.42 0z"/>
    <line x1="12" y1="9" x2="12" y2="13"/><line x1="12" y1="17" x2="12.01" y2="17"/>
  </svg>
);

const IconCheck = ({ size = 13 }) => (
  <svg width={size} height={size} viewBox="0 0 24 24" fill="none" stroke={C.green} strokeWidth="2.5" strokeLinecap="round" strokeLinejoin="round">
    <polyline points="20 6 9 17 4 12"/>
  </svg>
);

const IconSolana = () => (
  <svg width="18" height="14" viewBox="0 0 646 496" fill="none">
    <path d="M108.53 373.12a19.77 19.77 0 0 1 13.98-5.79H626.7a9.89 9.89 0 0 1 6.99 16.88L537.47 480.43a19.77 19.77 0 0 1-13.98 5.79H19.3a9.89 9.89 0 0 1-6.99-16.88l96.22-96.22z" fill={C.green}/>
    <path d="M108.53 15.36A19.77 19.77 0 0 1 122.51 9.57H626.7a9.89 9.89 0 0 1 6.99 16.88L537.47 122.67a19.77 19.77 0 0 1-13.98 5.79H19.3a9.89 9.89 0 0 1-6.99-16.88L108.53 15.36z" fill={C.purple}/>
    <path d="M537.47 193.65a19.77 19.77 0 0 0-13.98-5.79H19.3a9.89 9.89 0 0 0-6.99 16.88l96.22 96.22a19.77 19.77 0 0 0 13.98 5.79H626.7a9.89 9.89 0 0 0 6.99-16.88l-96.22-96.22z" fill="url(#solGrad)"/>
    <defs>
      <linearGradient id="solGrad" x1="0" y1="0" x2="1" y2="0">
        <stop offset="0%" stopColor={C.purple}/>
        <stop offset="100%" stopColor={C.green}/>
      </linearGradient>
    </defs>
  </svg>
);

// ── Risk Ring ─────────────────────────────────────────────────────────────────
function Ring({ score }) {
  const color = riskColor(score);
  const r = 46, cx = 54, cy = 54;
  const circ = 2 * Math.PI * r;
  const offset = circ - (score / 100) * circ;
  return (
    <svg width={108} height={108} viewBox="0 0 108 108">
      <defs>
        <filter id="ringGlow" x="-20%" y="-20%" width="140%" height="140%">
          <feGaussianBlur stdDeviation="2.5" result="blur"/>
          <feMerge><feMergeNode in="blur"/><feMergeNode in="SourceGraphic"/></feMerge>
        </filter>
      </defs>
      <circle cx={cx} cy={cy} r={r} fill="none" stroke={C.border2} strokeWidth={7}/>
      <circle cx={cx} cy={cy} r={r} fill="none" stroke={color} strokeWidth={7}
        strokeDasharray={circ} strokeDashoffset={offset} strokeLinecap="round"
        transform={`rotate(-90 ${cx} ${cy})`}
        filter="url(#ringGlow)"
        style={{ transition: "stroke-dashoffset 0.7s cubic-bezier(.4,0,.2,1)" }}
      />
      <text x={cx} y={cy - 2} textAnchor="middle" dominantBaseline="middle"
        style={{ fontSize: 26, fontWeight: 700, fill: color, fontFamily: C.mono }}>{score}</text>
      <text x={cx} y={cy + 18} textAnchor="middle"
        style={{ fontSize: 8, fill: C.textMut, fontFamily: C.sans, letterSpacing: 2, textTransform: "uppercase" }}>RISK</text>
    </svg>
  );
}

// ── Stat Chip ─────────────────────────────────────────────────────────────────
function Chip({ label, value, color = C.textSec }) {
  return (
    <div style={{ display: "flex", flexDirection: "column", gap: 2 }}>
      <span style={{ fontSize: 9, color: C.textMut, letterSpacing: 1.2, textTransform: "uppercase", fontWeight: 600 }}>{label}</span>
      <span style={{ fontSize: 12, color, fontFamily: C.mono, fontWeight: 500 }}>{value}</span>
    </div>
  );
}

// ── Scanner ───────────────────────────────────────────────────────────────────
function Scanner({ onScanDone }) {
  const [code,    setCode]    = useState(SAMPLE);
  const [name,    setName]    = useState("vault");
  const [result,  setResult]  = useState(null);
  const [loading, setLoading] = useState(false);
  const [error,   setError]   = useState("");
  const [fbText,  setFbText]  = useState("");
  const [fbSent,  setFbSent]  = useState(false);
  const [elapsed, setElapsed] = useState(null);

  async function runScan() {
    setLoading(true); setError(""); setResult(null); setFbSent(false); setElapsed(null);
    const t0 = Date.now();
    try {
      const res = await fetch(`${API}/scan`, {
        method: "POST",
        headers: { "Content-Type": "application/json" },
        body: JSON.stringify({ source_code: code, program_name: name, public: true }),
      });
      if (!res.ok) throw new Error(await res.text());
      const data = await res.json();
      setElapsed(((Date.now() - t0) / 1000).toFixed(2));
      setResult(data);
      if (onScanDone) onScanDone();
    } catch (e) {
      setError(`API unreachable — ensure the FastAPI server is running on port 8000.\n\n${e.message}`);
    } finally {
      setLoading(false);
    }
  }

  async function sendFeedback() {
    if (!result || !fbText.trim()) return;
    await fetch(`${API}/feedback`, {
      method: "POST",
      headers: { "Content-Type": "application/json" },
      body: JSON.stringify({ scan_id: result.scan_id, vuln_type: result.vuln_type, reason: fbText }),
    });
    setFbSent(true);
  }

  const field = {
    background: C.surface2,
    border: `1px solid ${C.border}`,
    borderRadius: 6,
    color: C.textPri,
    fontFamily: C.sans,
    fontSize: 13,
    outline: "none",
    padding: "8px 12px",
  };

  return (
    <div style={{ display: "grid", gridTemplateColumns: "1fr 1fr", gap: 20, alignItems: "start" }}>

      {/* ── Left: input ── */}
      <div style={{ background: C.surface, border: `1px solid ${C.border}`, borderRadius: 12, overflow: "hidden" }}>
        <div style={{ padding: "14px 16px", borderBottom: `1px solid ${C.border}`, display: "flex", alignItems: "center", gap: 10 }}>
          <span style={{ fontSize: 10, color: C.textMut, letterSpacing: 1.5, textTransform: "uppercase", fontWeight: 600, flex: 1 }}>
            Contract Source
          </span>
          <div style={{ display: "flex", alignItems: "center", gap: 6 }}>
            <input
              value={name}
              onChange={e => setName(e.target.value)}
              placeholder="program name"
              style={{ ...field, padding: "5px 10px", fontSize: 12, width: 150, fontFamily: C.mono }}
            />
            <button
              onClick={runScan}
              disabled={loading}
              style={{
                background: loading ? "transparent" : "rgba(153,69,255,0.15)",
                border: `1px solid ${loading ? C.border : C.purple}`,
                color: loading ? C.textMut : C.purple,
                borderRadius: 6, padding: "5px 16px",
                fontWeight: 600, fontSize: 12,
                cursor: loading ? "not-allowed" : "pointer",
                display: "flex", alignItems: "center", gap: 6,
                fontFamily: C.sans, whiteSpace: "nowrap",
                transition: "all 0.2s",
              }}
            >
              {loading ? (
                <>
                  <span style={{
                    display: "inline-block", width: 10, height: 10,
                    border: `1.5px solid ${C.purple}`, borderTopColor: "transparent",
                    borderRadius: "50%", animation: "spin 0.7s linear infinite",
                  }}/>
                  Analyzing
                </>
              ) : (
                <><IconSearch /> Analyze</>
              )}
            </button>
          </div>
        </div>
        <textarea
          value={code}
          onChange={e => setCode(e.target.value)}
          spellCheck={false}
          style={{
            display: "block", width: "100%",
            background: "#07080f",
            border: "none", borderTop: `1px solid ${C.border}`,
            color: "#c9d1d9",
            fontFamily: C.mono, fontSize: 12, lineHeight: 1.7,
            padding: "14px 16px", resize: "none", outline: "none",
            minHeight: 480, boxSizing: "border-box",
          }}
        />
      </div>

      {/* ── Right: results ── */}
      <div style={{ display: "flex", flexDirection: "column", gap: 12 }}>

        {/* Error */}
        {error && (
          <div style={{
            background: "rgba(239,68,68,0.07)", border: `1px solid rgba(239,68,68,0.25)`,
            borderLeft: `3px solid ${C.crit}`, borderRadius: 8,
            padding: 14, color: "#fca5a5", fontSize: 11,
            whiteSpace: "pre-wrap", fontFamily: C.mono, lineHeight: 1.6,
          }}>{error}</div>
        )}

        {/* Empty state */}
        {!result && !error && (
          <div style={{
            minHeight: 500, display: "flex", flexDirection: "column",
            alignItems: "center", justifyContent: "center", gap: 14,
            background: C.surface, border: `1px dashed ${C.border}`,
            borderRadius: 12,
          }}>
            <div style={{ opacity: 0.5 }}><IconShield size={32} /></div>
            <div style={{ fontSize: 13, color: C.textSec }}>Paste a contract and click Analyze</div>
            <div style={{ fontSize: 11, color: C.textMut }}>Supports Anchor · Native Solana · Rust</div>
          </div>
        )}

        {/* Result */}
        {result && (
          <>
            {/* Score card */}
            <div style={{
              background: C.surface, border: `1px solid ${C.border}`,
              borderRadius: 12, padding: "16px 18px",
              display: "flex", gap: 18, alignItems: "center",
            }}>
              <Ring score={result.risk_score} />
              <div style={{ flex: 1, minWidth: 0 }}>
                <div style={{ fontWeight: 700, fontSize: 15, color: C.textPri, marginBottom: 10, overflow: "hidden", textOverflow: "ellipsis", whiteSpace: "nowrap" }}>
                  {result.program_name}
                </div>
                <div style={{ display: "flex", gap: 6, flexWrap: "wrap", marginBottom: 12 }}>
                  {result.is_vulnerable ? (
                    <span style={{
                      background: "rgba(239,68,68,0.1)", color: C.crit,
                      border: "1px solid rgba(239,68,68,0.3)", borderRadius: 4,
                      padding: "3px 10px", fontSize: 10, fontWeight: 700, letterSpacing: 1,
                    }}>VULNERABLE</span>
                  ) : (
                    <span style={{
                      background: "rgba(20,241,149,0.08)", color: C.green,
                      border: "1px solid rgba(20,241,149,0.25)", borderRadius: 4,
                      padding: "3px 10px", fontSize: 10, fontWeight: 700, letterSpacing: 1,
                    }}>SECURE</span>
                  )}
                  {result.vuln_type && result.vuln_type !== "none" && (
                    <span style={{
                      background: "rgba(153,69,255,0.1)", color: C.purple,
                      border: "1px solid rgba(153,69,255,0.3)", borderRadius: 4,
                      padding: "3px 10px", fontSize: 10, letterSpacing: 0.5,
                    }}>{result.vuln_type.replace(/_/g, " ")}</span>
                  )}
                </div>
                <div style={{ display: "flex", gap: 20 }}>
                  <Chip label="Confidence" value={`${(result.confidence * 100).toFixed(1)}%`} color={C.textSec} />
                  <Chip label="Models" value={result.models_used?.join(" · ")} />
                  {elapsed && <Chip label="Time" value={`${elapsed}s`} />}
                </div>
                <div style={{ marginTop: 10, fontSize: 10, color: C.textMut, fontFamily: C.mono }}>
                  {result.scan_id}
                </div>
              </div>
            </div>

            {/* Findings */}
            {result.findings?.map((f, i) => {
              const s = SEV[f.severity] || SEV.Medium;
              return (
                <div key={i} style={{
                  background: s.bg, border: `1px solid ${s.border}`,
                  borderLeft: `3px solid ${s.color}`,
                  borderRadius: 8, padding: "14px 16px",
                }}>
                  <div style={{ display: "flex", justifyContent: "space-between", alignItems: "flex-start", marginBottom: 8, gap: 10 }}>
                    <span style={{ fontWeight: 600, fontSize: 13, color: C.textPri, display: "flex", alignItems: "center", gap: 7 }}>
                      <IconAlert color={s.color} />
                      {f.name}
                    </span>
                    <span style={{
                      color: s.color, fontWeight: 700, fontSize: 9, letterSpacing: 1.2,
                      background: "rgba(0,0,0,0.35)", padding: "3px 9px",
                      borderRadius: 3, border: `1px solid ${s.border}`,
                      textTransform: "uppercase", whiteSpace: "nowrap",
                    }}>{f.severity}</span>
                  </div>
                  <p style={{ fontSize: 12, color: C.textSec, lineHeight: 1.7, margin: 0 }}>{f.advice}</p>
                </div>
              );
            })}

            {result.is_vulnerable && result.findings?.length === 0 && (
              <div style={{
                background: "rgba(249,115,22,0.07)", border: `1px solid rgba(249,115,22,0.25)`,
                borderLeft: `3px solid ${C.high}`, borderRadius: 8, padding: "14px 16px",
                fontSize: 12, color: "#fdba74", lineHeight: 1.65,
              }}>
                Vulnerability pattern detected — specific type unidentified. Manual review recommended.
              </div>
            )}

            {/* Feedback */}
            <div style={{ background: C.surface, border: `1px solid ${C.border}`, borderRadius: 8, padding: "14px 16px" }}>
              <div style={{ fontSize: 9, color: C.textMut, letterSpacing: 1.5, textTransform: "uppercase", fontWeight: 600, marginBottom: 10 }}>
                Report False Positive
              </div>
              {fbSent ? (
                <div style={{ fontSize: 12, color: C.green, display: "flex", alignItems: "center", gap: 6 }}>
                  <IconCheck /> Feedback submitted — thank you.
                </div>
              ) : (
                <div style={{ display: "flex", gap: 8 }}>
                  <input
                    value={fbText}
                    onChange={e => setFbText(e.target.value)}
                    placeholder="Describe why this result is incorrect…"
                    style={{ ...field, flex: 1, fontSize: 12 }}
                  />
                  <button onClick={sendFeedback} style={{
                    ...field, padding: "8px 14px", cursor: "pointer",
                    fontWeight: 500, color: C.textSec, fontSize: 12,
                    whiteSpace: "nowrap",
                  }}>Submit</button>
                </div>
              )}
            </div>
          </>
        )}
      </div>
    </div>
  );
}

// ── Audit Log ─────────────────────────────────────────────────────────────────
function AuditLog({ refresh }) {
  const [entries, setEntries] = useState([]);
  const [loading, setLoading] = useState(true);

  useEffect(() => {
    setLoading(true);
    fetch(`${API}/leaderboard`)
      .then(r => r.json())
      .then(d => setEntries(d.entries || []))
      .catch(() => setEntries([]))
      .finally(() => setLoading(false));
  }, [refresh]);

  if (loading) return (
    <div style={{ padding: "60px 24px", textAlign: "center", fontFamily: C.mono, fontSize: 12, color: C.textMut }}>
      Loading records…
    </div>
  );

  if (!entries.length) return (
    <div style={{ padding: "80px 24px", textAlign: "center", color: C.textMut }}>
      <div style={{ fontSize: 13, color: C.textSec, marginBottom: 6 }}>No audit records yet</div>
      <div style={{ fontSize: 11 }}>Run a scan to populate the log</div>
    </div>
  );

  const cols = "44px 1fr 180px 70px 90px";
  const headerCell = { fontSize: 9, color: C.textMut, letterSpacing: 1.5, textTransform: "uppercase", fontWeight: 600 };

  return (
    <div>
      {/* Table header */}
      <div style={{
        display: "grid", gridTemplateColumns: cols,
        padding: "10px 20px", borderBottom: `1px solid ${C.border}`,
        gap: 12,
      }}>
        {["#", "Program", "Vulnerability", "Score", "Status"].map(h => (
          <span key={h} style={headerCell}>{h}</span>
        ))}
      </div>

      {entries.map((e, i) => {
        const rc = riskColor(e.risk_score);
        return (
          <div key={e.scan_id}
            style={{
              display: "grid", gridTemplateColumns: cols, gap: 12,
              padding: "14px 20px", borderBottom: `1px solid ${C.border}`,
              alignItems: "center", cursor: "default",
              transition: "background 0.15s",
            }}
            onMouseEnter={ev => ev.currentTarget.style.background = C.surface2}
            onMouseLeave={ev => ev.currentTarget.style.background = "transparent"}
          >
            <span style={{ fontFamily: C.mono, fontSize: 11, color: C.textMut }}>
              {String(i + 1).padStart(2, "0")}
            </span>
            <div style={{ minWidth: 0 }}>
              <div style={{ fontSize: 13, fontWeight: 600, color: C.textPri, overflow: "hidden", textOverflow: "ellipsis", whiteSpace: "nowrap" }}>
                {e.program_name}
              </div>
              <div style={{ fontSize: 10, color: C.textMut, marginTop: 2, fontFamily: C.mono }}>
                {new Date(e.scanned_at).toLocaleDateString("en-US", { month: "short", day: "numeric", year: "numeric" })}
              </div>
            </div>
            <span style={{ fontSize: 11, color: e.vuln_type !== "none" ? C.textSec : C.textMut, overflow: "hidden", textOverflow: "ellipsis", whiteSpace: "nowrap" }}>
              {e.vuln_type !== "none" ? e.vuln_type.replace(/_/g, " ") : "—"}
            </span>
            <span style={{ fontFamily: C.mono, fontWeight: 700, fontSize: 17, color: rc }}>
              {e.risk_score}
            </span>
            <span style={{ display: "flex", alignItems: "center", gap: 5, fontSize: 10, fontWeight: 700, letterSpacing: 0.8, textTransform: "uppercase", color: e.is_vulnerable ? C.crit : C.green }}>
              <span style={{ width: 5, height: 5, borderRadius: "50%", background: e.is_vulnerable ? C.crit : C.green, boxShadow: `0 0 5px ${e.is_vulnerable ? C.crit : C.green}` }}/>
              {e.is_vulnerable ? "Vuln" : "Safe"}
            </span>
          </div>
        );
      })}
    </div>
  );
}

// ── App ───────────────────────────────────────────────────────────────────────
export default function App() {
  const [tab, setTab] = useState("scanner");
  const [refresh, setRefresh] = useState(0);

  return (
    <div style={{
      minHeight: "100vh",
      background: C.bg,
      fontFamily: C.sans,
      color: C.textPri,
      backgroundImage: `
        radial-gradient(ellipse 60% 40% at 15% 15%, rgba(153,69,255,0.05) 0%, transparent 60%),
        radial-gradient(ellipse 50% 40% at 85% 85%, rgba(20,241,149,0.04) 0%, transparent 60%)
      `,
    }}>

      {/* ── Header ── */}
      <header style={{
        background: "rgba(12,14,26,0.85)",
        backdropFilter: "blur(16px)",
        borderBottom: `1px solid ${C.border}`,
        padding: "0 32px",
        display: "flex", alignItems: "center", height: 58,
        position: "sticky", top: 0, zIndex: 100,
      }}>
        <div style={{ display: "flex", alignItems: "center", gap: 10 }}>
          <IconShield size={22} />
          <div style={{ display: "flex", alignItems: "baseline", gap: 1 }}>
            <span style={{ fontWeight: 700, fontSize: 15, color: C.textPri, letterSpacing: 0.3 }}>Solana</span>
            <span style={{ fontWeight: 300, fontSize: 15, color: C.purple, letterSpacing: 0.3 }}>Auditor</span>
          </div>
          <div style={{
            marginLeft: 6, fontSize: 8, color: C.textMut,
            border: `1px solid ${C.border}`, borderRadius: 3,
            padding: "2px 6px", letterSpacing: 1.2, textTransform: "uppercase", fontFamily: C.mono,
          }}>v1.0</div>
        </div>

        <div style={{ flex: 1 }} />

        {/* Solana branding */}
        <div style={{ display: "flex", alignItems: "center", gap: 6, marginRight: 28, opacity: 0.6 }}>
          <IconSolana />
          <span style={{ fontSize: 10, color: C.textMut, letterSpacing: 0.5 }}>Powered by Solana</span>
        </div>

        <nav style={{ display: "flex" }}>
          {[["scanner", "Scanner"], ["log", "Audit Log"]].map(([id, label]) => (
            <button key={id} onClick={() => setTab(id)} style={{
              padding: "6px 18px",
              border: "none",
              borderBottom: tab === id ? `2px solid ${C.purple}` : "2px solid transparent",
              background: "transparent",
              color: tab === id ? C.purple : C.textMut,
              fontWeight: tab === id ? 600 : 400,
              fontSize: 13, cursor: "pointer",
              fontFamily: C.sans,
              transition: "all 0.2s",
              marginBottom: -1,
            }}>
              {label}
            </button>
          ))}
        </nav>
      </header>

      {/* ── Main ── */}
      <main style={{ maxWidth: 1240, margin: "0 auto", padding: "32px 28px" }}>

        {tab === "scanner" && (
          <>
            <div style={{ marginBottom: 28 }}>
              <h1 style={{ fontSize: 22, fontWeight: 700, color: C.textPri, margin: "0 0 6px" }}>
                Smart Contract Analyzer
              </h1>
              <p style={{ fontSize: 13, color: C.textSec, margin: 0, lineHeight: 1.6 }}>
                ML-powered vulnerability detection for Anchor and native Solana programs.&nbsp;
                <span style={{ color: C.textMut }}>Detects 9 vulnerability classes using XGBoost + CodeBERT ensemble.</span>
              </p>
            </div>
            <Scanner onScanDone={() => setRefresh(r => r + 1)} />
          </>
        )}

        {tab === "log" && (
          <>
            <div style={{ marginBottom: 28, display: "flex", alignItems: "center", gap: 12 }}>
              <div>
                <h1 style={{ fontSize: 22, fontWeight: 700, color: C.textPri, margin: "0 0 6px" }}>
                  Audit Log
                </h1>
                <p style={{ fontSize: 13, color: C.textSec, margin: 0 }}>
                  Public scan records ranked by risk score
                </p>
              </div>
              <div style={{ flex: 1 }} />
              <div style={{ display: "flex", alignItems: "center", gap: 6 }}>
                <span style={{ width: 6, height: 6, borderRadius: "50%", background: C.green, boxShadow: `0 0 7px ${C.green}`, display: "inline-block" }}/>
                <span style={{ fontSize: 10, color: C.textMut, letterSpacing: 1, textTransform: "uppercase" }}>Live</span>
              </div>
            </div>
            <div style={{ background: C.surface, border: `1px solid ${C.border}`, borderRadius: 12, overflow: "hidden" }}>
              <AuditLog refresh={refresh} />
            </div>
          </>
        )}
      </main>

      {/* ── Footer ── */}
      <footer style={{
        borderTop: `1px solid ${C.border}`,
        padding: "18px 32px",
        display: "flex", alignItems: "center", justifyContent: "space-between",
        marginTop: 40,
      }}>
        <span style={{ fontSize: 11, color: C.textMut }}>
          Solana Auditor — XGBoost + CodeBERT Ensemble
        </span>
        <span style={{ fontSize: 11, color: C.textMut, fontFamily: C.mono }}>
          Devnet
        </span>
      </footer>

      {/* ── Global styles ── */}
      <style>{`
        @keyframes spin { to { transform: rotate(360deg); } }
        * { box-sizing: border-box; }
        ::selection { background: rgba(153,69,255,0.3); color: #e8eaf6; }
        ::-webkit-scrollbar { width: 5px; height: 5px; }
        ::-webkit-scrollbar-track { background: transparent; }
        ::-webkit-scrollbar-thumb { background: ${C.border2}; border-radius: 4px; }
        ::-webkit-scrollbar-thumb:hover { background: #353860; }
        textarea, input, button { font-family: inherit; }
        textarea:focus, input:focus { border-color: ${C.border2} !important; outline: none; }
      `}</style>
    </div>
  );
}
