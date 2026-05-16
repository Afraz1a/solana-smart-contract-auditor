// frontend/src/App.jsx

import { useState, useEffect } from "react";

const API = "http://localhost:8000";

const SEV_COLOR = {
  Critical: { bg: "#fef2f2", border: "#fca5a5", text: "#dc2626" },
  High:     { bg: "#fff7ed", border: "#fdba74", text: "#ea580c" },
  Medium:   { bg: "#fefce8", border: "#fde047", text: "#ca8a04" },
};

function riskColor(score) {
  if (score >= 70) return "#dc2626";
  if (score >= 40) return "#ea580c";
  if (score >= 15) return "#ca8a04";
  return "#16a34a";
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

// ── Score ring ────────────────────────────────────────────────────────────────
function Ring({ score }) {
  const c = riskColor(score);
  const r = 42, cx = 50, cy = 50;
  const circ  = 2 * Math.PI * r;
  const offset = circ - (score / 100) * circ;
  return (
    <svg width={100} height={100} viewBox="0 0 100 100">
      <circle cx={cx} cy={cy} r={r} fill="none" stroke="#e5e7eb" strokeWidth={9}/>
      <circle cx={cx} cy={cy} r={r} fill="none" stroke={c} strokeWidth={9}
        strokeDasharray={circ} strokeDashoffset={offset} strokeLinecap="round"
        transform={`rotate(-90 ${cx} ${cy})`}/>
      <text x={cx} y={cy+2} textAnchor="middle" dominantBaseline="middle"
        style={{fontSize:20,fontWeight:700,fill:c,fontFamily:"monospace"}}>{score}</text>
      <text x={cx} y={cy+18} textAnchor="middle"
        style={{fontSize:9,fill:"#9ca3af",fontFamily:"sans-serif"}}>/100</text>
    </svg>
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

  async function runScan() {
    setLoading(true); setError(""); setResult(null); setFbSent(false);
    try {
      const res = await fetch(`${API}/scan`, {
        method: "POST",
        headers: { "Content-Type": "application/json" },
        body: JSON.stringify({ source_code: code, program_name: name, public: true }),
      });
      if (!res.ok) throw new Error(await res.text());
      const data = await res.json();
      setResult(data);
      if (onScanDone) onScanDone();
    } catch (e) {
      setError(`Cannot reach API. Make sure the server is running on port 8000.\n\n${e.message}`);
    } finally {
      setLoading(false);
    }
  }

  async function sendFeedback() {
    if (!result || !fbText.trim()) return;
    await fetch(`${API}/feedback`, {
      method: "POST",
      headers: { "Content-Type": "application/json" },
      body: JSON.stringify({
        scan_id:   result.scan_id,
        vuln_type: result.vuln_type,
        reason:    fbText,
      }),
    });
    setFbSent(true);
  }

  return (
    <div style={{display:"flex",gap:18}}>
      {/* Left: input */}
      <div style={{flex:1,display:"flex",flexDirection:"column",gap:10}}>
        <div style={{display:"flex",gap:8,alignItems:"center"}}>
          <input value={name} onChange={e=>setName(e.target.value)}
            placeholder="Program name"
            style={{padding:"7px 12px",border:"1px solid #d1d5db",borderRadius:6,
              fontSize:13,width:180,outline:"none",fontFamily:"inherit"}}/>
          <button onClick={runScan} disabled={loading}
            style={{padding:"7px 22px",background:loading?"#9ca3af":"#1d4ed8",
              color:"#fff",border:"none",borderRadius:6,fontWeight:600,
              fontSize:13,cursor:loading?"not-allowed":"pointer"}}>
            {loading ? "Scanning…" : "▶  Scan"}
          </button>
        </div>
        <textarea value={code} onChange={e=>setCode(e.target.value)} spellCheck={false}
          style={{flex:1,minHeight:460,fontFamily:"monospace",fontSize:12,lineHeight:1.6,
            padding:14,border:"1px solid #d1d5db",borderRadius:8,background:"#f8fafc",
            resize:"none",outline:"none",boxSizing:"border-box"}}/>
      </div>

      {/* Right: results */}
      <div style={{flex:1,display:"flex",flexDirection:"column",gap:12}}>
        {error && (
          <div style={{background:"#fef2f2",border:"1px solid #fca5a5",borderRadius:8,
            padding:14,color:"#dc2626",fontSize:12,whiteSpace:"pre-wrap"}}>{error}</div>
        )}

        {!result && !error && (
          <div style={{flex:1,display:"flex",flexDirection:"column",alignItems:"center",
            justifyContent:"center",border:"1px dashed #d1d5db",borderRadius:10,
            color:"#9ca3af",gap:8,minHeight:460}}>
            <span style={{fontSize:36}}>🔍</span>
            <span style={{fontSize:14}}>Paste your contract and click Scan</span>
          </div>
        )}

        {result && (
          <>
            {/* Score card */}
            <div style={{display:"flex",gap:16,alignItems:"center",
              background:"#f9fafb",border:"1px solid #e5e7eb",borderRadius:10,padding:16}}>
              <Ring score={result.risk_score}/>
              <div style={{flex:1}}>
                <div style={{fontWeight:700,fontSize:15,marginBottom:6}}>
                  {result.program_name}
                </div>
                <div style={{display:"flex",gap:8,flexWrap:"wrap",marginBottom:8}}>
                  {result.is_vulnerable ? (
                    <span style={{background:"#fef2f2",color:"#dc2626",
                      border:"1px solid #fca5a5",borderRadius:20,
                      padding:"2px 12px",fontSize:12,fontWeight:600}}>
                      ⚠ Vulnerable
                    </span>
                  ) : (
                    <span style={{background:"#f0fdf4",color:"#16a34a",
                      border:"1px solid #86efac",borderRadius:20,
                      padding:"2px 12px",fontSize:12,fontWeight:600}}>
                      ✅ Safe
                    </span>
                  )}
                  {result.vuln_type && result.vuln_type !== "none" && (
                    <span style={{background:"#eff6ff",color:"#1d4ed8",
                      border:"1px solid #bfdbfe",borderRadius:20,
                      padding:"2px 12px",fontSize:12}}>
                      {result.vuln_type.replace(/_/g," ")}
                    </span>
                  )}
                </div>
                <div style={{fontSize:11,color:"#9ca3af"}}>
                  Confidence: {(result.confidence*100).toFixed(1)}%
                  &nbsp;·&nbsp;
                  Models: {result.models_used?.join(" + ")}
                  &nbsp;·&nbsp;
                  ID: {result.scan_id}
                </div>
              </div>
            </div>

            {/* Findings */}
            {result.findings?.map((f,i) => {
              const s = SEV_COLOR[f.severity] || SEV_COLOR.Medium;
              return (
                <div key={i} style={{background:s.bg,border:`1px solid ${s.border}`,
                  borderLeft:`3px solid ${s.text}`,borderRadius:8,padding:14}}>
                  <div style={{display:"flex",justifyContent:"space-between",marginBottom:6}}>
                    <span style={{fontWeight:600,fontSize:14}}>{f.name}</span>
                    <span style={{color:s.text,fontWeight:700,fontSize:12,
                      background:"#fff",padding:"2px 10px",borderRadius:12,
                      border:`1px solid ${s.border}`}}>{f.severity}</span>
                  </div>
                  <div style={{fontSize:13,color:"#374151",lineHeight:1.6}}>
                    💡 {f.advice}
                  </div>
                </div>
              );
            })}

            {/* No findings but flagged */}
            {result.is_vulnerable && result.findings?.length === 0 && (
              <div style={{background:"#fff7ed",border:"1px solid #fdba74",
                borderRadius:8,padding:14,fontSize:13,color:"#92400e"}}>
                ⚠ The model thinks this contract is vulnerable but could not identify the specific issue. Manual review is recommended.
              </div>
            )}

            {/* Feedback */}
            <div style={{background:"#fff",border:"1px solid #e5e7eb",
              borderRadius:8,padding:14}}>
              <div style={{fontSize:12,fontWeight:600,color:"#6b7280",marginBottom:8}}>
                Think the result is wrong? Flag it:
              </div>
              {fbSent ? (
                <div style={{color:"#16a34a",fontSize:13}}>✅ Feedback submitted. Thank you!</div>
              ) : (
                <div style={{display:"flex",gap:8}}>
                  <input value={fbText} onChange={e=>setFbText(e.target.value)}
                    placeholder="Explain why this result is incorrect…"
                    style={{flex:1,padding:"7px 12px",border:"1px solid #d1d5db",
                      borderRadius:6,fontSize:12,outline:"none",fontFamily:"inherit"}}/>
                  <button onClick={sendFeedback}
                    style={{padding:"7px 16px",background:"#f3f4f6",
                      border:"1px solid #d1d5db",borderRadius:6,
                      cursor:"pointer",fontSize:12,fontWeight:500}}>
                    Submit
                  </button>
                </div>
              )}
            </div>
          </>
        )}
      </div>
    </div>
  );
}

// ── Leaderboard ───────────────────────────────────────────────────────────────
function Leaderboard({ refresh }) {
  const [entries,  setEntries]  = useState([]);
  const [loading,  setLoading]  = useState(true);

  useEffect(() => {
    setLoading(true);
    fetch(`${API}/leaderboard`)
      .then(r => r.json())
      .then(d => setEntries(d.entries || []))
      .catch(() => setEntries([]))
      .finally(() => setLoading(false));
  }, [refresh]);

  if (loading) return <p style={{color:"#9ca3af",textAlign:"center",padding:40}}>Loading…</p>;
  if (!entries.length) return (
    <div style={{textAlign:"center",color:"#9ca3af",padding:60}}>
      <div style={{fontSize:36,marginBottom:12}}>📋</div>
      No scans yet. Run a scan to see it here.
    </div>
  );

  const medals = ["🥇","🥈","🥉"];
  return (
    <div>
      <p style={{color:"#6b7280",fontSize:13,marginBottom:14}}>
        {entries.length} contract{entries.length!==1?"s":""} scanned publicly
      </p>
      <div style={{display:"flex",flexDirection:"column",gap:8}}>
        {entries.map((e,i) => {
          const c = riskColor(e.risk_score);
          return (
            <div key={e.scan_id} style={{display:"flex",alignItems:"center",gap:14,
              background:"#fff",border:"1px solid #e5e7eb",borderRadius:10,padding:"12px 16px"}}>
              <span style={{fontSize:18,minWidth:28}}>{medals[i]||`#${i+1}`}</span>
              <div style={{flex:1}}>
                <div style={{fontWeight:600,fontSize:14}}>{e.program_name}</div>
                <div style={{fontSize:11,color:"#9ca3af",marginTop:2}}>
                  {e.vuln_type !== "none" ? e.vuln_type.replace(/_/g," ") : "safe"}
                  &nbsp;·&nbsp;
                  {new Date(e.scanned_at).toLocaleDateString()}
                </div>
              </div>
              <span style={{
                background: e.is_vulnerable ? "#fef2f2" : "#f0fdf4",
                color:      e.is_vulnerable ? "#dc2626"  : "#16a34a",
                border:     `1px solid ${e.is_vulnerable ? "#fca5a5" : "#86efac"}`,
                borderRadius:20,padding:"2px 10px",fontSize:11,fontWeight:600,
              }}>
                {e.is_vulnerable ? "Vulnerable" : "Safe"}
              </span>
              <span style={{fontWeight:700,fontSize:18,fontFamily:"monospace",
                color:c,minWidth:36,textAlign:"right"}}>
                {e.risk_score}
              </span>
            </div>
          );
        })}
      </div>
    </div>
  );
}

// ── App ───────────────────────────────────────────────────────────────────────
export default function App() {
  const [tab,     setTab]     = useState("scanner");
  const [refresh, setRefresh] = useState(0);

  return (
    <div style={{minHeight:"100vh",background:"#f3f4f6",
      fontFamily:"Inter,system-ui,sans-serif"}}>

      {/* Header */}
      <div style={{background:"#fff",borderBottom:"1px solid #e5e7eb",
        padding:"0 32px",display:"flex",alignItems:"center",height:54,gap:16}}>
        <div style={{fontWeight:800,fontSize:17,color:"#1e40af"}}>🛡️ SolanaAuditor</div>
        <div style={{flex:1}}/>
        {[["scanner","🔍 Scanner"],["leaderboard","🏆 Leaderboard"]].map(([id,label])=>(
          <button key={id} onClick={()=>setTab(id)}
            style={{padding:"6px 16px",border:"none",borderRadius:6,
              background:tab===id?"#eff6ff":"transparent",
              color:tab===id?"#1d4ed8":"#6b7280",
              fontWeight:tab===id?600:400,fontSize:13,cursor:"pointer"}}>
            {label}
          </button>
        ))}
      </div>

      {/* Content */}
      <div style={{maxWidth:1100,margin:"0 auto",padding:24}}>
        {tab==="scanner" && (
          <Scanner onScanDone={()=>setRefresh(r=>r+1)}/>
        )}
        {tab==="leaderboard" && (
          <Leaderboard refresh={refresh}/>
        )}
      </div>
    </div>
  );
}
