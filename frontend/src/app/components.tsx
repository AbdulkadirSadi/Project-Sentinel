'use client'
import { useEffect, useState, useRef, useCallback } from 'react'
import { AreaChart, Area, XAxis, YAxis, Tooltip, ResponsiveContainer, PieChart, Pie, Cell, BarChart, Bar } from 'recharts'

/* ── Types ─────────────────────────────────────────────────────────────────── */
export interface Agent { id: string; os: string; addr: string; cpu?: number; ram_pct?: number; calibrated?: boolean; calib_start?: number; last_seen?: number; offline?: boolean }
export interface Alert { id: number; agent_id: string; ts: number; risk_score: number; threat_type: string; confidence: number; action_taken: string; resolved: boolean; pname?: string; pid?: number; rule_name?: string; file_path?: string }
export interface MetricPoint { time: string; cpu: number; ram: number }
export interface ProcessNode { pname: string; pid: number; ppid: number; exe_path?: string; username?: string; cmdline?: string; ts: number }

/* ── Helpers ────────────────────────────────────────────────────────────────── */
export const fmt    = (ts: number) => new Date(ts * 1000).toLocaleTimeString('tr-TR', { hour:'2-digit', minute:'2-digit', second:'2-digit' })
export const ago    = (ts: number) => { const s = Math.floor(Date.now()/1000 - ts); return s < 60 ? `${s}s önce` : `${Math.floor(s/60)}dk önce` }
export const shortId = (id: string) => id.length > 16 ? id.slice(0,8)+'…'+id.slice(-4) : id
export const osIcon  = (os: string) => os === 'windows' ? '🪟' : '🐧'
export const scoreColor = (s: number) => s >= 90 ? 'var(--red)' : s >= 70 ? 'var(--orange)' : 'var(--yellow)'
export const alertCls   = (s: number) => s >= 90 ? 'critical' : s >= 70 ? 'high' : 'medium'
export const PIE_COLORS = ['#ff4466','#ff9940','#00d4ff','#00ff88','#a78bfa','#ffd700','#fb7185','#34d399']

/* ── Sidebar ────────────────────────────────────────────────────────────────── */
export function Sidebar({ active, onNav, serverOk, aiOk, authUser, authRole, onLogout }: {
  active: string; onNav:(p:string)=>void; serverOk:boolean; aiOk:boolean;
  authUser?:string|null; authRole?:string|null; onLogout?:()=>void
}) {
  const items = [
    { id:'dashboard', icon:'◈', label:'Dashboard' },
    { id:'agents',    icon:'⬡', label:'Agents' },
    { id:'alerts',    icon:'⚡', label:'Alerts' },
    { id:'scan',      icon:'🔎', label:'Scanner' },
    { id:'rules',     icon:'⚙', label:'Rules' },
    { id:'yara',      icon:'🔬', label:'YARA Kuralları' },
    { id:'terminal',  icon:'⌨', label:'Terminal' },
    { id:'threats',   icon:'🧬', label:'Threat Intel' },
  ]
  return (
    <aside className="sidebar">
      <div className="sidebar-logo">
        <svg width="22" height="22" viewBox="0 0 24 24" fill="none" stroke="currentColor" strokeWidth="2">
          <path d="M12 22s8-4 8-10V5l-8-3-8 3v7c0 6 8 10 8 10z"/>
        </svg>
        <div><h1>SENTINEL</h1><span>XDR PLATFORM</span></div>
      </div>
      <nav className="sidebar-nav">
        {items.map(n => (
          <a key={n.id} className={`nav-item${active===n.id?' active':''}`} onClick={()=>onNav(n.id)}>
            <span style={{fontSize:15}}>{n.icon}</span>{n.label}
          </a>
        ))}
      </nav>
      <div className="sidebar-footer">
        <div className="status-dot"><div className={`dot${serverOk?'':' offline'}`}/> C2 Server</div>
        <div className="status-dot" style={{marginTop:6}}><div className={`dot${aiOk?'':' offline'}`}/> AI Engine</div>
        {authUser && (
          <div style={{marginTop:14, paddingTop:12, borderTop:'1px solid var(--border)'}}>
            <div style={{display:'flex', alignItems:'center', gap:8, marginBottom:8}}>
              <div style={{
                width:28, height:28, borderRadius:'50%',
                background:'linear-gradient(135deg,#6366f1,#8b5cf6)',
                display:'flex', alignItems:'center', justifyContent:'center',
                fontSize:12, fontWeight:700, color:'#fff', flexShrink:0
              }}>{authUser[0].toUpperCase()}</div>
              <div style={{flex:1, minWidth:0}}>
                <div style={{fontSize:12, fontWeight:600, color:'var(--text)', overflow:'hidden', textOverflow:'ellipsis', whiteSpace:'nowrap'}}>{authUser}</div>
                <div style={{fontSize:10, color:'var(--accent)', textTransform:'uppercase', letterSpacing:'0.5px'}}>{authRole}</div>
              </div>
            </div>
            {onLogout && (
              <button onClick={onLogout} style={{
                width:'100%', padding:'6px', borderRadius:6, border:'1px solid var(--border)',
                background:'transparent', color:'var(--text-muted)', fontSize:11,
                cursor:'pointer', transition:'all .2s'
              }}
              onMouseOver={e=>(e.currentTarget.style.background='rgba(239,68,68,0.12)',e.currentTarget.style.color='var(--red)',e.currentTarget.style.borderColor='rgba(239,68,68,0.3)')}
              onMouseOut={e=>(e.currentTarget.style.background='transparent',e.currentTarget.style.color='var(--text-muted)',e.currentTarget.style.borderColor='var(--border)')}
              >⏻ Çıkış Yap</button>
            )}
          </div>
        )}
      </div>
    </aside>
  )
}

/* ── Toast ──────────────────────────────────────────────────────────────────── */
export function Toast({ msg, type }: { msg:string; type:'success'|'error' }) {
  return <div className={`toast ${type}`}>{type==='success'?'✓ ':'✗ '}{msg}</div>
}

/* ── Process Tree Modal ─────────────────────────────────────────────────────── */
export function ProcessTreeModal({ agentId, pid, pname, onClose }: { agentId:string; pid:number; pname:string; onClose:()=>void }) {
  const [tree,    setTree]    = useState<ProcessNode[]>([])
  const [loading, setLoading] = useState(true)
  const [hovered, setHovered] = useState<number|null>(null)

  useEffect(() => {
    fetch(`/api/ai/process-tree/${agentId}/${pid}`)
      .then(r => r.ok ? r.json() : null)
      .then(d => { if (d?.tree) setTree(d.tree) })
      .finally(() => setLoading(false))
  }, [agentId, pid])

  /* ── 3D Küp ikonu (Elastic tarzı) ── */
  const Cube3D = ({ isTarget=false, isAlert=false, size=36 }: {isTarget?:boolean;isAlert?:boolean;size?:number}) => {
    const top  = isTarget ? '#fca5a5' : isAlert ? '#fdba74' : '#99f6e4'
    const mid  = isTarget ? '#f87171' : isAlert ? '#fb923c' : '#2dd4bf'
    const drk  = isTarget ? '#dc2626' : isAlert ? '#ea580c' : '#0d9488'
    const glow = isTarget ? 'rgba(248,113,113,0.5)' : isAlert ? 'rgba(251,146,60,0.4)' : 'rgba(45,212,191,0.3)'
    return (
      <svg width={size} height={size} viewBox="0 0 40 40"
        style={{flexShrink:0, filter:`drop-shadow(0 0 6px ${glow})`}}>
        <polygon points="20,3 37,12 20,21 3,12"  fill={top} opacity="0.95"/>
        <polygon points="3,12 20,21 20,37 3,28"  fill={mid}/>
        <polygon points="37,12 20,21 20,37 37,28" fill={drk}/>
      </svg>
    )
  }

  const isSuspicious = (name='') => {
    const s = ['mimikatz','nc.exe','ncat','mshta','wscript','cscript','regsvr32','psexec','rundll32']
    return s.some(x => name.toLowerCase().includes(x))
  }

  const timeDiff = (a: number, b: number) => {
    const ms = Math.abs(b - a) * 1000
    if (ms < 1000)  return `${ms.toFixed(0)} ms`
    if (ms < 60000) return `${(ms/1000).toFixed(1)} sn`
    return `${(ms/60000).toFixed(1)} dk`
  }

  const statusLabel = (node: ProcessNode) => {
    if (node.pid === pid) return 'ANALİZ EDİLEN EVENT'
    return 'PROCESS'
  }

  /* Node boyutu ve diyagonal adım */
  const NW=210, NH=108, DX=165, DY=128, PAD=24
  const svgW = PAD + tree.length * DX + NW + PAD
  const svgH = PAD + tree.length * DY + NH + PAD

  return (
    <div className="modal-overlay" onClick={onClose}>
      <div className="modal" onClick={e=>e.stopPropagation()}
        style={{width:'92vw',maxWidth:980,maxHeight:'90vh',padding:0,
                display:'flex',flexDirection:'column',overflow:'hidden'}}>

        {/* Başlık */}
        <div style={{display:'flex',alignItems:'center',gap:10,padding:'12px 18px',
                     borderBottom:'1px solid var(--border)',flexShrink:0}}>
          <Cube3D size={24} isAlert/>
          <div>
            <span style={{fontWeight:700,fontSize:14,color:'var(--text)'}}>Process Analyzer</span>
            <span style={{color:'var(--accent)',fontSize:11,marginLeft:10,fontFamily:'monospace'}}>{pname}</span>
            <span style={{color:'var(--text-dim)',fontSize:11,marginLeft:6,fontFamily:'monospace'}}>PID:{pid}</span>
          </div>
          <button onClick={onClose} style={{marginLeft:'auto',background:'none',
            border:'1px solid var(--border)',color:'var(--text-muted)',
            borderRadius:6,padding:'3px 10px',cursor:'pointer',fontSize:12}}>✕</button>
        </div>

        <div style={{display:'flex',flex:1,overflow:'hidden',minHeight:0}}>

          {/* ══ SOL: Grafik alanı ══ */}
          <div style={{flex:1,overflow:'auto',background:'var(--bg)',position:'relative'}}>

            {loading && (
              <div style={{display:'flex',alignItems:'center',justifyContent:'center',
                           height:'100%',flexDirection:'column',gap:12}}>
                <div className="spinner"/><span style={{color:'var(--text-muted)',fontSize:12}}>Yükleniyor…</span>
              </div>
            )}
            {!loading && tree.length === 0 && (
              <div style={{display:'flex',alignItems:'center',justifyContent:'center',
                           height:'100%',flexDirection:'column',gap:8}}>
                <span style={{fontSize:36}}>🔍</span>
                <span style={{color:'var(--text-muted)',fontSize:13}}>Process kaydı bulunamadı</span>
                <span style={{color:'var(--text-dim)',fontSize:11}}>Veri henüz biriktirilmemiş olabilir</span>
              </div>
            )}
            {!loading && tree.length > 0 && (
              <div style={{position:'relative',width:svgW,height:svgH,minWidth:'100%',minHeight:'100%'}}>

                {/* SVG bağlantı çizgileri + süre etiketleri */}
                <svg style={{position:'absolute',inset:0,width:'100%',height:'100%',pointerEvents:'none'}} overflow="visible">
                  <defs>
                    <marker id="tip" markerWidth="7" markerHeight="5" refX="5" refY="2.5" orient="auto">
                      <polygon points="0 0,7 2.5,0 5" fill="rgba(45,212,191,0.35)"/>
                    </marker>
                  </defs>
                  {tree.slice(0,-1).map((_,i) => {
                    const x1 = PAD + i*DX + NW/2
                    const y1 = PAD + i*DY + NH - 4
                    const x2 = PAD + (i+1)*DX + NW/2 - 28
                    const y2 = PAD + (i+1)*DY + 16
                    const mx=(x1+x2)/2, my=(y1+y2)/2
                    const dt = (tree[i]?.ts && tree[i+1]?.ts) ? timeDiff(tree[i].ts, tree[i+1].ts) : ''
                    return (
                      <g key={i}>
                        <line x1={x1} y1={y1} x2={x2} y2={y2}
                          stroke="rgba(45,212,191,0.2)" strokeWidth="1.5"
                          strokeDasharray="7 4" markerEnd="url(#tip)"/>
                        {dt && <>
                          <rect x={mx-22} y={my-9} width={44} height={14}
                            rx="4" fill="rgba(13,20,30,0.75)" stroke="rgba(45,212,191,0.15)" strokeWidth="1"/>
                          <text x={mx} y={my+2} fill="rgba(45,212,191,0.6)" fontSize="9"
                            fontFamily="monospace" textAnchor="middle">{dt}</text>
                        </>}
                      </g>
                    )
                  })}
                </svg>

                {/* Process node kartları */}
                {tree.map((node,i) => {
                  const isTarget = node.pid === pid
                  const isSus    = isSuspicious(node.pname)
                  const isHov    = hovered === node.pid
                  const left     = PAD + i * DX
                  const top      = PAD + i * DY
                  const nameClr  = isTarget ? '#f87171' : isSus ? '#fb923c' : 'var(--accent)'
                  return (
                    <div key={node.pid}
                      onMouseEnter={()=>setHovered(node.pid)}
                      onMouseLeave={()=>setHovered(null)}
                      style={{
                        position:'absolute', left, top, width:NW,
                        background: isTarget ? 'rgba(239,68,68,0.06)' : 'var(--bg-card)',
                        border:`1.5px solid ${isTarget?'#ef4444':isHov?'rgba(45,212,191,0.5)':'var(--border)'}`,
                        borderRadius:10, padding:'10px 12px',
                        boxShadow: isTarget
                          ? '0 0 20px rgba(239,68,68,0.18),0 4px 16px rgba(0,0,0,0.4)'
                          : isHov ? '0 0 12px rgba(45,212,191,0.12),0 4px 16px rgba(0,0,0,0.4)'
                                  : '0 4px 12px rgba(0,0,0,0.35)',
                        transition:'all .18s', cursor:'default',
                      }}>

                      {/* Durum etiketi */}
                      <div style={{fontSize:8,fontWeight:700,letterSpacing:'0.06em',
                                   color: isTarget?'#f87171':'var(--text-dim)',marginBottom:7}}>
                        {statusLabel(node)}
                      </div>

                      {/* Küp + isim */}
                      <div style={{display:'flex',alignItems:'center',gap:9}}>
                        <Cube3D size={34} isTarget={isTarget} isAlert={isSus}/>
                        <div style={{minWidth:0}}>
                          <div style={{fontFamily:'monospace',fontSize:12,fontWeight:700,
                                       color:nameClr,overflow:'hidden',textOverflow:'ellipsis',
                                       whiteSpace:'nowrap',maxWidth:130}}>
                            {node.pname || 'unknown'}
                          </div>
                          <div style={{fontSize:9,color:'var(--text-dim)',marginTop:2,fontFamily:'monospace'}}>
                            PID:{node.pid}{node.ppid?` · PPID:${node.ppid}`:''}
                          </div>
                        </div>
                      </div>

                      {/* Badge satırı */}
                      <div style={{display:'flex',gap:4,marginTop:8,flexWrap:'wrap'}}>
                        {node.username && (
                          <span style={{fontSize:8,padding:'2px 5px',borderRadius:3,
                            background:'rgba(45,212,191,0.08)',color:'var(--accent)',
                            border:'1px solid rgba(45,212,191,0.2)'}}>
                            👤 {node.username}
                          </span>
                        )}
                        {isTarget && (
                          <span style={{fontSize:8,padding:'2px 5px',borderRadius:3,
                            background:'rgba(239,68,68,0.12)',color:'#f87171',
                            border:'1px solid rgba(239,68,68,0.3)',fontWeight:700}}>
                            ⚠ HEDEF
                          </span>
                        )}
                        {isSus && !isTarget && (
                          <span style={{fontSize:8,padding:'2px 5px',borderRadius:3,
                            background:'rgba(251,146,60,0.1)',color:'#fb923c',
                            border:'1px solid rgba(251,146,60,0.25)'}}>
                            ⚡ ŞÜPHELİ
                          </span>
                        )}
                      </div>

                      {/* Hover: exe path */}
                      {isHov && node.exe_path && (
                        <div style={{marginTop:6,fontSize:8,color:'var(--text-dim)',fontFamily:'monospace',
                          wordBreak:'break-all',padding:'3px 6px',borderRadius:4,lineHeight:1.5,
                          background:'var(--bg)',border:'1px solid var(--border)'}}>
                          📁 {node.exe_path}
                        </div>
                      )}
                      {isHov && node.cmdline && node.cmdline !== node.exe_path && (
                        <div style={{marginTop:3,fontSize:8,color:'rgba(255,200,80,0.8)',fontFamily:'monospace',
                          wordBreak:'break-all',padding:'3px 6px',borderRadius:4,lineHeight:1.5,
                          background:'rgba(255,165,0,0.04)',border:'1px solid rgba(255,165,0,0.12)'}}>
                          $ {node.cmdline}
                        </div>
                      )}
                    </div>
                  )
                })}
              </div>
            )}
          </div>

          {/* ══ SAĞ: Event listesi ══ */}
          <div style={{width:250,borderLeft:'1px solid var(--border)',display:'flex',
                       flexDirection:'column',flexShrink:0,background:'var(--bg-card)'}}>
            <div style={{padding:'10px 14px',borderBottom:'1px solid var(--border)',
                         fontSize:10,fontWeight:700,color:'var(--text-muted)',letterSpacing:'0.05em'}}>
              TÜM PROCESS EVENT'LERİ
            </div>
            <div style={{overflowY:'auto',flex:1}}>
              {!loading && tree.map(node => {
                const isTarget = node.pid === pid
                const isSus    = isSuspicious(node.pname)
                const isHov    = hovered === node.pid
                return (
                  <div key={node.pid}
                    onMouseEnter={()=>setHovered(node.pid)}
                    onMouseLeave={()=>setHovered(null)}
                    style={{
                      display:'flex',alignItems:'center',gap:9,
                      padding:'9px 14px',borderBottom:'1px solid var(--border)',
                      background: isHov ? 'rgba(45,212,191,0.04)' : 'transparent',
                      transition:'background .15s',cursor:'default',
                    }}>
                    <Cube3D size={18} isTarget={isTarget} isAlert={isSus}/>
                    <div style={{flex:1,minWidth:0}}>
                      <div style={{
                        fontFamily:'monospace',fontSize:11,fontWeight:600,
                        color: isTarget?'#f87171':isSus?'#fb923c':'var(--accent)',
                        overflow:'hidden',textOverflow:'ellipsis',whiteSpace:'nowrap',
                      }}>{node.pname}</div>
                      {node.ts ? (
                        <div style={{fontSize:9,color:'var(--text-dim)',marginTop:1,fontFamily:'monospace'}}>
                          {new Date(node.ts*1000).toLocaleTimeString('tr-TR',
                            {hour:'2-digit',minute:'2-digit',second:'2-digit'})}
                        </div>
                      ) : null}
                    </div>
                    {isTarget && <span style={{fontSize:10,color:'#f87171'}}>●</span>}
                  </div>
                )
              })}
            </div>
          </div>

        </div>
      </div>
    </div>
  )
}

/* ── Action Modal ───────────────────────────────────────────────────────────── */
export function ActionModal({ agent, onClose, onSend }: { agent:Agent; onClose:()=>void; onSend:(a:string,p:Record<string,string>)=>void }) {
  const [action, setAction] = useState('kill_process')
  const [param, setParam]   = useState('')
  const actions = [
    { value:'kill_process',    label:'Kill Process',    placeholder:'PID (örn: 1234)', key:'pid'  },
    { value:'block_ip',        label:'Block IP',        placeholder:'1.2.3.4',         key:'ip'   },
    { value:'isolate_network', label:'Isolate Network', placeholder:'1.2.3.4',         key:'ip'   },
    { value:'unblock_ip',      label:'Unblock IP',      placeholder:'1.2.3.4',         key:'ip'   },
    { value:'quarantine_file', label:'Quarantine File', placeholder:'Dosya tam yolu',   key:'path' },
  ]
  const cur = actions.find(a=>a.value===action)!
  const send = () => { if (!param.trim()) return; onSend(action, {[cur.key]: param.trim()}); onClose() }
  return (
    <div className="modal-overlay" onClick={onClose}>
      <div className="modal" onClick={e=>e.stopPropagation()}>
        <h3>Ajan Eylemi — <span style={{color:'var(--accent)',fontFamily:'monospace',fontSize:12}}>{shortId(agent.id)}</span></h3>
        <div className="modal-field">
          <label>Eylem</label>
          <select value={action} onChange={e=>{setAction(e.target.value);setParam('')}}>
            {actions.map(a=><option key={a.value} value={a.value}>{a.label}</option>)}
          </select>
        </div>
        <div className="modal-field">
          <label>Parametre</label>
          <input value={param} onChange={e=>setParam(e.target.value)} placeholder={cur.placeholder} onKeyDown={e=>e.key==='Enter'&&send()}/>
        </div>
        <div className="modal-actions">
          <button className="btn-secondary" onClick={onClose}>İptal</button>
          <button className="btn-primary"   onClick={send}>Gönder</button>
        </div>
      </div>
    </div>
  )
}

/* ── Scan Page ────────────────────────────────────────────────────────── */
interface FileScan {
  id:number; agent_id:string; file_name:string; file_hash:string; file_size:number
  threat_type:string; risk_score:number; confidence:number; is_malware:boolean; ts:number
  vt_positives?:number|null; vt_total?:number|null; vt_label?:string|null; vt_permalink?:string|null
  yara_matches?:string|null
}

export function ScanPage() {
  const [scans,       setScans]       = useState<FileScan[]>([])
  const [scanning,    setScanning]    = useState(false)
  const [categorizing,setCategorizing]= useState(false)
  const [result,      setResult]      = useState<any>(null)
  const [dragOver,    setDragOver]    = useState(false)
  const [malOnly,     setMalOnly]     = useState(false)
  const [toast,       setToast]       = useState<{msg:string;type:'success'|'error'}|null>(null)
  const fileRef = useRef<HTMLInputElement>(null)

  const showMsg = (msg:string, type:'success'|'error'='success') => {
    setToast({msg,type}); setTimeout(()=>setToast(null),4000)
  }

  const loadScans = useCallback(async () => {
    const r = await fetch(`/api/ai/scans?limit=100&malware_only=${malOnly}`)
    if (r.ok) setScans(await r.json())
  }, [malOnly])

  useEffect(()=>{ loadScans() },[loadScans])

  // Dosyayı binary triage ile analiz et (Aşama 1)
  const analyzeFile = async (file: File) => {
    if (!file) return
    setScanning(true); setResult(null)
    try {
      const b64 = await new Promise<string>((res, rej) => {
        const reader = new FileReader();
        reader.readAsDataURL(file);
        reader.onload = () => {
          const str = reader.result as string;
          res(str.includes(',') ? str.split(',')[1] : str);
        };
        reader.onerror = e => rej(e);
      });
      const aiUrl = `${window.location.protocol}//${window.location.hostname}:8000/analyze/static`;
      const r = await fetch(aiUrl, {
        method: 'POST',
        headers: {'Content-Type':'application/json'},
        body: JSON.stringify({ agent_id:'manual', exe_b64:b64, file_name:file.name, categorize:false })
      })
      if (!r.ok) { const e=await r.json(); showMsg(e.detail||'Analiz hatası','error'); return }
      const data = await r.json()
      // b64'ü result'a ekle — kategorize butonu için lazım
      setResult({...data, file_name:file.name, file_size:file.size, _b64:b64})
      showMsg(data.is_malware ? '⚠ Zararlı tespit edildi!' : '✓ Dosya temiz', data.is_malware?'error':'success')
      loadScans()
    } catch { showMsg('Bağlantı hatası veya dosya çok büyük','error') }
    finally { setScanning(false) }
  }

  // Kategorize Et (Aşama 2) — sadece zararlı bulunursa çağrılır
  const categorizeFile = async () => {
    if (!result?._b64) return
    setCategorizing(true)
    try {
      const aiUrl = `${window.location.protocol}//${window.location.hostname}:8000/analyze/static`;
      const r = await fetch(aiUrl, {
        method: 'POST',
        headers: {'Content-Type':'application/json'},
        body: JSON.stringify({ agent_id:'manual', exe_b64:result._b64, file_name:result.file_name, categorize:true })
      })
      if (!r.ok) { const e=await r.json(); showMsg(e.detail||'Kategorilendirme hatası','error'); return }
      const data = await r.json()
      setResult((prev:any) => ({...prev, ...data, _b64:prev._b64}))
      showMsg(`Kategori: ${data.threat_type}`, 'success')
      loadScans()
    } catch { showMsg('Kategorilendirme hatası','error') }
    finally { setCategorizing(false) }
  }

  const onDrop = (e: React.DragEvent) => {
    e.preventDefault(); setDragOver(false)
    const f = e.dataTransfer.files[0]
    if (f) analyzeFile(f)
  }

  const scoreClr = (s:number) => s>=90?'var(--red)':s>=70?'var(--orange)':s>=40?'var(--yellow)':'var(--green)'

  return (<>
    <div className="page-header">
      <h2>File Scanner</h2>
      <p>PE / EXE dosyalarını iki aşamalı AI modeli ile analiz et</p>
    </div>

    {/* Yükleme Alanı */}
    <div className="card" style={{marginBottom:20}}
      onDragOver={e=>{e.preventDefault();setDragOver(true)}}
      onDragLeave={()=>setDragOver(false)}
      onDrop={onDrop}>
      <div onClick={()=>fileRef.current?.click()} style={{
        border:`2px dashed ${dragOver?'var(--accent)':'var(--border)'}`,
        borderRadius:10, padding:'40px 20px', textAlign:'center', cursor:'pointer',
        background: dragOver?'rgba(0,212,255,0.05)':'transparent', transition:'all .2s'
      }}>
        <div style={{fontSize:36,marginBottom:12}}>📁</div>
        <div style={{color:'var(--text)',fontSize:14,fontWeight:600}}>Dosyayı buraya sürükle veya tıkla</div>
        <div style={{color:'var(--text-muted)',fontSize:11,marginTop:6}}>.exe, .dll, .sys, .bin desteklenir</div>
        <input ref={fileRef} type="file" accept=".exe,.dll,.sys,.bin,.dat,.elf,.so" style={{display:'none'}}
          onChange={e=>{ if(e.target.files?.[0]) analyzeFile(e.target.files[0]) }}/>
      </div>

      {/* Analiz Sonucu */}
      {scanning && <div style={{textAlign:'center',padding:'20px 0'}}><div className="spinner" style={{margin:'0 auto'}}/><div style={{color:'var(--text-muted)',fontSize:12,marginTop:8}}>Binary triage çalışıyor…</div></div>}
      {result && !scanning && (
        <div style={{marginTop:16,padding:16,background:'var(--bg-input)',borderRadius:8,border:`1px solid ${result.is_malware?'var(--red)':'var(--green)'}`}}>
          {/* Dosya bilgisi + skor */}
          <div style={{display:'flex',justifyContent:'space-between',alignItems:'flex-start',flexWrap:'wrap',gap:10}}>
            <div>
              <div style={{fontWeight:700,fontSize:15,color:'var(--text)',marginBottom:4}}>📄 {result.file_name}</div>
              <div style={{fontSize:11,color:'var(--text-muted)',fontFamily:'monospace'}}>SHA-256: {result.file_hash}</div>
              <div style={{fontSize:11,color:'var(--text-dim)',marginTop:2}}>{result.file_size ? `${(result.file_size/1024).toFixed(1)} KB` : ''}</div>
            </div>
            <div style={{textAlign:'right'}}>
              <div style={{fontSize:28,fontWeight:800,color:scoreClr(result.risk_score)}}>{result.risk_score?.toFixed(1)}</div>
              <div style={{fontSize:10,color:'var(--text-muted)'}}>Risk Skoru</div>
            </div>
          </div>

          {/* Badge'ler */}
          <div style={{display:'flex',gap:8,marginTop:12,flexWrap:'wrap',alignItems:'center'}}>
            <span className={`badge badge-${result.is_malware?'red':'green'}`}>
              {result.is_malware?'⚠ ZARALI':'✓ TEMİZ'}
            </span>
            {/* Kategori badge — sadece kategorize edildiyse göster */}
            {result.categorized && result.threat_type && result.threat_type !== 'benign' && result.threat_type !== 'malicious' && (
              <span className="badge badge-orange">🏷 {result.threat_type}</span>
            )}
            {result.is_malware && !result.categorized && (
              <span className="badge" style={{background:'rgba(255,165,0,0.1)',color:'var(--orange)',fontSize:10}}>
                Kategori bilinmiyor
              </span>
            )}
            <span className="badge" style={{background:'var(--bg-card)',color:'var(--text-muted)',fontSize:10}}>
              {result.method === 'hash_lookup' ? '⚡ Hash DB' : result.categorized ? '🧠 Triage+CNN' : '🔍 Binary Triage'}
            </span>
            <span className="badge" style={{background:'var(--bg-card)',color:'var(--text-muted)',fontSize:10}}>
              Güven: %{((result.confidence||0)*100).toFixed(1)}
            </span>
            {result.recorded && <span className="badge" style={{background:'rgba(0,255,136,.1)',color:'var(--green)',fontSize:10}}>DB'ye kaydedildi ✓</span>}
          </div>

          {/* VT Sonucu */}
          {result.vt && result.vt.found !== false && (
            <div style={{marginTop:12,padding:'10px 12px',background:'rgba(99,102,241,0.06)',borderRadius:6,border:'1px solid rgba(99,102,241,0.2)'}}>
              <div style={{fontSize:11,fontWeight:700,color:'#818cf8',marginBottom:6}}>🛡 VirusTotal</div>
              <div style={{display:'flex',gap:16,alignItems:'center',flexWrap:'wrap'}}>
                <span style={{fontSize:13,fontWeight:800,color: result.vt.positives>0?'var(--red)':'var(--green)'}}>
                  {result.vt.positives ?? 0} / {result.vt.total ?? 0}
                </span>
                <span style={{fontSize:11,color:'var(--text-muted)'}}>motor tespit etti</span>
                {result.vt.label && <span className="badge badge-orange" style={{fontSize:10}}>{result.vt.label}</span>}
                {result.vt.permalink && (
                  <a href={result.vt.permalink} target="_blank" rel="noreferrer"
                    style={{fontSize:10,color:'#818cf8',textDecoration:'none'}}>🔗 VT'de Görüntüle</a>
                )}
              </div>
            </div>
          )}
          {result.vt && result.vt.found === false && (
            <div style={{marginTop:8,fontSize:10,color:'var(--text-dim)'}}>🛡 VirusTotal: Veritabanında bulunamadı</div>
          )}

          {/* YARA Sonuçları */}
          {result.yara_matches && result.yara_matches.length > 0 && (
            <div style={{marginTop:12,padding:'10px 12px',background:'rgba(251,146,60,0.06)',borderRadius:6,border:'1px solid rgba(251,146,60,0.2)'}}>
              <div style={{fontSize:11,fontWeight:700,color:'var(--orange)',marginBottom:6}}>⚡ YARA Eşleşmeleri</div>
              <div style={{display:'flex',flexDirection:'column',gap:4}}>
                {(result.yara_matches as {rule:string;description:string;severity:string;score:number}[]).map((m,i) => (
                  <div key={i} style={{display:'flex',alignItems:'center',gap:8}}>
                    <span style={{fontSize:10,fontFamily:'monospace',color:'var(--orange)',fontWeight:700}}>{m.rule}</span>
                    <span style={{fontSize:10,color:'var(--text-muted)'}}>{m.description}</span>
                    <span className="badge" style={{background:'rgba(251,146,60,0.12)',color:'var(--orange)',fontSize:9,padding:'1px 5px'}}>{m.severity}</span>
                  </div>
                ))}
              </div>
            </div>
          )}

          {/* Multiclass skor tablosu — kategorize edildiyse */}
          {result.categorized && result.scores && (
            <div style={{marginTop:14}}>
              <div style={{fontSize:11,color:'var(--text-muted)',marginBottom:6,fontWeight:600}}>Tehdit Kategorileri</div>
              <div style={{display:'flex',flexDirection:'column',gap:4}}>
                {Object.entries(result.scores as Record<string,number>)
                  .sort(([,a],[,b]) => b-a)
                  .map(([cls,prob]) => (
                    <div key={cls} style={{display:'flex',alignItems:'center',gap:8}}>
                      <div style={{width:80,fontSize:11,color:'var(--text)',textTransform:'capitalize'}}>{cls}</div>
                      <div style={{flex:1,background:'var(--bg-card)',borderRadius:4,height:6,overflow:'hidden'}}>
                        <div style={{width:`${(prob*100).toFixed(1)}%`,height:'100%',
                          background: cls==='benign'?'var(--green)':prob>0.5?'var(--red)':'var(--orange)',
                          transition:'width 0.4s ease'}}/>
                      </div>
                      <div style={{fontSize:10,color:'var(--text-muted)',width:38,textAlign:'right'}}>
                        {(prob*100).toFixed(1)}%
                      </div>
                    </div>
                  ))
                }
              </div>
            </div>
          )}

          {/* Kategorize Et butonu — zararlı ama henüz kategorize edilmemişse */}
          {result.is_malware && !result.categorized && result.method !== 'hash_lookup' && (
            <div style={{marginTop:14}}>
              <button
                id="btn-categorize"
                onClick={categorizeFile}
                disabled={categorizing}
                style={{
                  background:'linear-gradient(135deg,var(--orange),var(--red))',
                  color:'#fff', border:'none', borderRadius:8,
                  padding:'10px 20px', fontSize:13, fontWeight:700,
                  cursor:categorizing?'not-allowed':'pointer',
                  opacity:categorizing?0.7:1, transition:'all 0.2s',
                  display:'flex', alignItems:'center', gap:8
                }}>
                {categorizing
                  ? <><div className="spinner" style={{width:14,height:14,borderWidth:2}}/> Multiclass CNN çalışıyor…</>
                  : '🔬 Tehdit Kategorisini Belirle'}
              </button>
              <div style={{fontSize:10,color:'var(--text-muted)',marginTop:4}}>
                9 sınıflı model ile ransomware, trojan, worm vb. tespit edilir
              </div>
            </div>
          )}
        </div>
      )}
    </div>

    {/* Tarama Geçmişi */}
    <div className="card">
      <div className="card-header">
        <span className="card-title">Tarama Geçmişi ({scans.length})</span>
        <label style={{display:'flex',alignItems:'center',gap:6,fontSize:11,color:'var(--text-muted)',cursor:'pointer'}}>
          <input type="checkbox" checked={malOnly} onChange={e=>setMalOnly(e.target.checked)} style={{accentColor:'var(--accent)'}}/>
          Yalnızca zararlılar
        </label>
      </div>
      {scans.length === 0 ? (
        <div className="empty-state">Henüz tarama yok</div>
      ) : (
        <table style={{width:'100%',borderCollapse:'collapse',fontSize:12}}>
          <thead><tr style={{borderBottom:'1px solid var(--border)',color:'var(--text-muted)'}}>
            <th style={{textAlign:'left',padding:'8px 6px',fontWeight:500}}>Dosya</th>
            <th style={{textAlign:'left',padding:'8px 6px',fontWeight:500}}>SHA-256</th>
            <th style={{textAlign:'left',padding:'8px 6px',fontWeight:500}}>Tehdit</th>
            <th style={{textAlign:'center',padding:'8px 6px',fontWeight:500}}>Skor</th>
            <th style={{textAlign:'left',padding:'8px 6px',fontWeight:500}}>VT / YARA</th>
            <th style={{textAlign:'center',padding:'8px 6px',fontWeight:500}}>Durum</th>
            <th style={{textAlign:'left',padding:'8px 6px',fontWeight:500}}>Zaman</th>
          </tr></thead>
          <tbody>
            {scans.map(s=>(
              <tr key={s.id} style={{borderBottom:'1px solid var(--border)'}}>
                <td style={{padding:'9px 6px'}}>
                  <div style={{fontWeight:600,color:'var(--text)',fontFamily:'monospace',fontSize:11}}>{s.file_name}</div>
                  <div style={{fontSize:10,color:'var(--text-dim)'}}>{s.agent_id !== 'manual' ? `🖥 ${s.agent_id.slice(0,12)}` : '👤 Manuel'} · {(s.file_size/1024).toFixed(1)} KB</div>
                </td>
                <td style={{padding:'9px 6px'}}>
                  <code style={{fontSize:9,color:'var(--text-dim)',wordBreak:'break-all'}}>{s.file_hash.slice(0,20)}…</code>
                </td>
                <td style={{padding:'9px 6px'}}>
                  <span className="badge badge-orange" style={{fontSize:10}}>{s.threat_type}</span>
                </td>
                <td style={{padding:'9px 6px',textAlign:'center'}}>
                  <span style={{color:scoreClr(s.risk_score),fontWeight:700}}>{s.risk_score.toFixed(0)}</span>
                </td>
                <td style={{padding:'9px 6px',fontSize:10,maxWidth:160}}>
                  {s.vt_positives != null && s.vt_total != null ? (
                    <div style={{display:'flex',flexDirection:'column',gap:2}}>
                      <span style={{color:s.vt_positives>0?'var(--red)':'var(--green)',fontWeight:700}}>
                        🛡 {s.vt_positives}/{s.vt_total}
                      </span>
                      {s.vt_label && <span style={{color:'var(--text-muted)',fontSize:9}}>{s.vt_label}</span>}
                    </div>
                  ) : <span style={{color:'var(--text-dim)'}}>—</span>}
                  {s.yara_matches && s.yara_matches !== '[]' && (() => {
                    try {
                      const m = JSON.parse(s.yara_matches)
                      return m.length > 0 ? <div style={{color:'var(--orange)',fontSize:9,marginTop:2}}>⚡ {m[0].rule}{m.length>1?` +${m.length-1}`:''}</div> : null
                    } catch { return null }
                  })()}
                </td>
                <td style={{padding:'9px 6px',textAlign:'center'}}>
                  {s.is_malware
                    ? <span style={{color:'var(--red)',fontSize:11,fontWeight:600}}>⚠ ZARALI</span>
                    : <span style={{color:'var(--green)',fontSize:11}}>✓ Temiz</span>}
                </td>
                <td style={{padding:'9px 6px',fontSize:10,color:'var(--text-muted)'}}>{fmt(s.ts)}</td>
              </tr>
            ))}
          </tbody>
        </table>
      )}
    </div>
    {toast && <Toast msg={toast.msg} type={toast.type}/>}
  </>)
}

/* ── Rules Page ────────────────────────────────────────────────────────── */
interface DetectionRule { id:number; name:string; description:string; rule_text:string; threat_type:string; score:number; enabled:boolean; created_at:number }

const THREAT_TYPES = ['custom','ransomware','trojan','worm','backdoor','adware','spyware','dropper','cryptominer','credential_theft','lateral_movement','c2_common','obfuscated_ps','privilege_escalation']

const EXAMPLES = [
  { label:'Mimikatz tespiti',        rule:'process.name = "mimikatz.exe"',                                                        threat:'credential_theft', score:98 },
  { label:'Powershell obfuscation',  rule:'process.name = "powershell.exe" AND process.cmdline contains "-enc"',                  threat:'obfuscated_ps',    score:88 },
  { label:'C2 port 4444',            rule:'network.port = 4444',                                                                   threat:'c2_common',        score:90 },
  { label:'Netcat kullanımı',        rule:'process.name contains "nc" AND process.cmdline contains "-e"',                         threat:'backdoor',         score:85 },
  { label:'Şüpheli exe (temp)',      rule:'process.exe contains "/tmp/"',                                                          threat:'dropper',          score:75 },
  { label:'lsass dump',              rule:'process.cmdline contains "lsass"',                                                     threat:'credential_theft', score:95 },
  { label:'nmap tarama',             rule:'process.name = "nmap"',                                                                 threat:'lateral_movement', score:70 },
  { label:'Yüksek CPU (>90%)',       rule:'cpu.percent >= 90',                                                                    threat:'cryptominer',      score:75 },
]

export function RulesPage() {
  const [rules,    setRules]    = useState<DetectionRule[]>([])
  const [loading,  setLoading]  = useState(true)
  const [showForm, setShowForm] = useState(false)
  const [editRule, setEditRule] = useState<DetectionRule|null>(null)
  const [toast,    setToast]    = useState<{msg:string;type:'success'|'error'}|null>(null)

  // form state
  const [name,       setName]       = useState('')
  const [desc,       setDesc]       = useState('')
  const [ruleText,   setRuleText]   = useState('')
  const [threatType, setThreatType] = useState('custom')
  const [score,      setScore]      = useState(80)

  const showMsg = (msg:string, type:'success'|'error'='success') => {
    setToast({msg,type}); setTimeout(()=>setToast(null),3000)
  }

  const load = useCallback(async () => {
    try {
      const r = await fetch('/api/ai/rules')
      if (r.ok) setRules(await r.json())
    } finally { setLoading(false) }
  }, [])

  useEffect(()=>{ load() },[load])

  const resetForm = () => { setName(''); setDesc(''); setRuleText(''); setThreatType('custom'); setScore(80); setEditRule(null); setShowForm(false) }

  const openEdit = (rule:DetectionRule) => {
    setName(rule.name); setDesc(rule.description); setRuleText(rule.rule_text)
    setThreatType(rule.threat_type); setScore(rule.score); setEditRule(rule); setShowForm(true)
  }

  const applyExample = (ex:typeof EXAMPLES[0]) => {
    setRuleText(ex.rule); setThreatType(ex.threat); setScore(ex.score)
    if (!name) setName(ex.label)
    setShowForm(true)
  }

  const save = async () => {
    if (!name.trim() || !ruleText.trim()) return showMsg('Ad ve kural metni zorunlu','error')
    const body = { name:name.trim(), description:desc, rule_text:ruleText.trim(), threat_type:threatType, score, enabled:true }
    const url  = editRule ? `/api/ai/rules/${editRule.id}` : '/api/ai/rules'
    const method = editRule ? 'PATCH' : 'POST'
    const r = await fetch(url, { method, headers:{'Content-Type':'application/json'}, body:JSON.stringify(body) })
    if (r.ok) { showMsg(editRule?'Güncellendi':'Kural oluşturuldu'); resetForm(); load() }
    else      { const e=await r.json(); showMsg(e.detail||'Hata','error') }
  }

  const toggle = async (rule:DetectionRule) => {
    const r = await fetch(`/api/ai/rules/${rule.id}`, { method:'PATCH', headers:{'Content-Type':'application/json'}, body:JSON.stringify({enabled:!rule.enabled}) })
    if (r.ok) { showMsg(rule.enabled?'Kural devre dışı':'Kural aktifleştirildi'); load() }
  }

  const del = async (id:number) => {
    if (!confirm('Kuralı sil?')) return
    const r = await fetch(`/api/ai/rules/${id}`, {method:'DELETE'})
    if (r.ok) { showMsg('Silindi'); load() }
  }

  return (<>
    <div className="page-header">
      <h2>Detection Rules</h2>
      <p>KQL sözdiziminde özel tehdit tespit kuralları</p>
    </div>

    {/* Kural Formu */}
    {showForm && (
      <div className="card" style={{marginBottom:20}}>
        <div className="card-header">
          <span className="card-title">{editRule?'Kuralı Düzenle':'Yeni Kural'}</span>
          <button className="btn-secondary" style={{fontSize:11,padding:'4px 10px'}} onClick={resetForm}>İptal</button>
        </div>
        <div style={{display:'grid',gridTemplateColumns:'1fr 1fr',gap:14,padding:'0 0 14px'}}>
          <div><label style={{fontSize:11,color:'var(--text-muted)',display:'block',marginBottom:4}}>Kural Adı *</label>
            <input value={name} onChange={e=>setName(e.target.value)} placeholder="Mimikatz Tespiti" style={{width:'100%',background:'var(--bg-input)',border:'1px solid var(--border)',color:'var(--text)',padding:'8px 10px',borderRadius:6,fontSize:13}}/></div>
          <div><label style={{fontSize:11,color:'var(--text-muted)',display:'block',marginBottom:4}}>Açıklama</label>
            <input value={desc} onChange={e=>setDesc(e.target.value)} placeholder="İsteğe bağlı" style={{width:'100%',background:'var(--bg-input)',border:'1px solid var(--border)',color:'var(--text)',padding:'8px 10px',borderRadius:6,fontSize:13}}/></div>
        </div>
        <div style={{marginBottom:12}}>
          <label style={{fontSize:11,color:'var(--text-muted)',display:'block',marginBottom:4}}>KQL Kuralı *</label>
          <textarea value={ruleText} onChange={e=>setRuleText(e.target.value)} rows={3}
            placeholder={`process.name = "mimikatz.exe"\nprocess.cmdline contains "-enc" AND event.type = "process_new"\nnetwork.port = 4444`}
            style={{width:'100%',background:'var(--bg-input)',border:'1px solid var(--border)',color:'var(--accent)',padding:'10px',borderRadius:6,fontSize:13,fontFamily:'monospace',resize:'vertical'}}/>
          <div style={{fontSize:10,color:'var(--text-dim)',marginTop:4}}>Alanlar: <code>process.name</code> <code>process.cmdline</code> <code>process.exe</code> <code>network.port</code> <code>network.remote_ip</code> <code>event.type</code> <code>cpu.percent</code> | Operatörler: <code>=</code> <code>contains</code> <code>matches</code> <code>&gt;</code> <code>&lt;</code> | Mantıksal: <code>AND</code> <code>OR</code></div>
        </div>
        <div style={{display:'grid',gridTemplateColumns:'1fr 1fr auto',gap:14,alignItems:'flex-end'}}>
          <div><label style={{fontSize:11,color:'var(--text-muted)',display:'block',marginBottom:4}}>Tehdit Tipi</label>
            <select value={threatType} onChange={e=>setThreatType(e.target.value)} style={{width:'100%',background:'var(--bg-input)',border:'1px solid var(--border)',color:'var(--text)',padding:'8px 10px',borderRadius:6,fontSize:13}}>
              {THREAT_TYPES.map(t=><option key={t} value={t}>{t}</option>)}
            </select></div>
          <div><label style={{fontSize:11,color:'var(--text-muted)',display:'block',marginBottom:4}}>Risk Skoru (0-100)</label>
            <input type="number" min={0} max={100} value={score} onChange={e=>setScore(+e.target.value)} style={{width:'100%',background:'var(--bg-input)',border:'1px solid var(--border)',color:'var(--text)',padding:'8px 10px',borderRadius:6,fontSize:13}}/></div>
          <button className="btn-primary" onClick={save} style={{height:37}}>{editRule?'Güncelle':'Kaydet'}</button>
        </div>
      </div>
    )}

    {/* Hızlı Örnekler */}
    {!showForm && (
      <div className="card" style={{marginBottom:20}}>
        <div className="card-header"><span className="card-title">⚡ Hazır Kurallar</span>
          <button className="btn-primary" style={{fontSize:11,padding:'4px 12px'}} onClick={()=>setShowForm(true)}>+ Yeni Kural</button>
        </div>
        <div style={{display:'flex',flexWrap:'wrap',gap:8,paddingBottom:4}}>
          {EXAMPLES.map(ex=>(
            <button key={ex.label} onClick={()=>applyExample(ex)} style={{background:'var(--bg-input)',border:'1px solid var(--border)',color:'var(--text-muted)',padding:'6px 12px',borderRadius:6,fontSize:11,cursor:'pointer',transition:'all .2s'}}
              onMouseEnter={e=>(e.currentTarget.style.borderColor='var(--accent)',e.currentTarget.style.color='var(--accent)')}
              onMouseLeave={e=>(e.currentTarget.style.borderColor='var(--border)',e.currentTarget.style.color='var(--text-muted)')}>
              {ex.label}
            </button>
          ))}
        </div>
      </div>
    )}

    {/* Kural Listesi */}
    <div className="card">
      <div className="card-header"><span className="card-title">Aktif Kurallar ({rules.length})</span></div>
      {loading ? <div className="spinner" style={{margin:'30px auto'}}/> : rules.length === 0 ? (
        <div className="empty-state">Henüz kural yok — yukarıdan ekle</div>
      ) : (
        <table style={{width:'100%',borderCollapse:'collapse',fontSize:12}}>
          <thead><tr style={{borderBottom:'1px solid var(--border)',color:'var(--text-muted)'}}>
            <th style={{textAlign:'left',padding:'8px 6px',fontWeight:500}}>Ad</th>
            <th style={{textAlign:'left',padding:'8px 6px',fontWeight:500}}>KQL Kuralı</th>
            <th style={{textAlign:'left',padding:'8px 6px',fontWeight:500}}>Tehdit</th>
            <th style={{textAlign:'center',padding:'8px 6px',fontWeight:500}}>Skor</th>
            <th style={{textAlign:'center',padding:'8px 6px',fontWeight:500}}>Durum</th>
            <th style={{textAlign:'center',padding:'8px 6px',fontWeight:500}}>İşlem</th>
          </tr></thead>
          <tbody>
            {rules.map(rule=>(
              <tr key={rule.id} style={{borderBottom:'1px solid var(--border)',opacity:rule.enabled?1:0.45,transition:'opacity .2s'}}>
                <td style={{padding:'10px 6px'}}>
                  <div style={{fontWeight:600,color:'var(--text)'}}>{rule.name}</div>
                  {rule.description&&<div style={{fontSize:10,color:'var(--text-dim)',marginTop:2}}>{rule.description}</div>}
                </td>
                <td style={{padding:'10px 6px',maxWidth:260}}>
                  <code style={{fontSize:11,color:'var(--accent)',wordBreak:'break-word',lineHeight:1.6}}>{rule.rule_text}</code>
                </td>
                <td style={{padding:'10px 6px'}}>
                  <span className="badge badge-orange" style={{fontSize:10}}>{rule.threat_type}</span>
                </td>
                <td style={{padding:'10px 6px',textAlign:'center'}}>
                  <span style={{color:rule.score>=90?'var(--red)':rule.score>=70?'var(--orange)':'var(--yellow)',fontWeight:700}}>{rule.score}</span>
                </td>
                <td style={{padding:'10px 6px',textAlign:'center'}}>
                  <button onClick={()=>toggle(rule)} style={{background:rule.enabled?'rgba(0,212,100,0.15)':'var(--bg-input)',border:`1px solid ${rule.enabled?'var(--green)':'var(--border)'}`,color:rule.enabled?'var(--green)':'var(--text-muted)',padding:'3px 10px',borderRadius:4,fontSize:10,cursor:'pointer'}}>
                    {rule.enabled?'Aktif':'Pasif'}
                  </button>
                </td>
                <td style={{padding:'10px 6px',textAlign:'center'}}>
                  <div style={{display:'flex',gap:6,justifyContent:'center'}}>
                    <button onClick={()=>openEdit(rule)} style={{background:'var(--bg-input)',border:'1px solid var(--border)',color:'var(--text-muted)',padding:'3px 8px',borderRadius:4,fontSize:10,cursor:'pointer'}}>Düzenle</button>
                    <button onClick={()=>del(rule.id)} style={{background:'rgba(255,68,102,.1)',border:'1px solid var(--red)',color:'var(--red)',padding:'3px 8px',borderRadius:4,fontSize:10,cursor:'pointer'}}>Sil</button>
                  </div>
                </td>
              </tr>
            ))}
          </tbody>
        </table>
      )}
    </div>
    {toast && <Toast msg={toast.msg} type={toast.type}/>}
  </>)
}

/* ── Threat Intel Page ──────────────────────────────────────────────────────── */
interface MalwareHash {
  id: number; sha256: string; name: string; threat_type: string;
  risk_score: number; source: string; added_at: number; notes?: string
}
interface ThreatStats {
  total_hashes: number
  by_threat_type: {threat_type: string; count: number}[]
  by_source: {source: string; count: number}[]
}

export function ThreatIntelPage() {
  const [hashes,   setHashes]   = useState<MalwareHash[]>([])
  const [stats,    setStats]    = useState<ThreatStats|null>(null)
  const [loading,  setLoading]  = useState(false)
  const [filter,   setFilter]   = useState('')
  const [toast,    setToast]    = useState<{msg:string;type:'success'|'error'}|null>(null)
  // Yeni hash formu
  const [sha256,   setSha256]   = useState('')
  const [name,     setName]     = useState('')
  const [ttype,    setTtype]    = useState('malware')
  const [score,    setScore]    = useState(90)
  const [adding,   setAdding]   = useState(false)

  const showToast = (msg: string, type: 'success'|'error') => {
    setToast({msg, type}); setTimeout(() => setToast(null), 3500)
  }

  const load = useCallback(async () => {
    setLoading(true)
    try {
      const [h, s] = await Promise.all([
        fetch('/api/ai/threat-intel/hashes?limit=500').then(r => r.json()),
        fetch('/api/ai/threat-intel/stats').then(r => r.json()),
      ])
      setHashes(Array.isArray(h) ? h : [])
      setStats(s)
    } catch { showToast('Yükleme hatası', 'error') }
    finally  { setLoading(false) }
  }, [])

  useEffect(() => { load() }, [load])

  const addHash = async () => {
    if (sha256.length !== 64) { showToast('SHA-256 hash 64 karakter olmalı', 'error'); return }
    setAdding(true)
    try {
      const r = await fetch('/api/ai/threat-intel/hashes', {
        method: 'POST',
        headers: {'Content-Type':'application/json'},
        body: JSON.stringify({sha256, name, threat_type: ttype, risk_score: score, source: 'manual'})
      })
      if (!r.ok) throw new Error(await r.text())
      showToast('Hash eklendi ✓', 'success')
      setSha256(''); setName('')
      await load()
    } catch (e: any) { showToast(e.message||'Hata', 'error') }
    finally { setAdding(false) }
  }

  const deleteHash = async (sha256: string) => {
    if (!confirm('Bu hash kaydını silmek istiyor musunuz?')) return
    try {
      const r = await fetch(`/api/ai/threat-intel/hashes/${sha256}`, {method:'DELETE'})
      if (!r.ok) throw new Error(await r.text())
      showToast('Silindi', 'success')
      await load()
    } catch (e: any) { showToast(e.message||'Hata', 'error') }
  }

  const filtered = hashes.filter(h =>
    !filter || h.sha256.includes(filter.toLowerCase()) ||
    h.name.toLowerCase().includes(filter.toLowerCase()) ||
    h.threat_type.includes(filter.toLowerCase())
  )

  const threatColors: Record<string,string> = {
    ransomware:'#ff4466', credential_theft:'#ff9940', rat:'#a78bfa',
    backdoor:'#f97316', cryptominer:'#fbbf24', c2_framework:'#ef4444',
    trojan:'#fb7185', malware:'#94a3b8', dropper:'#34d399'
  }

  return (<>
    {toast && <Toast msg={toast.msg} type={toast.type}/>}
    <div className="page-header">
      <h2>🧬 Threat Intel — Malware Hash Veritabanı</h2>
      <p>Bilinen zararlı SHA-256 hash'leri — CNN öncesi anlık tespit</p>
    </div>

    {/* İstatistik kartları */}
    {stats && (
      <div className="stats-grid" style={{marginBottom:24}}>
        <div className="stat-card">
          <div className="stat-label">Toplam Hash</div>
          <div className="stat-value accent">{stats.total_hashes}</div>
          <div className="stat-sub">Kayıtlı zararlı</div>
        </div>
        {stats.by_threat_type.slice(0,3).map(t => (
          <div key={t.threat_type} className="stat-card">
            <div className="stat-label">{t.threat_type}</div>
            <div className="stat-value" style={{color: threatColors[t.threat_type]||'var(--text)'}}>{t.count}</div>
            <div className="stat-sub">hash</div>
          </div>
        ))}
      </div>
    )}

    {/* Hash ekleme formu */}
    <div className="card" style={{marginBottom:20}}>
      <div className="card-header"><span className="card-title">➕ Yeni Hash Ekle</span></div>
      <div style={{display:'flex', gap:8, flexWrap:'wrap', padding:'12px 0'}}>
        <input value={sha256} onChange={e=>setSha256(e.target.value.trim())} placeholder="SHA-256 (64 hex karakter)"
          style={{flex:'2 1 300px',background:'var(--bg-input)',border:'1px solid var(--border)',color:'var(--accent)',padding:'8px 12px',borderRadius:6,fontSize:12,fontFamily:'monospace'}}/>
        <input value={name} onChange={e=>setName(e.target.value)} placeholder="Zararlı adı (ör. Mimikatz)"
          style={{flex:'1 1 180px',background:'var(--bg-input)',border:'1px solid var(--border)',color:'var(--text)',padding:'8px 12px',borderRadius:6,fontSize:13}}/>
        <select value={ttype} onChange={e=>setTtype(e.target.value)}
          style={{flex:'1 1 140px',background:'var(--bg-input)',border:'1px solid var(--border)',color:'var(--text)',padding:'8px 10px',borderRadius:6,fontSize:13}}>
          {['malware','ransomware','trojan','backdoor','rat','cryptominer','dropper','credential_theft','c2_framework','spyware'].map(t=>
            <option key={t} value={t}>{t}</option>
          )}
        </select>
        <input type="number" min={0} max={100} value={score} onChange={e=>setScore(+e.target.value)} placeholder="Risk Skoru"
          style={{flex:'0 0 100px',background:'var(--bg-input)',border:'1px solid var(--border)',color:'var(--text)',padding:'8px 10px',borderRadius:6,fontSize:13}}/>
        <button onClick={addHash} disabled={adding}
          style={{flex:'0 0 auto',background:'var(--accent)',color:'#000',border:'none',padding:'8px 18px',borderRadius:6,fontSize:13,fontWeight:700,cursor:'pointer',opacity:adding?.6:1}}>
          {adding ? '...' : 'Ekle'}
        </button>
      </div>
    </div>

    {/* Hash listesi */}
    <div className="card">
      <div className="card-header">
        <span className="card-title">🗂 Hash Listesi ({filtered.length})</span>
        <input value={filter} onChange={e=>setFilter(e.target.value)} placeholder="Filtrele..."
          style={{background:'var(--bg-input)',border:'1px solid var(--border)',color:'var(--text)',padding:'4px 10px',borderRadius:5,fontSize:12,width:200}}/>
      </div>
      {loading ? <div style={{padding:24,color:'var(--text-dim)',textAlign:'center'}}>Yükleniyor…</div> :
      filtered.length === 0 ? <div style={{padding:24,color:'var(--text-dim)',textAlign:'center'}}>Hash bulunamadı.</div> :
      <div style={{overflowX:'auto'}}>
        <table style={{width:'100%',borderCollapse:'collapse',fontSize:12}}>
          <thead>
            <tr style={{color:'var(--text-dim)',borderBottom:'1px solid var(--border)'}}>
              <th style={{padding:'6px 10px',textAlign:'left'}}>SHA-256</th>
              <th style={{padding:'6px 10px',textAlign:'left'}}>İsim</th>
              <th style={{padding:'6px 10px',textAlign:'left'}}>Tür</th>
              <th style={{padding:'6px 10px',textAlign:'center'}}>Risk</th>
              <th style={{padding:'6px 10px',textAlign:'left'}}>Kaynak</th>
              <th style={{padding:'6px 10px',textAlign:'center'}}>İşlem</th>
            </tr>
          </thead>
          <tbody>
            {filtered.map(h => (
              <tr key={h.id} style={{borderBottom:'1px solid rgba(255,255,255,0.04)',transition:'background .15s'}}
                onMouseEnter={e=>(e.currentTarget.style.background='rgba(255,255,255,0.03)')}
                onMouseLeave={e=>(e.currentTarget.style.background='transparent')}>
                <td style={{padding:'6px 10px',fontFamily:'monospace',color:'var(--text-dim)',fontSize:10}}>
                  {h.sha256.slice(0,12)}…{h.sha256.slice(-8)}
                </td>
                <td style={{padding:'6px 10px',color:'var(--text)',fontWeight:600}}>{h.name}</td>
                <td style={{padding:'6px 10px'}}>
                  <span style={{background:`${threatColors[h.threat_type]||'#666'}22`,color:threatColors[h.threat_type]||'var(--text-dim)',padding:'2px 8px',borderRadius:4,fontSize:10,fontWeight:600}}>
                    {h.threat_type}
                  </span>
                </td>
                <td style={{padding:'6px 10px',textAlign:'center',color:h.risk_score>=90?'var(--red)':h.risk_score>=70?'var(--orange)':'var(--yellow)',fontWeight:700}}>
                  {h.risk_score}
                </td>
                <td style={{padding:'6px 10px',color:'var(--text-dim)',fontSize:10}}>{h.source}</td>
                <td style={{padding:'6px 10px',textAlign:'center'}}>
                  <button onClick={()=>deleteHash(h.sha256)}
                    style={{background:'rgba(255,68,102,0.15)',border:'1px solid var(--red)',color:'var(--red)',padding:'2px 8px',borderRadius:4,fontSize:10,cursor:'pointer'}}>
                    Sil
                  </button>
                </td>
              </tr>
            ))}
          </tbody>
        </table>
      </div>}
    </div>
  </>)
}

/* ── YARA Rules Page ─────────────────────────────────────────────────────────── */
interface YaraFile {
  file: string
  editable: boolean
  rule_count: number
  size: number
  rules: { name: string; description: string; severity: string; score: number }[]
  error?: string
}
interface YaraStatus {
  ready: boolean
  file_count: number
  rule_count: number
  disabled_files: string[]
  vt_enabled: boolean
}

const YARA_TEMPLATE = `/*
  Sentinel XDR — Özel YARA Kuralları
  =====================================
  Buraya kendi YARA kurallarınızı yazın.
*/

rule CUSTOM_Suspicious_File
{
    meta:
        description = "Özel şüpheli dosya kuralı"
        severity    = "high"
        score       = 80
    strings:
        $s1 = "suspicious_string" ascii nocase
    condition:
        any of them
}
`

export function YaraRulesPage() {
  const [files,         setFiles]         = useState<YaraFile[]>([])
  const [status,        setStatus]        = useState<YaraStatus|null>(null)
  const [loading,       setLoading]       = useState(true)
  const [editorContent, setEditorContent] = useState(YARA_TEMPLATE)
  const [saving,        setSaving]        = useState(false)
  const [reloading,     setReloading]     = useState(false)
  const [toggling,      setToggling]      = useState<string|null>(null)
  const [activeFile,    setActiveFile]    = useState<YaraFile|null>(null)
  const [toast,         setToast]         = useState<{msg:string;type:'success'|'error'}|null>(null)
  const uploadRef = useRef<HTMLInputElement>(null)

  const showMsg = (msg:string, type:'success'|'error'='success') => {
    setToast({msg, type}); setTimeout(()=>setToast(null), 4000)
  }

  const loadData = useCallback(async () => {
    setLoading(true)
    try {
      const [sr, fr] = await Promise.all([
        fetch('/api/ai/yara/status'),
        fetch('/api/ai/yara/rules'),
      ])
      if (sr.ok) setStatus(await sr.json())
      if (fr.ok) {
        const data: YaraFile[] = await fr.json()
        setFiles(data)
        // custom_rules.yar içeriğini editöre yükle (ilk açılışta)
        const custom = data.find(f => f.file === 'custom_rules.yar')
        if (!custom) setEditorContent(YARA_TEMPLATE)
      }
    } finally { setLoading(false) }
  }, [])

  useEffect(() => { loadData() }, [loadData])

  const saveRules = async () => {
    setSaving(true)
    try {
      const r = await fetch('/api/ai/yara/rules/save', {
        method:'POST', headers:{'Content-Type':'application/json'},
        body: JSON.stringify({ content: editorContent })
      })
      const data = await r.json()
      if (r.ok) { showMsg(`✓ Kaydedildi — ${data.rule_count} dosya aktif`, 'success'); loadData() }
      else showMsg(data.detail || 'Kayıt hatası', 'error')
    } catch { showMsg('Bağlantı hatası', 'error') }
    finally { setSaving(false) }
  }

  const reloadRules = async () => {
    setReloading(true)
    try {
      const r = await fetch('/api/ai/yara/reload', { method:'POST' })
      const data = await r.json()
      if (r.ok) { showMsg(`✓ Yenilendi`, 'success'); loadData() }
      else showMsg('Yenileme hatası', 'error')
    } catch { showMsg('Bağlantı hatası', 'error') }
    finally { setReloading(false) }
  }

  const toggleFile = async (filename: string) => {
    setToggling(filename)
    try {
      const r = await fetch('/api/ai/yara/rules/toggle', {
        method:'POST', headers:{'Content-Type':'application/json'},
        body: JSON.stringify({ filename })
      })
      const data = await r.json()
      if (r.ok) {
        showMsg(`${filename}: ${data.active?'Etkinleştirildi':'Devre dışı bırakıldı'}`, 'success')
        loadData()
      } else showMsg(data.detail || 'Hata', 'error')
    } catch { showMsg('Bağlantı hatası', 'error') }
    finally { setToggling(null) }
  }

  const uploadFile = async (file: File) => {
    const form = new FormData()
    form.append('file', file)
    try {
      const r = await fetch('/api/ai/yara/rules/upload', { method:'POST', body: form })
      const data = await r.json()
      if (r.ok) { showMsg(`✓ ${file.name} yüklendi`, 'success'); loadData() }
      else showMsg(data.detail || 'Yükleme hatası', 'error')
    } catch { showMsg('Yükleme hatası', 'error') }
  }

  const sevColor = (s:string) => s==='critical'?'var(--red)':s==='high'?'var(--orange)':s==='medium'?'var(--yellow)':'var(--green)'
  const totalRules = files.reduce((s,f)=>s+f.rule_count,0)
  const activeFiles = status ? files.length - (status.disabled_files?.length||0) : files.length

  return (<>
    <div className="page-header">
      <h2>YARA Kuralları</h2>
      <p>İmza tabanlı statik dosya analizi — PE, ELF, script tarama</p>
    </div>

    {/* Durum Kartları */}
    <div className="stats-grid" style={{gridTemplateColumns:'repeat(4,1fr)',marginBottom:20}}>
      <div className="stat-card">
        <div className="stat-label">Motor</div>
        <div className={`stat-value ${status?.ready?'green':'red'}`} style={{fontSize:18,marginTop:4}}>
          {status?.ready ? '● AKTİF' : '○ HAZIR DEĞİL'}
        </div>
        <div className="stat-sub">yara-python</div>
      </div>
      <div className="stat-card">
        <div className="stat-label">Bireysel Kural</div>
        <div className="stat-value accent">{status?.rule_count ?? totalRules}</div>
        <div className="stat-sub">tüm dosyalarda toplam</div>
      </div>
      <div className="stat-card">
        <div className="stat-label">Aktif Dosya</div>
        <div className="stat-value green">{activeFiles}</div>
        <div className="stat-sub">/ {files.length} toplam .yar</div>
      </div>
      <div className="stat-card">
        <div className="stat-label">VT Entegrasyon</div>
        <div className={`stat-value ${status?.vt_enabled?'accent':'red'}`} style={{fontSize:18,marginTop:4}}>
          {status?.vt_enabled ? '● AÇIK' : '○ KAPALI'}
        </div>
        <div className="stat-sub">VirusTotal API</div>
      </div>
    </div>

    {loading ? <div className="spinner"/> : (<div style={{display:'grid',gridTemplateColumns:'340px 1fr',gap:20,alignItems:'start'}}>

      {/* Sol: Kural Dosyaları */}
      <div>
        <div className="card" style={{marginBottom:16}}>
          <div className="card-header">
            <span className="card-title">Kural Dosyaları</span>
            <div style={{display:'flex',gap:6}}>
              {/* Dosya Yükle */}
              <button onClick={()=>uploadRef.current?.click()}
                style={{background:'rgba(0,255,136,0.1)',border:'1px solid rgba(0,255,136,0.3)',
                  borderRadius:6,color:'var(--green)',padding:'4px 10px',fontSize:11,cursor:'pointer'}}>
                ⬆ Yükle
              </button>
              <input ref={uploadRef} type="file" accept=".yar,.yara" style={{display:'none'}}
                onChange={e=>{ if(e.target.files?.[0]) uploadFile(e.target.files[0]); e.target.value='' }}/>
              <button onClick={reloadRules} disabled={reloading}
                style={{background:'rgba(0,212,255,0.1)',border:'1px solid rgba(0,212,255,0.3)',
                  borderRadius:6,color:'var(--accent)',padding:'4px 10px',fontSize:11,cursor:'pointer'}}>
                {reloading ? '↻…' : '↻ Yenile'}
              </button>
            </div>
          </div>
          <div style={{display:'flex',flexDirection:'column',gap:8}}>
            {files.map(f => {
              const isDisabled = status?.disabled_files?.includes(f.file) ?? false
              return (
                <div key={f.file} className="yara-rule-card"
                  style={{opacity:isDisabled?0.5:1,
                    borderColor:activeFile?.file===f.file?'var(--accent)':'var(--border)',
                    cursor:'pointer'}}
                  onClick={()=>setActiveFile(activeFile?.file===f.file?null:f)}>
                  <div style={{display:'flex',justifyContent:'space-between',alignItems:'center'}}>
                    <span className="yara-rule-name" style={{color:isDisabled?'var(--text-dim)':'var(--orange)'}}>
                      📄 {f.file}
                    </span>
                    {/* Toggle Switch */}
                    <button
                      disabled={toggling===f.file}
                      onClick={e=>{e.stopPropagation(); toggleFile(f.file)}}
                      style={{
                        background: isDisabled?'rgba(255,255,255,0.08)':'rgba(0,255,136,0.15)',
                        border: `1px solid ${isDisabled?'var(--border)':'rgba(0,255,136,0.4)'}`,
                        borderRadius:20, color: isDisabled?'var(--text-muted)':'var(--green)',
                        padding:'2px 10px', fontSize:10, cursor:'pointer', fontWeight:600,
                        transition:'all 0.2s'
                      }}>
                      {toggling===f.file?'…':isDisabled?'Kapalı':'Açık'}
                    </button>
                  </div>
                  <div style={{display:'flex',justifyContent:'space-between',marginTop:4}}>
                    <span style={{fontSize:10,color:'var(--text-muted)'}}>{f.rule_count} bireysel kural</span>
                    <span style={{fontSize:9,color:'var(--text-dim)'}}>{(f.size/1024).toFixed(1)} KB</span>
                  </div>
                  {f.editable && <span style={{fontSize:9,color:'var(--accent)',display:'block',marginTop:2}}>✏ Editörde düzenlenebilir</span>}
                  {f.error && <span style={{fontSize:10,color:'var(--red)',display:'block',marginTop:2}}>⚠ {f.error}</span>}
                </div>
              )
            })}
          </div>
        </div>

        {/* Seçili dosyanın kural listesi */}
        {activeFile && activeFile.rules.length > 0 && (
          <div className="card">
            <div className="card-header">
              <span className="card-title">{activeFile.file}</span>
              <span style={{fontSize:10,color:'var(--text-muted)'}}>{activeFile.rule_count} kural</span>
            </div>
            <div style={{display:'flex',flexDirection:'column',gap:6,maxHeight:360,overflowY:'auto'}}>
              {activeFile.rules.map((r,i) => (
                <div key={i} className="yara-rule-card">
                  <div className="yara-rule-name">⚡ {r.name}</div>
                  {r.description && <div className="yara-rule-desc">{r.description}</div>}
                  <div style={{display:'flex',gap:6,marginTop:4}}>
                    <span style={{fontSize:9,color:sevColor(r.severity),
                      border:`1px solid ${sevColor(r.severity)}`,borderRadius:3,padding:'1px 5px'}}>
                      {r.severity}
                    </span>
                    <span style={{fontSize:9,color:'var(--text-dim)'}}>skor:{r.score}</span>
                  </div>
                </div>
              ))}
            </div>
          </div>
        )}
      </div>

      {/* Sağ: Özel Kural Editörü */}
      <div className="card">
        <div className="card-header">
          <span className="card-title">✏ Özel Kurallar — custom_rules.yar</span>
          <div style={{display:'flex',gap:8}}>
            <button onClick={()=>setEditorContent(YARA_TEMPLATE)}
              style={{background:'transparent',border:'1px solid var(--border)',borderRadius:6,
                color:'var(--text-muted)',padding:'4px 10px',fontSize:11,cursor:'pointer'}}>
              Şablon
            </button>
            <button onClick={saveRules} disabled={saving}
              style={{background:'linear-gradient(135deg,var(--accent),#0099cc)',border:'none',
                borderRadius:6,color:'#050812',padding:'6px 16px',fontSize:12,fontWeight:700,
                cursor:saving?'not-allowed':'pointer',opacity:saving?0.7:1}}>
              {saving?'⏳ Kaydediliyor…':'💾 Kaydet & Uygula'}
            </button>
          </div>
        </div>
        <div style={{fontSize:11,color:'var(--text-muted)',marginBottom:10,lineHeight:1.6}}>
          Kaydedildiğinde anında devreye girer — servis yeniden başlatma gerekmez.
          Başka dosya yüklemek için sol paneldeki <strong style={{color:'var(--green)'}}>⬆ Yükle</strong> butonunu kullan.
        </div>
        <textarea
          className="yara-editor"
          value={editorContent}
          onChange={e=>setEditorContent(e.target.value)}
          spellCheck={false}
        />
        <div style={{marginTop:10,padding:'8px 12px',background:'rgba(0,212,255,0.04)',
          borderRadius:6,border:'1px solid rgba(0,212,255,0.12)',fontSize:11,color:'var(--text-muted)'}}>
          💡 <strong style={{color:'var(--accent)'}}>Format:</strong>{' '}
          <code style={{color:'var(--orange)',background:'rgba(255,153,64,0.1)',padding:'1px 4px',borderRadius:3}}>
            rule AD {'{ meta: description="..." severity="high" score=80 strings: $s="..." condition: any of them }'}
          </code>
        </div>
      </div>
    </div>)}

    {toast && <Toast msg={toast.msg} type={toast.type}/>}
  </>)
}

