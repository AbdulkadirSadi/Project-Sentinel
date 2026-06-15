'use client'
import { useEffect, useState, useRef, useCallback } from 'react'
import { AreaChart, Area, XAxis, YAxis, Tooltip, ResponsiveContainer, PieChart, Pie, Cell, BarChart, Bar, Legend } from 'recharts'
import { Sidebar, Toast, ProcessTreeModal, ActionModal, RulesPage, ScanPage, ThreatIntelPage, YaraRulesPage, fmt, ago, shortId, osIcon, scoreColor, alertCls, PIE_COLORS } from './components'
import type { Agent, Alert, MetricPoint, ProcessNode } from './components'

/* ── Types ──────────────────────────────────────────────────────────────────── */
interface DetectionRule {
  id: number
  name: string
  description: string
  rule_text: string
  threat_type: string
  score: number
  enabled: boolean
  created_at: number
}

/* ── Dashboard ──────────────────────────────────────────────────────────────── */

interface BeatSummary {
  process_beat: { total:number; last_hour:number; top_processes:{name:string;count:number}[]; agents:{agent_id:string;count:number}[] }
  network_beat: { total:number; last_hour:number; top_ports:{port:number;count:number}[]; agents:{agent_id:string;count:number}[] }
  file_beat:    { total:number; last_hour:number; malware_count:number; agents:{agent_id:string;count:number}[] }
  alert_beat:   { total:number; last_hour:number; critical:number; by_type:{type:string;count:number}[] }
  system_beat:  { agents:{agent_id:string;cpu:number;ram_pct:number}[]; avg_cpu:number; avg_ram:number }
}

function DashboardPage({ agents, alerts, metrics, onNav }: { agents:Agent[]; alerts:Alert[]; metrics:MetricPoint[]; onNav:(p:string)=>void }) {
  const open     = alerts.filter(a=>!a.resolved).length
  const critical = alerts.filter(a=>a.risk_score>=90&&!a.resolved).length
  const autoAct  = alerts.filter(a=>a.action_taken&&a.action_taken!=='none').length
  const recent   = [...alerts].sort((a,b)=>b.ts-a.ts).slice(0,8)
  const [beats, setBeats] = useState<BeatSummary|null>(null)

  useEffect(() => {
    const fetchBeats = () =>
      fetch('/api/ai/beats/summary')
        .then(r => r.ok ? r.json() : null)
        .then(d => { if (d) setBeats(d) })
        .catch(() => {})
    fetchBeats()
    const t = setInterval(fetchBeats, 30000)
    return () => clearInterval(t)
  }, [])

  // Tehdit tipi dağılımı (pie)
  const typeCounts: Record<string,number> = {}
  alerts.forEach(a=>{ if(a.threat_type&&a.threat_type!=='none') typeCounts[a.threat_type]=(typeCounts[a.threat_type]||0)+1 })
  const pieData = Object.entries(typeCounts).map(([name,value])=>({name,value}))

  // Son 7 günlük alert trendi
  const trendData = (() => {
    const days: Record<string,{date:string;toplam:number;kritik:number}> = {}
    const now = Math.floor(Date.now()/1000)
    for (let i=6;i>=0;i--) {
      const d = new Date((now - i*86400)*1000)
      const key = d.toLocaleDateString('tr-TR',{month:'short',day:'numeric'})
      days[key]={date:key,toplam:0,kritik:0}
    }
    alerts.forEach(a=>{
      const d = new Date(a.ts*1000)
      const key = d.toLocaleDateString('tr-TR',{month:'short',day:'numeric'})
      if(key in days){days[key].toplam++;if(a.risk_score>=90)days[key].kritik++}
    })
    return Object.values(days)
  })()

  return (<>
    <div className="page-header"><h2>Dashboard</h2><p>Sistem genelinde tehdit durumu ve ajan sağlığı</p></div>
    <div className="stats-grid">
      <div className="stat-card"><div className="stat-label">Aktif Ajan</div><div className="stat-value accent">{agents.length}</div><div className="stat-sub">Çevrimiçi</div></div>
      <div className="stat-card"><div className="stat-label">Açık Alert</div><div className="stat-value red">{open}</div><div className="stat-sub">Çözümlenmemiş</div></div>
      <div className="stat-card"><div className="stat-label">Kritik ≥90</div><div className="stat-value orange">{critical}</div><div className="stat-sub">Yüksek öncelik</div></div>
      <div className="stat-card"><div className="stat-label">Oto Yanıt</div><div className="stat-value green">{autoAct}</div><div className="stat-sub">İşlem yapıldı</div></div>
    </div>

    {/* ── XDR Beats ── */}
    <div style={{marginBottom:8}}>
      <div style={{display:'flex',alignItems:'center',gap:10,marginBottom:14}}>
        <div style={{width:3,height:18,background:'linear-gradient(180deg,var(--accent),var(--green))',borderRadius:2}}/>
        <span style={{fontSize:13,fontWeight:700,color:'var(--text)',letterSpacing:'0.04em'}}>XDR BEATS</span>
        <span style={{fontSize:10,color:'var(--text-muted)',background:'rgba(0,212,255,0.08)',border:'1px solid rgba(0,212,255,0.2)',padding:'2px 8px',borderRadius:20}}>Son 24s</span>
        {!beats && <span style={{fontSize:10,color:'var(--text-dim)'}}>yükleniyor…</span>}
      </div>
      <div style={{display:'grid',gridTemplateColumns:'repeat(5,1fr)',gap:12}}>

        {/* Process Beat */}
        <div onClick={()=>onNav('agents')} style={{
          background:'linear-gradient(135deg,rgba(0,212,255,0.06),rgba(0,212,255,0.02))',
          border:'1px solid rgba(0,212,255,0.2)',borderRadius:12,padding:'16px 14px',
          cursor:'pointer',transition:'all .2s',position:'relative',overflow:'hidden'
        }}
        onMouseOver={e=>(e.currentTarget.style.borderColor='rgba(0,212,255,0.5)',e.currentTarget.style.transform='translateY(-2px)')}
        onMouseOut={e=>(e.currentTarget.style.borderColor='rgba(0,212,255,0.2)',e.currentTarget.style.transform='translateY(0)')}
        >
          <div style={{position:'absolute',top:0,right:0,width:60,height:60,background:'radial-gradient(circle,rgba(0,212,255,0.1),transparent)',borderRadius:'50%',transform:'translate(20px,-20px)'}}/>
          <div style={{display:'flex',alignItems:'center',justifyContent:'space-between',marginBottom:8}}>
            <span style={{fontSize:18}}>⚙️</span>
            <span style={{fontSize:9,fontWeight:700,color:'var(--accent)',background:'rgba(0,212,255,0.1)',padding:'2px 6px',borderRadius:4,letterSpacing:'0.05em'}}>PROCESS</span>
          </div>
          <div style={{fontSize:26,fontWeight:800,color:'var(--text)',lineHeight:1}}>{(beats?.process_beat.total ?? 0).toLocaleString()}</div>
          <div style={{fontSize:10,color:'var(--text-muted)',marginTop:3}}>event / 24s</div>
          <div style={{marginTop:10,display:'flex',gap:4,flexWrap:'wrap'}}>
            {(beats?.process_beat.top_processes ?? []).slice(0,3).map((p,i)=>(
              <span key={i} style={{fontSize:8,padding:'2px 5px',borderRadius:3,background:'rgba(0,212,255,0.08)',color:'var(--accent)',fontFamily:'monospace',maxWidth:70,overflow:'hidden',textOverflow:'ellipsis',whiteSpace:'nowrap'}}>{p.name}</span>
            ))}
          </div>
          <div style={{marginTop:8,paddingTop:8,borderTop:'1px solid rgba(0,212,255,0.1)',display:'flex',alignItems:'center',gap:6}}>
            <div style={{width:6,height:6,borderRadius:'50%',background:'var(--accent)',animation:'pulse 2s infinite'}}/>
            <span style={{fontSize:9,color:'var(--text-muted)'}}>{beats?.process_beat.last_hour ?? 0} son 1s</span>
          </div>
        </div>

        {/* Network Beat */}
        <div onClick={()=>onNav('agents')} style={{
          background:'linear-gradient(135deg,rgba(0,255,136,0.06),rgba(0,255,136,0.02))',
          border:'1px solid rgba(0,255,136,0.2)',borderRadius:12,padding:'16px 14px',
          cursor:'pointer',transition:'all .2s',position:'relative',overflow:'hidden'
        }}
        onMouseOver={e=>(e.currentTarget.style.borderColor='rgba(0,255,136,0.5)',e.currentTarget.style.transform='translateY(-2px)')}
        onMouseOut={e=>(e.currentTarget.style.borderColor='rgba(0,255,136,0.2)',e.currentTarget.style.transform='translateY(0)')}
        >
          <div style={{position:'absolute',top:0,right:0,width:60,height:60,background:'radial-gradient(circle,rgba(0,255,136,0.1),transparent)',borderRadius:'50%',transform:'translate(20px,-20px)'}}/>
          <div style={{display:'flex',alignItems:'center',justifyContent:'space-between',marginBottom:8}}>
            <span style={{fontSize:18}}>🌐</span>
            <span style={{fontSize:9,fontWeight:700,color:'var(--green)',background:'rgba(0,255,136,0.1)',padding:'2px 6px',borderRadius:4,letterSpacing:'0.05em'}}>NETWORK</span>
          </div>
          <div style={{fontSize:26,fontWeight:800,color:'var(--text)',lineHeight:1}}>{(beats?.network_beat.total ?? 0).toLocaleString()}</div>
          <div style={{fontSize:10,color:'var(--text-muted)',marginTop:3}}>bağlantı / 24s</div>
          <div style={{marginTop:10,display:'flex',gap:4,flexWrap:'wrap'}}>
            {(beats?.network_beat.top_ports ?? []).slice(0,4).map((p,i)=>(
              <span key={i} style={{fontSize:8,padding:'2px 5px',borderRadius:3,background:'rgba(0,255,136,0.08)',color:'var(--green)',fontFamily:'monospace'}}>:{p.port}</span>
            ))}
          </div>
          <div style={{marginTop:8,paddingTop:8,borderTop:'1px solid rgba(0,255,136,0.1)',display:'flex',alignItems:'center',gap:6}}>
            <div style={{width:6,height:6,borderRadius:'50%',background:'var(--green)',animation:'pulse 2s infinite'}}/>
            <span style={{fontSize:9,color:'var(--text-muted)'}}>{beats?.network_beat.last_hour ?? 0} son 1s</span>
          </div>
        </div>

        {/* File Integrity Beat */}
        <div onClick={()=>onNav('scan')} style={{
          background:'linear-gradient(135deg,rgba(255,153,64,0.06),rgba(255,153,64,0.02))',
          border:`1px solid ${(beats?.file_beat.malware_count??0)>0?'rgba(239,68,68,0.35)':'rgba(255,153,64,0.2)'}`,
          borderRadius:12,padding:'16px 14px',
          cursor:'pointer',transition:'all .2s',position:'relative',overflow:'hidden'
        }}
        onMouseOver={e=>(e.currentTarget.style.transform='translateY(-2px)')}
        onMouseOut={e=>(e.currentTarget.style.transform='translateY(0)')}
        >
          <div style={{position:'absolute',top:0,right:0,width:60,height:60,background:'radial-gradient(circle,rgba(255,153,64,0.1),transparent)',borderRadius:'50%',transform:'translate(20px,-20px)'}}/>
          <div style={{display:'flex',alignItems:'center',justifyContent:'space-between',marginBottom:8}}>
            <span style={{fontSize:18}}>🗂️</span>
            <span style={{fontSize:9,fontWeight:700,color:'var(--orange)',background:'rgba(255,153,64,0.1)',padding:'2px 6px',borderRadius:4,letterSpacing:'0.05em'}}>FILE INT.</span>
          </div>
          <div style={{fontSize:26,fontWeight:800,color:'var(--text)',lineHeight:1}}>{(beats?.file_beat.total ?? 0).toLocaleString()}</div>
          <div style={{fontSize:10,color:'var(--text-muted)',marginTop:3}}>tarama / 24s</div>
          {(beats?.file_beat.malware_count??0) > 0 && (
            <div style={{marginTop:8,display:'flex',alignItems:'center',gap:5,padding:'4px 8px',background:'rgba(239,68,68,0.1)',borderRadius:6,border:'1px solid rgba(239,68,68,0.2)'}}>
              <span style={{fontSize:10}}>⚠️</span>
              <span style={{fontSize:10,fontWeight:700,color:'var(--red)'}}>{beats!.file_beat.malware_count} zararlı</span>
            </div>
          )}
          <div style={{marginTop:8,paddingTop:8,borderTop:'1px solid rgba(255,153,64,0.1)',display:'flex',alignItems:'center',gap:6}}>
            <div style={{width:6,height:6,borderRadius:'50%',background:'var(--orange)',animation:'pulse 2s infinite'}}/>
            <span style={{fontSize:9,color:'var(--text-muted)'}}>{beats?.file_beat.last_hour ?? 0} son 1s</span>
          </div>
        </div>

        {/* Alert Beat */}
        <div onClick={()=>onNav('alerts')} style={{
          background:'linear-gradient(135deg,rgba(239,68,68,0.06),rgba(239,68,68,0.02))',
          border:`1px solid ${(beats?.alert_beat.critical??0)>0?'rgba(239,68,68,0.4)':'rgba(239,68,68,0.2)'}`,
          borderRadius:12,padding:'16px 14px',
          cursor:'pointer',transition:'all .2s',position:'relative',overflow:'hidden'
        }}
        onMouseOver={e=>(e.currentTarget.style.borderColor='rgba(239,68,68,0.6)',e.currentTarget.style.transform='translateY(-2px)')}
        onMouseOut={e=>(e.currentTarget.style.borderColor=(beats?.alert_beat.critical??0)>0?'rgba(239,68,68,0.4)':'rgba(239,68,68,0.2)',e.currentTarget.style.transform='translateY(0)')}
        >
          <div style={{position:'absolute',top:0,right:0,width:60,height:60,background:'radial-gradient(circle,rgba(239,68,68,0.1),transparent)',borderRadius:'50%',transform:'translate(20px,-20px)'}}/>
          <div style={{display:'flex',alignItems:'center',justifyContent:'space-between',marginBottom:8}}>
            <span style={{fontSize:18}}>⚡</span>
            <span style={{fontSize:9,fontWeight:700,color:'var(--red)',background:'rgba(239,68,68,0.1)',padding:'2px 6px',borderRadius:4,letterSpacing:'0.05em'}}>ALERT</span>
          </div>
          <div style={{fontSize:26,fontWeight:800,color:'var(--text)',lineHeight:1}}>{(beats?.alert_beat.total ?? 0).toLocaleString()}</div>
          <div style={{fontSize:10,color:'var(--text-muted)',marginTop:3}}>alert / 24s</div>
          {(beats?.alert_beat.critical??0) > 0 && (
            <div style={{marginTop:8,display:'flex',alignItems:'center',gap:5,padding:'4px 8px',background:'rgba(239,68,68,0.12)',borderRadius:6,border:'1px solid rgba(239,68,68,0.3)'}}>
              <span style={{fontSize:10}}>🔴</span>
              <span style={{fontSize:10,fontWeight:700,color:'var(--red)'}}>{beats!.alert_beat.critical} kritik</span>
            </div>
          )}
          <div style={{marginTop:8,paddingTop:8,borderTop:'1px solid rgba(239,68,68,0.1)',display:'flex',alignItems:'center',gap:6}}>
            <div style={{width:6,height:6,borderRadius:'50%',background:'var(--red)',animation:'pulse 1.5s infinite'}}/>
            <span style={{fontSize:9,color:'var(--text-muted)'}}>{beats?.alert_beat.last_hour ?? 0} son 1s</span>
          </div>
        </div>

        {/* System Beat */}
        <div onClick={()=>onNav('dashboard')} style={{
          background:'linear-gradient(135deg,rgba(167,139,250,0.06),rgba(167,139,250,0.02))',
          border:'1px solid rgba(167,139,250,0.2)',borderRadius:12,padding:'16px 14px',
          cursor:'pointer',transition:'all .2s',position:'relative',overflow:'hidden'
        }}
        onMouseOver={e=>(e.currentTarget.style.borderColor='rgba(167,139,250,0.5)',e.currentTarget.style.transform='translateY(-2px)')}
        onMouseOut={e=>(e.currentTarget.style.borderColor='rgba(167,139,250,0.2)',e.currentTarget.style.transform='translateY(0)')}
        >
          <div style={{position:'absolute',top:0,right:0,width:60,height:60,background:'radial-gradient(circle,rgba(167,139,250,0.1),transparent)',borderRadius:'50%',transform:'translate(20px,-20px)'}}/>
          <div style={{display:'flex',alignItems:'center',justifyContent:'space-between',marginBottom:8}}>
            <span style={{fontSize:18}}>💻</span>
            <span style={{fontSize:9,fontWeight:700,color:'#a78bfa',background:'rgba(167,139,250,0.1)',padding:'2px 6px',borderRadius:4,letterSpacing:'0.05em'}}>SYSTEM</span>
          </div>
          <div style={{display:'flex',gap:12,alignItems:'flex-end'}}>
            <div>
              <div style={{fontSize:20,fontWeight:800,color:'var(--text)',lineHeight:1}}>{beats?.system_beat.avg_cpu ?? (metrics.length>0?metrics[metrics.length-1].cpu.toFixed(0):0)}%</div>
              <div style={{fontSize:9,color:'#a78bfa',marginTop:2}}>CPU ort.</div>
            </div>
            <div>
              <div style={{fontSize:20,fontWeight:800,color:'var(--text)',lineHeight:1}}>{beats?.system_beat.avg_ram ?? (metrics.length>0?metrics[metrics.length-1].ram.toFixed(0):0)}%</div>
              <div style={{fontSize:9,color:'#a78bfa',marginTop:2}}>RAM ort.</div>
            </div>
          </div>
          <div style={{marginTop:10,display:'flex',flexDirection:'column',gap:3}}>
            {(beats?.system_beat.agents ?? []).slice(0,2).map((a,i)=>(
              <div key={i} style={{display:'flex',alignItems:'center',gap:4}}>
                <span style={{fontSize:8,color:'var(--text-dim)',fontFamily:'monospace',width:50,overflow:'hidden',textOverflow:'ellipsis',whiteSpace:'nowrap'}}>{a.agent_id.slice(0,8)}</span>
                <div style={{flex:1,height:3,background:'var(--border)',borderRadius:2,overflow:'hidden'}}>
                  <div style={{width:`${a.cpu}%`,height:'100%',background:'#a78bfa',borderRadius:2}}/>
                </div>
                <span style={{fontSize:8,color:'#a78bfa',width:24,textAlign:'right'}}>{a.cpu}%</span>
              </div>
            ))}
          </div>
        </div>

      </div>
    </div>

    <div className="dashboard-grid">
      {/* CPU/RAM Trend */}
      <div className="card">
        <div className="card-header"><span className="card-title">CPU / RAM Trendi (Ortalama)</span></div>
        <ResponsiveContainer width="100%" height={200}>
          <AreaChart data={metrics}>
            <defs>
              <linearGradient id="gCpu" x1="0" y1="0" x2="0" y2="1"><stop offset="5%" stopColor="var(--accent)" stopOpacity={0.3}/><stop offset="95%" stopColor="var(--accent)" stopOpacity={0}/></linearGradient>
              <linearGradient id="gRam" x1="0" y1="0" x2="0" y2="1"><stop offset="5%" stopColor="var(--green)"  stopOpacity={0.3}/><stop offset="95%" stopColor="var(--green)"  stopOpacity={0}/></linearGradient>
            </defs>
            <XAxis dataKey="time" tick={{fill:'#3d4f6e',fontSize:9}}/>
            <YAxis domain={[0,100]} tick={{fill:'#3d4f6e',fontSize:9}} unit="%"/>
            <Tooltip contentStyle={{background:'var(--bg-card)',border:'1px solid var(--border)',borderRadius:8,fontSize:11}}/>
            <Area type="monotone" dataKey="cpu" stroke="var(--accent)" fill="url(#gCpu)" name="CPU" unit="%" strokeWidth={1.5} dot={false}/>
            <Area type="monotone" dataKey="ram" stroke="var(--green)"  fill="url(#gRam)" name="RAM" unit="%" strokeWidth={1.5} dot={false}/>
          </AreaChart>
        </ResponsiveContainer>
      </div>
      {/* Alert Trend */}
      <div className="card full-width">
        <div className="card-header"><span className="card-title">Alert Trendi — Son 7 Gün</span></div>
        <ResponsiveContainer width="100%" height={180}>
          <BarChart data={trendData} barGap={4}>
            <XAxis dataKey="date" tick={{fill:'#3d4f6e',fontSize:9}}/>
            <YAxis tick={{fill:'#3d4f6e',fontSize:9}} allowDecimals={false}/>
            <Tooltip contentStyle={{background:'var(--bg-card)',border:'1px solid var(--border)',borderRadius:8,fontSize:11}}/>
            <Legend iconType="circle" iconSize={8} wrapperStyle={{fontSize:10,color:'var(--text-muted)'}}/>
            <Bar dataKey="toplam" name="Toplam" fill="var(--accent)" radius={[3,3,0,0]} maxBarSize={32}/>
            <Bar dataKey="kritik" name="Kritik (≥90)" fill="var(--red)" radius={[3,3,0,0]} maxBarSize={32}/>
          </BarChart>
        </ResponsiveContainer>
      </div>
      {/* Tehdit Dağılımı */}
      <div className="card">
        <div className="card-header"><span className="card-title">Tehdit Dağılımı</span></div>
        {pieData.length === 0 ? <div className="empty-state">Henüz alert yok</div> : (
          <ResponsiveContainer width="100%" height={200}>
            <PieChart>
              <Pie data={pieData} cx="50%" cy="50%" innerRadius={55} outerRadius={85} dataKey="value" paddingAngle={3}>
                {pieData.map((_,i)=><Cell key={i} fill={PIE_COLORS[i%PIE_COLORS.length]}/>)}
              </Pie>
              <Tooltip contentStyle={{background:'var(--bg-card)',border:'1px solid var(--border)',borderRadius:8,fontSize:11}}/>
              <Legend iconType="circle" iconSize={8} wrapperStyle={{fontSize:10,color:'var(--text-muted)'}}/>
            </PieChart>
          </ResponsiveContainer>
        )}
      </div>
      {/* Son Alertler */}
      <div className="card full-width">
        <div className="card-header"><span className="card-title">Son Alertler</span></div>
        <div className="alert-list" style={{maxHeight:280}}>
          {recent.length===0 ? <div className="empty-state">Alert yok</div> : recent.map(a=>(
            <div key={a.id} className={`alert-item ${alertCls(a.risk_score)}`}>
              <div className="alert-score" style={{color:scoreColor(a.risk_score)}}>{a.risk_score.toFixed(0)}</div>
              <div className="alert-body">
                <div className="alert-type">{(a.pname||a.threat_type).replace(/_/g,' ').toUpperCase()}</div>
                <div className="alert-detail">
                  {shortId(a.agent_id)}
                  {a.rule_name && <span style={{color:'var(--accent)',marginLeft:6,fontSize:10}}>⚙ {a.rule_name}</span>}
                  {' '}| güven:{(a.confidence*100).toFixed(0)}%
                </div>
                <div className="alert-time">{fmt(a.ts)}</div>
              </div>
              {a.action_taken&&a.action_taken!=='none'
                ? <span className="alert-badge badge-auto">{a.action_taken.replace(/_/g,' ')}</span>
                : <span className="alert-badge badge-open" style={{cursor:'pointer'}} onClick={()=>onNav('alerts')}>OPEN</span>}
            </div>
          ))}
        </div>
      </div>
    </div>
  </>) 
}

/* ── Agents ─────────────────────────────────────────────────────────────────── */
function AgentsPage({ agents, onAction, onControlCalib }: { agents:Agent[]; onAction:(a:Agent)=>void; onControlCalib:(id:string, act:string)=>void }) {
  return (<>
    <div className="page-header"><h2>Agents</h2><p>{agents.length} ajan bağlı</p></div>
    <div className="agent-list">
      {agents.length===0 ? <div className="card"><div className="empty-state">Bağlı ajan yok</div></div> : agents.map(a=>(
        <div key={a.id} className="agent-card">
          <div className="agent-header">
            <span className="agent-os-icon">{osIcon(a.os)}</span>
            <div>
              <div style={{fontFamily:'monospace',fontSize:12,color:'var(--text-primary)'}}>{shortId(a.id)}</div>
              <div className="agent-addr">{a.addr}</div>
            </div>
            <span className={`badge badge-${a.offline ? 'red' : 'green'}`} style={{marginLeft:'auto'}}>
              {a.offline ? '● OFFLINE' : '● ONLINE'}
            </span>
          </div>
          <div className="metric-bar">
            <div className="metric-label"><span>CPU</span><span>{(a.cpu??0).toFixed(1)}%</span></div>
            <div className="bar-track"><div className={`bar-fill ${(a.cpu??0)>75?'bar-orange':'bar-green'}`} style={{width:`${Math.min(a.cpu??0,100)}%`}}/></div>
          </div>
          <div className="metric-bar">
            <div className="metric-label"><span>RAM</span><span>{(a.ram_pct??0).toFixed(1)}%</span></div>
            <div className="bar-track"><div className={`bar-fill ${(a.ram_pct??0)>80?'bar-orange':'bar-green'}`} style={{width:`${Math.min(a.ram_pct??0,100)}%`}}/></div>
          </div>
          <div className="agent-actions" style={{display:'flex',justifyContent:'space-between',alignItems:'center'}}>
            <div style={{display:'flex',gap:6,background:'var(--bg)',padding:'4px 8px',borderRadius:6,border:'1px solid var(--border)',alignItems:'center'}}>
              <span style={{fontSize:10,color:'var(--text-muted)'}}>AI:</span>
              {a.calibrated ? (
                <span className="badge badge-green" style={{fontSize:9}}>Öğrendi</span>
              ) : a.calib_start && a.calib_start > 0 ? (
                <span className="badge badge-orange" style={{fontSize:9}}>Öğreniyor</span>
              ) : (
                <span className="badge badge-red" style={{fontSize:9}}>Sıfır</span>
              )}
              {(!a.calibrated && (!a.calib_start || a.calib_start === 0)) && <button className="action-btn" style={{fontSize:9,padding:'2px 6px'}} onClick={()=>onControlCalib(a.id, 'start')}>▶ Başlat</button>}
              {(!a.calibrated && a.calib_start && a.calib_start > 0) && <button className="action-btn" style={{fontSize:9,padding:'2px 6px',borderColor:'var(--orange)',color:'var(--orange)'}} onClick={()=>onControlCalib(a.id, 'stop')}>⏹ Bitir</button>}
              <button className="action-btn" style={{fontSize:9,padding:'2px 6px',borderColor:'var(--red)',color:'var(--red)'}} onClick={()=>onControlCalib(a.id, 'reset')}>↺ Sıfırla</button>
            </div>
            <button className="action-btn shell" onClick={()=>onAction(a)}>⬡ Eylem Gönder</button>
          </div>
        </div>
      ))}
    </div>
  </>)
}

/* ── Alerts ─────────────────────────────────────────────────────────────────── */
function AlertsPage({ alerts, onResolve, onTree, onAlertAction }: { alerts:Alert[]; onResolve:(id:number)=>void; onTree:(agentId:string,pid:number,pname:string)=>void; onAlertAction:(agentId:string,action:string,params:Record<string,string>)=>void }) {
  const [search,    setSearch]    = useState('')
  const [sevFilter, setSevFilter] = useState<'all'|'critical'|'high'|'medium'>('all')
  const [srcFilter, setSrcFilter] = useState<'all'|'auto'|'yara'|'vt'|'behavioral'>('all')
  const [typeFilter,setTypeFilter]= useState('')
  const sorted = [...alerts].sort((a,b)=>b.ts-a.ts)
  const filtered = sorted.filter(a => {
    if (search) { const q=search.toLowerCase(); if(!a.pname?.toLowerCase().includes(q)&&!a.threat_type?.toLowerCase().includes(q)&&!a.rule_name?.toLowerCase().includes(q)) return false }
    if (sevFilter==='critical' && a.risk_score<90) return false
    if (sevFilter==='high'     && a.risk_score<70) return false
    if (sevFilter==='medium'   && (a.risk_score<40||a.risk_score>=70)) return false
    if (srcFilter==='auto'  && !(a.rule_name||'').startsWith('AutoScan')) return false
    if (srcFilter==='yara'  && !(a.rule_name||'').startsWith('YARA:')) return false
    if (srcFilter==='vt'    && !(a.rule_name||'').startsWith('VirusTotal:')) return false
    if (srcFilter==='behavioral' && ((a.rule_name||'').startsWith('AutoScan')||(a.rule_name||'').startsWith('YARA:')||(a.rule_name||'').startsWith('VirusTotal:')||(a.rule_name||'').startsWith('HashDB:'))) return false
    if (typeFilter && a.threat_type!==typeFilter) return false
    return true
  })
  const threatTypes = [...new Set(sorted.map(a=>a.threat_type).filter(Boolean))].slice(0,12)
  return (<>
    <div className="page-header"><h2>Alerts</h2><p>{filtered.filter(a=>!a.resolved).length} görüntülenen / {alerts.filter(a=>!a.resolved).length} toplam açık</p></div>

    {/* Filtre Çubuğu */}
    <div className="filter-bar">
      <input
        type="text"
        placeholder="🔍 Ara: dosya, tehdit, kural…"
        value={search} onChange={e=>setSearch(e.target.value)}
      />
      <select value={sevFilter} onChange={e=>setSevFilter(e.target.value as typeof sevFilter)}>
        <option value="all">Tüm Seviyeler</option>
        <option value="critical">🔴 Kritik (≥90)</option>
        <option value="high">🟠 Yüksek (≥70)</option>
        <option value="medium">🟡 Orta (40-70)</option>
      </select>
      <select value={srcFilter} onChange={e=>setSrcFilter(e.target.value as typeof srcFilter)}>
        <option value="all">Tüm Kaynaklar</option>
        <option value="auto">⚙ Auto Scan</option>
        <option value="yara">⚡ YARA</option>
        <option value="vt">🛡 VirusTotal</option>
        <option value="behavioral">🧠 Behavioral</option>
      </select>
      <select value={typeFilter} onChange={e=>setTypeFilter(e.target.value)}>
        <option value="">Tüm Tipler</option>
        {threatTypes.map(t=><option key={t} value={t}>{t}</option>)}
      </select>
      {(search||sevFilter!=='all'||srcFilter!=='all'||typeFilter) &&
        <button className="filter-clear" onClick={()=>{setSearch('');setSevFilter('all');setSrcFilter('all');setTypeFilter('')}}>
          ✕ Temizle
        </button>}
    </div>
    <div className="card">
      <div className="alert-list" style={{maxHeight:'72vh'}}>
        {filtered.length===0 ? <div className="empty-state">Filtre koşuluna uyan alert yok</div> : filtered.map(a => {
          const isAutoScan = (a.rule_name||'').startsWith('AutoScan')
          const filePath   = a.pname || ''
          return (
          <div key={a.id} className={`alert-item ${alertCls(a.risk_score)}`} style={{opacity:a.resolved?0.45:1}}>
            <div className="alert-score" style={{color:scoreColor(a.risk_score)}}>{a.risk_score.toFixed(0)}</div>
            <div className="alert-body">
              <div className="alert-type">
                {isAutoScan && <span style={{background:'rgba(99,102,241,0.15)',color:'#818cf8',fontSize:9,padding:'1px 5px',borderRadius:3,marginRight:5,fontWeight:700}}>● AUTO</span>}
                {(a.pname || a.threat_type).replace(/_/g,' ').toUpperCase()}
              </div>
              <div className="alert-detail">
                {shortId(a.agent_id)}
                {a.rule_name && <span style={{color:'var(--accent)',marginLeft:6,fontSize:10}}>⚙ {a.rule_name}</span>}
                {a.pid && a.pid > 0 && <span style={{color:'var(--text-dim)',marginLeft:6,fontSize:10}}>PID:{a.pid}</span>}
                {' '}| güven:{(a.confidence*100).toFixed(0)}%
              </div>
              <div className="alert-time">{fmt(a.ts)} — {ago(a.ts)}</div>
              {/* Auto-scan için hızlı aksiyon butonları */}
              {isAutoScan && !a.resolved && (
                <div style={{display:'flex',gap:4,marginTop:6,flexWrap:'wrap'}}>
                  <button className="action-btn" style={{fontSize:9,padding:'3px 8px',borderColor:'var(--red)',color:'var(--red)'}}
                    onClick={()=>onAlertAction(a.agent_id,'isolate_network',{})}>
                    🔌 Ağdan Kopar
                  </button>
                  <button className="action-btn" style={{fontSize:9,padding:'3px 8px',borderColor:'var(--orange)',color:'var(--orange)'}}
                    onClick={()=>{ if(filePath) onAlertAction(a.agent_id,'quarantine_file',{path:filePath}) }}
                    disabled={!filePath}>
                    🗂 Karantinaya Al
                  </button>
                  <button className="action-btn" style={{fontSize:9,padding:'3px 8px',borderColor:'#6b7280',color:'#9ca3af'}}
                    onClick={()=>{ if(filePath&&window.confirm(`Dosya kalıcı silinecek: ${filePath}`)) onAlertAction(a.agent_id,'delete_file',{path:filePath}) }}
                    disabled={!filePath}>
                    ⚠ Dosyayı Sil
                  </button>
                </div>
              )}
            </div>
            <div style={{display:'flex',flexDirection:'column',gap:4,alignItems:'flex-end'}}>
              {a.action_taken&&a.action_taken!=='none'
                ? <span className="alert-badge badge-auto">{a.action_taken.replace(/_/g,' ')}</span>
                : <span className="alert-badge badge-open">OPEN</span>}
              <div style={{display:'flex',gap:4}}>
                {(a.pid && a.pid > 0)
                  ? <button className="action-btn shell" style={{fontSize:9,padding:'2px 6px'}}
                      onClick={()=>onTree(a.agent_id, a.pid!, a.pname||a.threat_type)}>🌳 Ağaç</button>
                  : <span style={{fontSize:9,color:'var(--text-dim)',padding:'2px 6px'}}>PID yok</span>
                }
                {!a.resolved&&<button className="action-btn kill" style={{fontSize:9,padding:'2px 6px'}} onClick={()=>onResolve(a.id)}>✓</button>}
              </div>
            </div>
          </div>
        )})}
      </div>
    </div>
  </>)
}


/* ── Terminal ───────────────────────────────────────────────────────────────── */
function TerminalPage({ agents }: { agents:Agent[] }) {
  const [selectedAgent, setSelectedAgent] = useState('')
  const [cmd, setCmd]     = useState('')
  const [lines, setLines] = useState<string[]>(['[Sentinel Terminal] Ajan seç ve komut gir.',''])
  const [history, setHistory] = useState<string[]>([])
  const [histIdx, setHistIdx] = useState(-1)
  const outputRef = useRef<HTMLDivElement>(null)

  // Cevapları poll et
  useEffect(() => {
    if (!selectedAgent) return
    const iv = setInterval(async () => {
      try {
        const token = typeof window !== 'undefined' ? localStorage.getItem('sentinel_token') : ''
        const r = await fetch(`/api/go/api/shell/result?agent_id=${selectedAgent}`, {
          headers: { 'Authorization': `Bearer ${token}` }
        })
        if (r.status === 401) { setLines(prev=>[...prev,'[HATA] Oturum süresi doldu, lütfen tekrar giriş yapın.']); return }
        if (!r.ok) return
        const data: string[] = await r.json()
        if (data.length > 0) {
          setLines(prev => [...prev, ...data.map(l=>`  ${l}`), ''])
        }
      } catch {}
    }, 800)
    return () => clearInterval(iv)
  }, [selectedAgent])

  // Çıktı en alta scroll
  useEffect(() => { if (outputRef.current) outputRef.current.scrollTop = outputRef.current.scrollHeight }, [lines])

  const send = async () => {
    if (!selectedAgent || !cmd.trim()) return
    const c = cmd.trim()
    setLines(prev => [...prev, `${shortId(selectedAgent)} $ ${c}`])
    setHistory(prev => [c, ...prev.slice(0,49)])
    setHistIdx(-1)
    setCmd('')
    try {
      const token = typeof window !== 'undefined' ? localStorage.getItem('sentinel_token') : ''
      const r = await fetch('/api/go/api/shell', {
        method:'POST',
        headers:{'Content-Type':'application/json', 'Authorization': `Bearer ${token}`},
        body: JSON.stringify({ agent_id: selectedAgent, cmd: c })
      })
      if (r.status === 401) setLines(prev=>[...prev,'[HATA] Oturum süresi doldu.'])
      else if (!r.ok) setLines(prev=>[...prev,`[HATA] Sunucu hatası: ${r.status}`])
    } catch { setLines(prev=>[...prev,'[HATA] Bağlantı kurulamadı']) }
  }

  const onKey = (e: React.KeyboardEvent) => {
    if (e.key === 'Enter') { send(); return }
    if (e.key === 'ArrowUp') {
      const idx = Math.min(histIdx+1, history.length-1)
      setHistIdx(idx); setCmd(history[idx]||'')
    }
    if (e.key === 'ArrowDown') {
      const idx = Math.max(histIdx-1, -1)
      setHistIdx(idx); setCmd(idx===-1?'':history[idx]||'')
    }
  }

  return (<>
    <div className="page-header"><h2>Terminal</h2><p>Ajanlara gerçek zamanlı komut gönder</p></div>
    <div className="card" style={{height:'75vh',display:'flex',flexDirection:'column'}}>
      {/* Ajan seçimi */}
      <div style={{display:'flex',gap:8,marginBottom:12,flexWrap:'wrap'}}>
        {agents.map(a=>(
          <button key={a.id} onClick={()=>{ setSelectedAgent(a.id); setLines(['[Terminal] Ajan bağlandı: '+shortId(a.id),'']) }}
            className="action-btn shell" style={{fontSize:11,padding:'6px 12px',background:selectedAgent===a.id?'var(--accent-glow)':'',borderColor:selectedAgent===a.id?'var(--accent)':''}}>
            {osIcon(a.os)} {shortId(a.id)}
          </button>
        ))}
        {agents.length===0&&<span style={{color:'var(--text-dim)',fontSize:13}}>Bağlı ajan yok</span>}
      </div>
      {/* Çıktı */}
      <div ref={outputRef} style={{flex:1,overflowY:'auto',fontFamily:'JetBrains Mono, monospace',fontSize:12,lineHeight:1.7,color:'var(--green)',background:'rgba(0,0,0,0.3)',borderRadius:8,padding:'12px 16px',whiteSpace:'pre-wrap',wordBreak:'break-all'}}>
        {lines.map((l,i)=>(
          <div key={i} style={{color: l.startsWith('[HATA]')?'var(--red)': l.includes('$ ')?'var(--accent)':'var(--green)'}}>{l||'\u00a0'}</div>
        ))}
      </div>
      {/* Input */}
      <div style={{display:'flex',gap:8,marginTop:10,alignItems:'center'}}>
        <span style={{fontFamily:'monospace',fontSize:12,color:'var(--accent)',whiteSpace:'nowrap'}}>
          {selectedAgent ? shortId(selectedAgent)+' $' : '(ajan seç) $'}
        </span>
        <input value={cmd} onChange={e=>setCmd(e.target.value)} onKeyDown={onKey}
          disabled={!selectedAgent}
          style={{flex:1,background:'rgba(0,0,0,0.4)',border:'1px solid var(--border)',borderRadius:6,padding:'8px 12px',color:'var(--green)',fontFamily:'JetBrains Mono,monospace',fontSize:12,outline:'none'}}
          placeholder={selectedAgent ? 'Komut gir (↑↓ geçmiş)' : 'Önce ajan seç'}
        />
        <button className="btn-primary" style={{padding:'8px 16px',fontSize:12}} onClick={send} disabled={!selectedAgent}>Gönder</button>
        <button className="btn-secondary" style={{padding:'8px 12px',fontSize:12}} onClick={()=>setLines([''])}>Temizle</button>
      </div>
    </div>
  </>)
}

/* ── Login Page ─────────────────────────────────────────────────────────────── */
function LoginPage({ onLogin }: { onLogin: (token: string, username: string, role: string) => void }) {
  const [username, setUsername] = useState('')
  const [password, setPassword] = useState('')
  const [error,    setError]    = useState('')
  const [loading,  setLoading]  = useState(false)

  const handleSubmit = async (e: React.FormEvent) => {
    e.preventDefault()
    setLoading(true); setError('')
    try {
      const r = await fetch('/api/ai/auth/login', {
        method: 'POST',
        headers: {'Content-Type': 'application/json'},
        body: JSON.stringify({username, password})
      })
      if (r.ok) {
        const d = await r.json()
        localStorage.setItem('sentinel_token', d.access_token)
        localStorage.setItem('sentinel_user',  d.username)
        localStorage.setItem('sentinel_role',  d.role)
        onLogin(d.access_token, d.username, d.role)
      } else {
        const d = await r.json()
        setError(d.detail || 'Giriş başarısız.')
      }
    } catch {
      setError('Sunucuya bağlanılamadı.')
    } finally {
      setLoading(false)
    }
  }

  return (
    <div style={{
      minHeight: '100vh', display: 'flex', alignItems: 'center', justifyContent: 'center',
      background: 'var(--bg)', fontFamily: 'Inter, system-ui, sans-serif'
    }}>
      <div style={{
        width: 380, padding: '40px 36px',
        background: 'var(--surface)', border: '1px solid var(--border)',
        borderRadius: 16, boxShadow: '0 24px 60px rgba(0,0,0,0.4)'
      }}>
        {/* Logo */}
        <div style={{textAlign:'center', marginBottom: 32}}>
          <div style={{
            width: 56, height: 56, borderRadius: 14, margin: '0 auto 14px',
            background: 'linear-gradient(135deg, #6366f1, #8b5cf6)',
            display:'flex', alignItems:'center', justifyContent:'center',
            fontSize: 28, boxShadow: '0 8px 24px rgba(99,102,241,0.4)'
          }}>🛡️</div>
          <h1 style={{margin:0, fontSize:22, fontWeight:700, color:'var(--text)'}}>Sentinel XDR</h1>
          <p style={{margin:'6px 0 0', fontSize:13, color:'var(--text-muted)'}}>Güvenlik Operasyon Merkezi</p>
        </div>

        <form onSubmit={handleSubmit}>
          <div style={{marginBottom:16}}>
            <label style={{display:'block', fontSize:12, color:'var(--text-muted)', marginBottom:6, fontWeight:500}}>
              KULLANICI ADI
            </label>
            <input
              id="login-username"
              value={username} onChange={e=>setUsername(e.target.value)}
              autoComplete="username" required
              style={{
                width:'100%', boxSizing:'border-box',
                background:'rgba(255,255,255,0.05)', border:'1px solid var(--border)',
                borderRadius:8, padding:'10px 14px', color:'var(--text)',
                fontSize:14, outline:'none',
                transition:'border-color .2s'
              }}
              onFocus={e=>e.target.style.borderColor='var(--accent)'}
              onBlur={e=>e.target.style.borderColor='var(--border)'}
              placeholder="admin"
            />
          </div>
          <div style={{marginBottom:20}}>
            <label style={{display:'block', fontSize:12, color:'var(--text-muted)', marginBottom:6, fontWeight:500}}>
              ŞİFRE
            </label>
            <input
              id="login-password"
              type="password"
              value={password} onChange={e=>setPassword(e.target.value)}
              autoComplete="current-password" required
              style={{
                width:'100%', boxSizing:'border-box',
                background:'rgba(255,255,255,0.05)', border:'1px solid var(--border)',
                borderRadius:8, padding:'10px 14px', color:'var(--text)',
                fontSize:14, outline:'none',
                transition:'border-color .2s'
              }}
              onFocus={e=>e.target.style.borderColor='var(--accent)'}
              onBlur={e=>e.target.style.borderColor='var(--border)'}
              placeholder="••••••••"
            />
          </div>

          {error && (
            <div style={{
              padding:'10px 14px', borderRadius:8, marginBottom:16,
              background:'rgba(239,68,68,0.12)', border:'1px solid rgba(239,68,68,0.3)',
              color:'var(--red)', fontSize:13
            }}>⚠️ {error}</div>
          )}

          <button
            id="login-submit"
            type="submit" disabled={loading} className="btn-primary"
            style={{width:'100%', padding:'11px', fontSize:15, fontWeight:600, borderRadius:8}}
          >
            {loading ? 'Giriş yapılıyor…' : 'Giriş Yap'}
          </button>
        </form>

        <p style={{textAlign:'center', marginTop:20, fontSize:12, color:'var(--text-muted)'}}>
          Varsayılan: <code style={{color:'var(--accent)'}}>admin / admin123</code>
        </p>
      </div>
    </div>
  )
}

/* ── App Root ───────────────────────────────────────────────────────────────── */
export default function App() {
  const [page,        setPage]        = useState('dashboard')
  const [agents,      setAgents]      = useState<Agent[]>([])
  const [alerts,      setAlerts]      = useState<Alert[]>([])
  const [metrics,     setMetrics]     = useState<MetricPoint[]>([])
  const [serverOk,    setServerOk]    = useState(false)
  const [aiOk,        setAiOk]        = useState(false)
  const [actionAgent, setActionAgent] = useState<Agent|null>(null)
  const [treeInfo,    setTreeInfo]    = useState<{agentId:string;pid:number;pname:string}|null>(null)
  const [toast,       setToast]       = useState<{msg:string;type:'success'|'error'}|null>(null)

  // ── Auth state ──────────────────────────────────────────────────────────────
  // localStorage sunucu tarafında mevcut değil (Next.js SSR), null başlat
  const [authToken,   setAuthToken]   = useState<string|null>(null)
  const [authUser,    setAuthUser]    = useState<string|null>(null)
  const [authRole,    setAuthRole]    = useState<string|null>(null)
  const [authReady,   setAuthReady]   = useState(false)  // hydration tamamlandı mı?

  // Client-side mount sonrası localStorage'dan oku
  useEffect(() => {
    const token = localStorage.getItem('sentinel_token')
    const user  = localStorage.getItem('sentinel_user')
    const role  = localStorage.getItem('sentinel_role')
    if (token) setAuthToken(token)
    if (user)  setAuthUser(user)
    if (role)  setAuthRole(role)
    setAuthReady(true)
  }, [])

  /** Auth header'lı fetch — tüm API çağrılarında kullan */
  const authFetch = useCallback((url: string, opts: RequestInit = {}) => {
    const token = typeof window !== 'undefined' ? localStorage.getItem('sentinel_token') : null
    const headers: Record<string,string> = {
      ...(opts.headers as Record<string,string> || {}),
    }
    if (token) headers['Authorization'] = `Bearer ${token}`
    return fetch(url, {...opts, headers})
  }, [])

  // ── Tüm hook'lar koşullu return'lerden ÖNCE tanımlanmalı (Rules of Hooks) ──

  const refresh = useCallback(async () => {
    try {
      const token = localStorage.getItem('sentinel_token')
      const authH: Record<string,string> = token ? {'Authorization': `Bearer ${token}`} : {}
      const [agR, alR, bR] = await Promise.all([
        fetch('/api/go/api/agents'),
        fetch('/api/ai/alerts?limit=100&unresolved_only=false', {headers: authH}),
        fetch('/api/ai/agents', {headers: authH})
      ])
      let baseData:any[] = []
      if (bR.ok) {
        const bd = await bR.json()
        if (Array.isArray(bd)) baseData = bd
      }
      if (agR.ok) {
        const d = await agR.json()
        setAgents(prev => {
          return (Array.isArray(d) ? d : []).map((ag:any) => {
            const b = baseData.find((x:any) => x.agent_id === ag.id)
            const exist = prev.find(p => p.id === ag.id)
            return { ...ag, cpu: exist?.cpu ?? 0, ram_pct: exist?.ram_pct ?? 0, calibrated: b?.calibrated, calib_start: b?.calib_start }
          })
        })
        setServerOk(true)
      } else {
        setServerOk(false)
      }
      if (alR.ok) {
        const d = await alR.json()
        setAlerts(Array.isArray(d) ? d : [])
        setAiOk(true)
      } else {
        setAiOk(false)
      }
    } catch {
      setServerOk(false)
    }
  }, [])

  const collectMetrics = useCallback(async () => {
    try {
      const r = await fetch('/api/go/api/metrics')
      if (!r.ok) return
      const data: {agent_id: string; cpu: number; ram_pct: number}[] = await r.json()
      if (!data || data.length === 0) return
      const cpu = Math.round(data.reduce((s, a) => s + (a.cpu || 0), 0) / data.length)
      const ram = Math.round(data.reduce((s, a) => s + (a.ram_pct || 0), 0) / data.length)
      const now = new Date().toLocaleTimeString('tr-TR', {hour:'2-digit', minute:'2-digit', second:'2-digit'})
      setMetrics(prev => [...prev.slice(-29), {time: now, cpu, ram}])
      setAgents(prev => prev.map(ag => {
        const m = data.find(d => d.agent_id === ag.id)
        return m ? {...ag, cpu: m.cpu, ram_pct: m.ram_pct} : ag
      }))
    } catch {}
  }, [])

  // interval'lar — koşullu return'lerden önce
  useEffect(()=>{ refresh(); const t=setInterval(refresh,5000); return()=>clearInterval(t) },[refresh])
  useEffect(()=>{ const t=setInterval(collectMetrics,5000); return()=>clearInterval(t) },[collectMetrics])

  const handleLogin = (token: string, username: string, role: string) => {
    setAuthToken(token); setAuthUser(username); setAuthRole(role)
  }

  const handleLogout = () => {
    localStorage.removeItem('sentinel_token')
    localStorage.removeItem('sentinel_user')
    localStorage.removeItem('sentinel_role')
    setAuthToken(null); setAuthUser(null); setAuthRole(null)
  }

  // ── Koşullu return'ler — tüm hook'lardan sonra ──────────────────────────────

  // Hydration tamamlanmadan hiçbir şey render etme (SSR flicker önleme)
  if (!authReady) return null

  // Oturum yoksa login ekranı göster
  if (!authToken) {
    return <LoginPage onLogin={handleLogin} />
  }

  // ── Yardımcı handler'lar (hook değil, normal fonksiyon) ─────────────────────

  const showToast = (msg:string, type:'success'|'error') => { setToast({msg,type}); setTimeout(()=>setToast(null),3500) }

  const handleControlCalib = async (agentId:string, action:string) => {
    try {
      const r = await authFetch(`/api/ai/calibrate/${agentId}/control`, {
        method: 'POST',
        headers: {'Content-Type': 'application/json'},
        body: JSON.stringify({action})
      })
      if (r.ok) {
        showToast(`Kalibrasyon ${action} başarılı`, 'success')
        refresh()
      } else {
        showToast(`Hata`, 'error')
      }
    } catch {
      showToast('Bağlantı hatası', 'error')
    }
  }

  const handleResolve = async (id:number) => {
    try {
      const r = await authFetch(`/api/ai/alerts/${id}/resolve`, {
        method: 'PATCH',
        headers: {'Content-Type': 'application/json'},
        body: JSON.stringify({notes: 'Manuel cozum'})
      })
      if (r.ok) {
        showToast('Cozumlendi', 'success')
        refresh()
      } else {
        showToast('Hata', 'error')
      }
    } catch {
      showToast('Baglanti hatasi', 'error')
    }
  }

  const handleAction = async (action:string, params:Record<string,string>) => {
    if (!actionAgent) return
    try {
      const r = await authFetch('/api/go/api/action', {
        method: 'POST',
        headers: {'Content-Type': 'application/json'},
        body: JSON.stringify({agent_id: actionAgent.id, action, params})
      })
      if (r.ok) {
        showToast(action + ' gönderildi', 'success')
      } else {
        const msg = r.status === 401 ? 'Oturum süresi doldu' : r.status === 400 ? 'Geçersiz parametre' : 'Gönderilemedi'
        showToast(msg, 'error')
      }
    } catch {
      showToast('Bağlantı hatası', 'error')
    }
  }

  return (
    <div className="layout">
      <Sidebar active={page} onNav={setPage} serverOk={serverOk} aiOk={aiOk}
        authUser={authUser} authRole={authRole} onLogout={handleLogout}/>
      <main className="main">
        {page==='dashboard' && <DashboardPage agents={agents} alerts={alerts} metrics={metrics} onNav={setPage}/>}
        {page==='agents'    && <AgentsPage    agents={agents} onAction={a=>setActionAgent(a)} onControlCalib={handleControlCalib}/>}
        {page==='alerts'    && <AlertsPage    alerts={alerts} onResolve={handleResolve}
            onTree={(aid,pid,pname)=>setTreeInfo({agentId:aid,pid,pname})}
            onAlertAction={async (agentId,action,params)=>{
              try {
                const r = await authFetch('/api/go/api/action',{
                  method:'POST', headers:{'Content-Type':'application/json'},
                  body:JSON.stringify({agent_id:agentId, action, params})
                })
                if(r.ok) showToast(action+' gönderildi','success')
                else showToast(r.status===401?'Oturum doldu':'Gönderilemedi','error')
              } catch { showToast('Bağlantı hatası','error') }
            }}/>}

        {page==='scan'      && <ScanPage/>}
        {page==='rules'     && <RulesPage/>}
        {page==='yara'      && <YaraRulesPage/>}
        {page==='threats'   && <ThreatIntelPage/>}
        {page==='terminal'  && <TerminalPage  agents={agents}/>}
      </main>
      {actionAgent && <ActionModal agent={actionAgent} onClose={()=>setActionAgent(null)} onSend={handleAction}/>}
      {treeInfo    && <ProcessTreeModal {...treeInfo} onClose={()=>setTreeInfo(null)}/>}
      {toast       && <Toast msg={toast.msg} type={toast.type}/>}
    </div>
  )
}
