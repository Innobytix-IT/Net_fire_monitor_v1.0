/* ═══════════════════════════════════════════════════════════
   NET-FIRE-MONITOR  –  dashboard.js
   Live-Dashboard: Graph, Stats, Top-Talker, Protos, Pakete
   ═══════════════════════════════════════════════════════════ */

'use strict';

window.NFM = window.NFM || {};
var NFM = window.NFM;

NFM.ppsHistory = [];
NFM.bpsHistory = [];
NFM.MAX_HIST   = 60;

// ── Formatierung ─────────────────────────────────────────────
NFM.fmtBps = bps => {
  if (bps >= 1048576) return (bps/1048576).toFixed(1) + ' MB/s';
  if (bps >= 1024)    return (bps/1024).toFixed(1) + ' KB/s';
  return bps.toFixed(0) + ' B/s';
};

// ── Graph ─────────────────────────────────────────────────────
NFM.drawGraph = () => {
  const canvas = document.getElementById('graph-canvas');
  if (!canvas) return;
  canvas.width  = canvas.offsetWidth;
  canvas.height = 80;
  const ctx = canvas.getContext('2d');
  ctx.clearRect(0, 0, canvas.width, canvas.height);
  const data = NFM.ppsHistory;
  if (data.length < 2) return;

  const max  = Math.max(...data, 1);
  const w = canvas.width, h = canvas.height;
  const step = w / (data.length - 1);

  // Grid
  ctx.strokeStyle = 'rgba(30,45,74,.7)';
  ctx.lineWidth = 1;
  for (let i=0;i<=4;i++) {
    const y = h - (i/4)*h;
    ctx.beginPath(); ctx.moveTo(0,y); ctx.lineTo(w,y); ctx.stroke();
  }

  // Fill
  const grad = ctx.createLinearGradient(0,0,0,h);
  grad.addColorStop(0,'rgba(0,170,255,.38)');
  grad.addColorStop(1,'rgba(0,170,255,.02)');
  ctx.beginPath();
  data.forEach((v,i) => {
    const x = i*step, y = h-(v/max)*(h-4);
    i===0 ? ctx.moveTo(x,y) : ctx.lineTo(x,y);
  });
  ctx.lineTo(w,h); ctx.lineTo(0,h); ctx.closePath();
  ctx.fillStyle = grad; ctx.fill();

  // Line
  ctx.beginPath();
  data.forEach((v,i) => {
    const x=i*step, y=h-(v/max)*(h-4);
    i===0 ? ctx.moveTo(x,y) : ctx.lineTo(x,y);
  });
  ctx.strokeStyle='#00aaff'; ctx.lineWidth=2; ctx.stroke();

  // Baseline marker
  const bl = NFM.baselinePps || 0;
  if (bl > 0) {
    const blY = h - (bl/max)*(h-4);
    ctx.setLineDash([4,4]);
    ctx.strokeStyle = 'rgba(255,215,0,.5)';
    ctx.lineWidth = 1;
    ctx.beginPath(); ctx.moveTo(0,blY); ctx.lineTo(w,blY); ctx.stroke();
    ctx.setLineDash([]);
  }
};

// ── Dashboard Refresh ─────────────────────────────────────────
NFM.refreshDashboard = async () => {
  try {
    const r = await fetch('/api/status');
    if (!r.ok) return;
    const d = await r.json();

    // Snapshot Info Banner anzeigen wenn vorhanden
    if (d.snapshot_info) {
        const si = d.snapshot_info;
        const banner = document.getElementById('snap-banner');
        if (banner) {
            banner.classList.add('visible');
            const icon = si.saved_by === 'web' ? '🌐' : '🖥️';
            banner.innerHTML = `${icon} Snapshot: <span>${NFM.escHtml(si.saved_by.toUpperCase())}</span> vom <span>${NFM.escHtml(si.saved_at)}</span>`;
        }
    }

    // GeoLite2-Datenbank fehlt → Hinweis-Banner anzeigen
    const geoBanner = document.getElementById('geo-missing-banner');
    if (geoBanner) {
        if (d.geo_db_missing) {
            geoBanner.style.display = 'block';
        } else {
            geoBanner.style.display = 'none';
        }
    }

    // Stumm-geschaltete IPs für Alarm-Seite aktualisieren
    if (typeof NFM !== 'undefined' && NFM.updateMutedIps) {
        NFM.updateMutedIps(d.muted_ips || []);
    }

    // Header aktualisieren
    const modeMap = {
      monitor: ['b-monitor','👁 MONITOR'],
      confirm: ['b-confirm','⚡ CONFIRM'],
      auto:    ['b-auto','🔥 AUTO']
    };
    const [cls,lbl] = modeMap[d.firewall_mode] || ['b-neutral', d.firewall_mode];
    const badge = document.getElementById('hdr-badge');
    if (badge) { badge.className='badge '+cls; badge.textContent=lbl; }

    const ifc = document.getElementById('hdr-interface');
    if (ifc) ifc.textContent = 'Interface: ' + (d.interface||'alle');
    const ti = document.getElementById('hdr-ti');
    if (ti) {
      // BUG-TI5 Fix: IPs und CIDR-Netze separat anzeigen wenn verfügbar
      if (d.ti_cidr_count > 0) {
        ti.textContent = 'TI: ' + (d.ti_ip_count||0).toLocaleString('de-DE')
          + ' IPs + ' + (d.ti_cidr_count||0).toLocaleString('de-DE') + ' Netze';
      } else {
        ti.textContent = 'TI: ' + (d.ti_count||0).toLocaleString('de-DE');
      }
    }

    // Stats
    NFM.setText('s-pps',     (d.pps||0).toFixed(1)+' pps');
    NFM.setText('s-bps',     NFM.fmtBps(d.bps||0));
    NFM.setText('s-baseline',(d.baseline_pps||0).toFixed(1)+' pps');
    NFM.setText('s-thresh',  'Schwellenwert: +'+d.threshold+'%');
    NFM.setText('s-alerts',   d.alert_count||0);
    NFM.setText('s-blocked',  'Geblockte IPs: '+(d.blocked_count||0));
    // TI-Anzeige: bei CIDR-Einträgen detailliert, sonst kompakt
    if (d.ti_cidr_count > 0) {
      NFM.setText('s-ti', (d.ti_ip_count||0).toLocaleString('de-DE')
        + ' IPs / ' + (d.ti_cidr_count||0).toLocaleString('de-DE') + ' Netze');
    } else {
      NFM.setText('s-ti', (d.ti_count||0).toLocaleString('de-DE'));
    }

    // Graph
    NFM.baselinePps = d.baseline_pps || 0;
    NFM.ppsHistory.push(d.pps||0);
    NFM.bpsHistory.push(d.bps||0);
    if (NFM.ppsHistory.length > NFM.MAX_HIST) NFM.ppsHistory.shift();
    if (NFM.bpsHistory.length > NFM.MAX_HIST) NFM.bpsHistory.shift();
    NFM.drawGraph();

    // Top Talker
    const tt = document.getElementById('top-talkers');
    if (tt) tt.innerHTML = (d.top_talkers||[]).map(t=>`
      <tr>
        <td class="c-ip">${NFM.escHtml(t.ip)}</td>
        <td class="c-dim">${NFM.escHtml(t.host||'–')}</td>
        <td class="c-geo">${NFM.escHtml(t.geo||'–')}</td>
        <td class="${t.private?'c-lan':'c-pub'}">${t.private?'🏠 LAN':'🌍'}</td>
        <td class="c-num">${NFM.escHtml(String(t.count))}</td>
      </tr>`).join('');

    // Protokolle
    const total = Object.values(d.protos||{}).reduce((a,b)=>a+b,0)||1;
    const pb = document.getElementById('proto-bars');
    if (pb) pb.innerHTML = Object.entries(d.protos||{}).map(([k,v])=>{
      const allowed = {'TCP':'pb-tcp','UDP':'pb-udp','ICMP':'pb-icmp','OTHER':'pb-oth'};
      const cls = allowed[k] || 'pb-oth';
      const safeK = NFM.escHtml(k);
      const safeV = parseInt(v, 10) || 0;
      return `<div class="proto-row">
        <span class="proto-name">${safeK}</span>
        <div class="proto-bar ${cls}" style="width:${Math.max(3,safeV/total*220)}px"></div>
        <span class="proto-cnt">${safeV}</span>
      </div>`;
    }).join('');

    // Top Ports
    const tp = document.getElementById('top-ports');
    if (tp) tp.innerHTML = (d.top_ports||[]).map(p=>`
      <tr>
        <td class="c-port">${NFM.escHtml(String(p.port||'–'))}</td>
        <td class="c-dim">${NFM.escHtml(p.service||'–')}</td>
        <td class="c-num">${NFM.escHtml(String(p.count||0))}</td>
      </tr>`).join('');

    // Letzte Pakete
    const rp = document.getElementById('recent-pkts');
    if (rp) rp.innerHTML = (d.recent_packets||[]).map(p=>`
      <tr>
        <td class="c-dim">${NFM.escHtml(p.timestamp)}</td>
        <td class="c-geo">${NFM.escHtml(p.geo||'–')}</td>
        <td class="c-ip">${NFM.escHtml(p.src_ip)}</td>
        <td class="c-dim">→</td>
        <td class="c-ip2">${NFM.escHtml(p.dst_ip)}</td>
        <td class="c-${NFM.escHtml((p.protocol||'other').toLowerCase())}">${NFM.escHtml(p.protocol||'–')}</td>
        <td class="c-port">${NFM.escHtml(String(p.dst_port||'–'))}</td>
        <td class="c-num">${NFM.escHtml(String(p.size||0))} B</td>
      </tr>`).join('');

    // Dashboard Alarme
    const da = document.getElementById('dash-alerts');
    if (da) da.innerHTML = (d.recent_alerts||[]).length
      ? (d.recent_alerts||[]).map(a=>`<div>🚨 ${NFM.escHtml(a)}</div>`).join('')
      : '<div style="color:var(--green)">✅ Keine Alarme</div>';

  } catch(e) { console.warn('Dashboard refresh:', e); }
};

NFM.setText = (id, val) => {
  const el = document.getElementById(id);
  if (el) el.textContent = val;
};

// ── Init ─────────────────────────────────────────────────────
window.addEventListener('DOMContentLoaded', () => {
  NFM.refreshDashboard();
  setInterval(NFM.refreshDashboard, 2000);

  // Uhr
  const tick = () => {
    const cl = document.getElementById('hdr-clock');
    if (cl) cl.textContent = new Date().toLocaleTimeString('de-DE');
  };
  tick();
  setInterval(tick, 1000);

  // Graph resize
  window.addEventListener('resize', NFM.drawGraph);
});