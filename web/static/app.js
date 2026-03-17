/* ═══════════════════════════════════════════════════════════
   NET-FIRE-MONITOR  v3.0  –  app.js
   Navigation, Alarme, Listen, Regeln, Logs, Konfiguration
   CSRF-Schutz: alle schreibenden Requests verwenden nfmFetch()
   ═══════════════════════════════════════════════════════════ */

'use strict';

window.NFM = window.NFM || {};
var NFM = window.NFM;

// ── Hilfsfunktionen ─────────────────────────────────────────
NFM.escHtml = s =>
  String(s).replace(/&/g,'&amp;').replace(/</g,'&lt;').replace(/>/g,'&gt;');

NFM.escAttr = s =>
  String(s).replace(/&/g,'&amp;').replace(/</g,'&lt;').replace(/>/g,'&gt;')
           .replace(/"/g,'&quot;').replace(/'/g,'&#39;');

NFM.toast = (msg, type='inf') => {
  const c = document.getElementById('toasts');
  if (!c) return;
  const el = document.createElement('div');
  el.className = 'toast toast-'+type;
  el.textContent = msg;
  c.appendChild(el);
  setTimeout(() => el.remove(), 3500);
};

// ── Navigation ───────────────────────────────────────────────
NFM.showPage = (name, btn) => {
  document.querySelectorAll('.page').forEach(p => p.classList.remove('active'));
  document.querySelectorAll('.nav-btn').forEach(b => b.classList.remove('active'));
  const page = document.getElementById('page-' + name);
  if (page) page.classList.add('active');
  if (btn)  btn.classList.add('active');
  const loaders = {
    alarms: NFM.loadAlarms,
    lists:  NFM.loadLists,
    rules:  NFM.loadRules,
    logs:   () => NFM.loadLog('monitor'),
    config: NFM.loadConfigUI,
  };
  if (loaders[name]) loaders[name]();
};

// ══════════════════════════════════════════════════════════════
// ALARME
// ══════════════════════════════════════════════════════════════
NFM.alarmFilter = 'all';

NFM.loadAlarms = async () => {
  try {
    const r = await fetch('/api/alarms');
    if (!r.ok) return;
    const data = await r.json();
    NFM.renderAlarms(data.alarms || []);
  } catch(e) {
    const c = document.getElementById('alarm-list');
    if (c) c.innerHTML = '<div style="color:var(--red);padding:16px;">Fehler: ' + e + '</div>';
  }
};

NFM.filterAlarms = (f, btn) => {
  NFM.alarmFilter = f;
  document.querySelectorAll('.alarm-filter-btn').forEach(b => b.classList.remove('active'));
  if (btn) btn.classList.add('active');
  NFM.loadAlarms();
};

NFM.renderAlarms = (alarms) => {
  const c = document.getElementById('alarm-list');
  if (!c) return;
  const filtered = NFM.alarmFilter === 'all'
    ? alarms
    : alarms.filter(a => a.msg.includes(NFM.alarmFilter));
  if (!filtered.length) {
    c.innerHTML = '<div style="color:var(--green);padding:24px;text-align:center;">✅ Keine Alarme</div>';
    return;
  }
  c.innerHTML = filtered.map((a, i) => {
    const tc = a.msg.includes('Threat')||a.msg.includes('☠️') ? 'ti' :
               a.msg.includes('Port')                          ? 'scan' :
               a.msg.includes('Regel')                         ? 'rule' :
               a.msg.includes('Blacklist')                     ? 'bl' : '';
    const isMuted = NFM.mutedIps && a.ip && NFM.mutedIps.includes(a.ip);
    return `<div class="alarm-card ${tc}" id="alarm-card-${i}">
      <div class="a-ts">🕐 ${NFM.escHtml(a.ts)}</div>
      <div class="a-msg">🚨 ${NFM.escHtml(a.msg)}</div>
      ${a.ip ? `<div class="a-meta">
        IP: <span>${NFM.escHtml(a.ip)}</span>
        ${isMuted ? '&nbsp;|&nbsp; <span style="color:var(--yellow)">🔇 Stumm</span>' : ''}
      </div>` : ''}
      <div class="a-acts">
        ${a.ip ? `
        <button class="btn btn-g" data-ip="${NFM.escAttr(a.ip)}" data-act="whitelist" onclick="NFM.alarmActFromBtn(this)">✅ Whitelist</button>
        <button class="btn btn-r" data-ip="${NFM.escAttr(a.ip)}" data-act="blacklist" onclick="NFM.alarmActFromBtn(this)">🚫 Blacklist</button>
        <button class="btn btn-y" data-ip="${NFM.escAttr(a.ip)}" data-act="block"     onclick="NFM.alarmActFromBtn(this)">🔒 Blocken</button>
        ${isMuted
          ? `<button class="btn btn-b" data-ip="${NFM.escAttr(a.ip)}" onclick="NFM.unmuteIp(this.dataset.ip,this)">🔔 Entstummen</button>`
          : `<button class="btn btn-d" style="position:relative" data-ip="${NFM.escAttr(a.ip)}" onclick="NFM.showMuteMenu(this)">🔇 Stumm ▾</button>`
        }` : ''}
        <button class="btn btn-d" onclick="this.closest('.alarm-card').style.opacity='.3'">⏭ Überspringen</button>
      </div>
    </div>`;
  }).join('');
};

NFM.alarmActFromBtn = btn => {
  const ip     = btn.dataset.ip;
  const action = btn.dataset.act;
  NFM.alarmAct(action, ip, btn);
};

NFM.alarmAct = async (action, ip, btn) => {
  if (!ip || !/^[\d.:a-fA-F]+$/.test(ip)) { NFM.toast('Ungültige IP','err'); return; }
  try {
    let url = '/api/list-action';
    let body = {action:'add', list: action, ip};
    if (action === 'block') {
      url  = '/api/firewall-action';
      body = {action:'block', ip};
    }
    const r = await nfmFetch(url, {
      method:'POST',
      headers:{'Content-Type':'application/json'},
      body: JSON.stringify(body)
    });
    const d = await r.json();
    if (d.ok) {
      NFM.toast(d.message, 'ok');
      const card = btn.closest('.alarm-card');
      if (card) {
        card.style.borderLeftColor = 'var(--green)';
        card.querySelector('.a-acts').innerHTML =
          `<span style="color:var(--green);font-size:11px;">✅ ${NFM.escHtml(d.message)}</span>`;
      }
    } else { NFM.toast(d.message,'err'); }
  } catch(e) { NFM.toast('Fehler: '+e,'err'); }
};

// ══════════════════════════════════════════════════════════════
// WHITELIST / BLACKLIST
// ══════════════════════════════════════════════════════════════
NFM.loadLists = async () => {
  try {
    const r = await fetch('/api/config');
    const cfg = await r.json();
    NFM.renderList('whitelist', cfg.whitelist||[], 'wl-items', 'wl-count', false);
    NFM.renderList('blacklist', cfg.blacklist||[], 'bl-items', 'bl-count', true);
  } catch(e) { console.warn(e); }
  NFM.loadMuteList();
  try {
    const r = await fetch('/api/status');
    const d = await r.json();
    if (d.alert_cooldown) {
      const el = document.getElementById('mute-cooldown-secs');
      if (el) el.value = d.alert_cooldown;
      const disp = document.getElementById('mute-cooldown-display');
      if (disp) disp.textContent = NFM.fmtDuration(d.alert_cooldown);
    }
  } catch(e) {}
};

NFM.renderList = (list, items, containerId, countId, isBlack) => {
  const c = document.getElementById(containerId);
  const n = document.getElementById(countId);
  if (n) n.textContent = items.length + ' IPs';
  if (!c) return;
  if (!items.length) {
    c.innerHTML = '<div style="color:var(--text3);font-size:11px;padding:8px;">Keine Einträge</div>';
    return;
  }
  c.innerHTML = items.map(ip => `
    <div class="ip-item">
      <span style="${isBlack?'color:var(--red)':''}">${NFM.escHtml(ip)}</span>
      <span class="ip-del" data-list="${list}" data-ip="${NFM.escAttr(ip)}"
            onclick="NFM.removeFromListBtn(this)">✕</span>
    </div>`).join('');
};

NFM.removeFromListBtn = async btn => {
  const list = btn.dataset.list;
  const ip   = btn.dataset.ip;
  NFM.removeFromList(list, ip);
};

NFM.addToList = async (list) => {
  // HTML-IDs: wl-new und bl-new (nicht wl-input/bl-input)
  const input = document.getElementById(list === 'whitelist' ? 'wl-new' : 'bl-new');
  const ip = input ? input.value.trim() : '';
  if (!ip) return;
  if (!/^[\d.:a-fA-F/]+$/.test(ip)) { NFM.toast('Ungültige IP','err'); return; }
  try {
    const r = await nfmFetch('/api/list-action', {
      method:'POST',
      headers:{'Content-Type':'application/json'},
      body: JSON.stringify({list, action:'add', ip})
    });
    const d = await r.json();
    if (d.ok) { NFM.toast(d.message,'ok'); if(input) input.value=''; NFM.loadLists(); }
    else       NFM.toast(d.message,'err');
  } catch(e) { NFM.toast('Fehler: '+e,'err'); }
};

NFM.removeFromList = async (list, ip) => {
  try {
    const r = await nfmFetch('/api/list-action', {
      method:'POST',
      headers:{'Content-Type':'application/json'},
      body: JSON.stringify({list, action:'remove', ip})
    });
    const d = await r.json();
    if (d.ok) { NFM.toast(d.message,'ok'); NFM.loadLists(); }
    else       NFM.toast(d.message,'err');
  } catch(e) { NFM.toast('Fehler: '+e,'err'); }
};

// ══════════════════════════════════════════════════════════════
// STUMM-SCHALTUNG
// ══════════════════════════════════════════════════════════════
NFM.fmtDuration = (secs) => {
  if (secs < 0)     return 'Dauerhaft';
  if (secs < 60)    return secs + ' Sek.';
  if (secs < 3600)  return Math.round(secs/60) + ' Min.';
  if (secs < 86400) return Math.round(secs/3600) + ' Std.';
  return Math.round(secs/86400) + ' Tage';
};

NFM.mutedIps = [];
NFM.updateMutedIps = (ips) => { NFM.mutedIps = ips || []; };

NFM.loadMuteList = async () => {
  const c = document.getElementById('mute-items');
  const n = document.getElementById('mute-count');
  if (!c) return;
  try {
    const r = await fetch('/api/status');
    const d = await r.json();
    const muted = d.muted_ips || [];
    if (n) n.textContent = muted.length + ' IPs';
    if (!muted.length) {
      c.innerHTML = '<div style="color:var(--text3);font-size:11px;padding:8px;">Keine Einträge</div>';
      return;
    }
    c.innerHTML = muted.map(ip => `
      <div class="ip-item">
        <span style="color:var(--yellow)">${NFM.escHtml(ip)}</span>
        <span class="ip-del" data-ip="${NFM.escAttr(ip)}" onclick="NFM.unmuteIp(this.dataset.ip,this)">✕</span>
      </div>`).join('');
  } catch(e) { console.warn(e); }
};

NFM.showMuteMenu = (btn) => {
  document.querySelectorAll('.mute-menu').forEach(m => m.remove());
  const ip = btn.dataset.ip;
  const menu = document.createElement('div');
  menu.className = 'mute-menu';
  menu.style.cssText = `position:absolute;z-index:500;background:var(--bg2);
    border:1px solid var(--border2);border-radius:2px;padding:4px 0;min-width:180px;
    box-shadow:0 4px 16px rgba(0,0,0,.5);`;
  const opts = [
    {label:'🔇 15 Min.',  secs:900},
    {label:'🔇 1 Stunde', secs:3600},
    {label:'🔇 6 Stunden',secs:21600},
    {label:'🔇 24 Stunden',secs:86400},
    {label:'🔇 Dauerhaft',secs:-1},
  ];
  opts.forEach(opt => {
    const item = document.createElement('div');
    item.textContent = opt.label;
    item.style.cssText = 'padding:6px 14px;cursor:pointer;font-size:12px;color:var(--text2);';
    item.onmouseenter = () => item.style.background = 'rgba(0,100,255,.08)';
    item.onmouseleave = () => item.style.background = '';
    item.onclick = () => { menu.remove(); NFM.muteIp(ip, opt.secs, btn); };
    menu.appendChild(item);
  });
  btn.style.position = 'relative';
  btn.appendChild(menu);
  setTimeout(() => document.addEventListener('click', function _c(e) {
    if (!menu.contains(e.target)) { menu.remove(); document.removeEventListener('click',_c); }
  }), 0);
};

NFM.muteIp = async (ip, duration, btn) => {
  try {
    const r = await nfmFetch('/api/firewall-action', {
      method:'POST',
      headers:{'Content-Type':'application/json'},
      body: JSON.stringify({action:'mute', ip, duration})
    });
    const d = await r.json();
    if (d.ok) {
      NFM.toast(d.message,'ok');
      NFM.mutedIps.push(ip);
    } else NFM.toast(d.message,'err');
  } catch(e) { NFM.toast('Fehler: '+e,'err'); }
};

NFM.unmuteIp = async (ip, btn) => {
  try {
    const r = await nfmFetch('/api/firewall-action', {
      method:'POST',
      headers:{'Content-Type':'application/json'},
      body: JSON.stringify({action:'unmute', ip})
    });
    const d = await r.json();
    if (d.ok) {
      NFM.toast(d.message,'ok');
      NFM.mutedIps = NFM.mutedIps.filter(m => m !== ip);
      NFM.loadLists();
    } else NFM.toast(d.message,'err');
  } catch(e) { NFM.toast('Fehler: '+e,'err'); }
};

// Stumm schalten über das Eingabefeld auf der Listen-Seite
NFM.addMuteFromInput = async () => {
  const ipEl  = document.getElementById('mute-new-ip');
  const durEl = document.getElementById('mute-new-duration');
  const ip       = ipEl  ? ipEl.value.trim()          : '';
  const duration = durEl ? parseInt(durEl.value, 10)   : 3600;
  if (!ip) { NFM.toast('Bitte IP eingeben','err'); return; }
  if (!/^[\d.:a-fA-F]+$/.test(ip)) { NFM.toast('Ungültige IP','err'); return; }
  try {
    const r = await nfmFetch('/api/firewall-action', {
      method:'POST',
      headers:{'Content-Type':'application/json'},
      body: JSON.stringify({action:'mute', ip, duration})
    });
    const d = await r.json();
    if (d.ok) {
      NFM.toast(d.message, 'ok');
      if (ipEl) ipEl.value = '';
      NFM.loadMuteList();
    } else NFM.toast(d.message, 'err');
  } catch(e) { NFM.toast('Fehler: '+e,'err'); }
};

// Cooldown speichern
NFM.saveCooldown = async () => {
  const el = document.getElementById('mute-cooldown-secs');
  const secs = el ? parseInt(el.value, 10) : 300;
  if (isNaN(secs) || secs < 0 || secs > 86400) {
    NFM.toast('Ungültiger Wert (0–86400s)', 'err'); return;
  }
  try {
    const r = await nfmFetch('/api/firewall-action', {
      method:'POST',
      headers:{'Content-Type':'application/json'},
      body: JSON.stringify({action:'set_cooldown', seconds:secs})
    });
    const d = await r.json();
    if (d.ok) NFM.toast('Cooldown gespeichert ✅', 'ok');
    else       NFM.toast(d.message, 'err');
  } catch(e) { NFM.toast('Fehler: '+e,'err'); }
};

// ══════════════════════════════════════════════════════════════
// FIREWALL-REGELN
// ══════════════════════════════════════════════════════════════
NFM.loadRules = async () => {
  const c = document.getElementById('rules-list');
  if (!c) return;
  try {
    const r   = await fetch('/api/config');
    const cfg = await r.json();
    const rules = cfg.firewall_rules || [];
    if (!rules.length) {
      c.innerHTML = '<div style="color:var(--text3);padding:16px;">Keine Regeln konfiguriert</div>';
      return;
    }
    c.innerHTML = `<table class="tbl"><thead><tr>
      <th>Proto</th><th>Port</th><th>Quell-IP</th><th>Aktion</th><th>Kommentar</th><th></th>
    </tr></thead><tbody>${rules.map((rule,i) => `<tr>
      <td>${NFM.escHtml(rule.proto)}</td>
      <td>${NFM.escHtml(String(rule.port||'alle'))}</td>
      <td>${NFM.escHtml(rule.src_ip||'alle')}</td>
      <td><span class="badge ${rule.action==='block'?'b-red':rule.action==='allow'?'b-green':'b-yellow'}">${NFM.escHtml(rule.action)}</span></td>
      <td style="color:var(--text2)">${NFM.escHtml(rule.comment||'–')}</td>
      <td><button class="btn btn-r" data-idx="${i}" onclick="NFM.deleteRuleBtn(this)">🗑 Löschen</button></td>
    </tr>`).join('')}</tbody></table>`;
  } catch(e) { console.warn(e); }
};

// Neue-Regel-Formular einblenden (Inline-Panel unterhalb der Tabelle)
NFM.showAddRule = () => {
  // Falls Formular bereits offen → schließen
  const existing = document.getElementById('add-rule-form');
  if (existing) { existing.remove(); return; }

  const form = document.createElement('div');
  form.id = 'add-rule-form';
  form.style.cssText = 'margin-top:12px;padding:14px 16px;background:var(--bg2);border:1px solid var(--border2);border-radius:2px;';
  form.innerHTML = `
    <div style="font-size:12px;color:var(--text2);margin-bottom:10px;font-weight:600;">➕ Neue Firewall-Regel</div>
    <div class="frow" style="flex-wrap:wrap;gap:8px;align-items:center;">
      <select class="inp" id="rule-proto" style="width:90px;">
        <option value="any">any</option>
        <option value="tcp">TCP</option>
        <option value="udp">UDP</option>
        <option value="icmp">ICMP</option>
      </select>
      <input class="inp" id="rule-port" type="number" min="0" max="65535" placeholder="Port (0=alle)" style="width:130px;">
      <input class="inp" id="rule-src" placeholder="Quell-IP (leer=alle)" style="width:170px;">
      <select class="inp" id="rule-action" style="width:100px;">
        <option value="block">block</option>
        <option value="allow">allow</option>
        <option value="alert">alert</option>
      </select>
      <input class="inp" id="rule-comment" placeholder="Kommentar" style="flex:1;min-width:120px;">
      <button class="btn btn-g" onclick="NFM.addRule()">✅ Hinzufügen</button>
      <button class="btn btn-d" onclick="document.getElementById('add-rule-form').remove()">✕ Abbrechen</button>
    </div>`;

  const container = document.getElementById('rules-list').parentElement;
  container.appendChild(form);
  document.getElementById('rule-port').focus();
};

NFM.deleteRuleBtn = async btn => {
  const idx = parseInt(btn.dataset.idx, 10);
  try {
    const r = await nfmFetch('/api/rules', {
      method:'POST',
      headers:{'Content-Type':'application/json'},
      body: JSON.stringify({action:'delete', index:idx})
    });
    const d = await r.json();
    if (d.ok) { NFM.toast('Regel gelöscht','ok'); NFM.loadRules(); }
    else       NFM.toast(d.message,'err');
  } catch(e) { NFM.toast('Fehler: '+e,'err'); }
};

NFM.addRule = async () => {
  const g = id => {
    const el = document.getElementById(id);
    return el ? el.value.trim() : '';
  };
  const rule = {
    proto:   g('rule-proto'),
    port:    parseInt(g('rule-port'),10)||0,
    src_ip:  g('rule-src'),
    action:  g('rule-action'),
    comment: g('rule-comment'),
  };
  try {
    const r = await nfmFetch('/api/rules', {
      method:'POST',
      headers:{'Content-Type':'application/json'},
      body: JSON.stringify({action:'add', rule})
    });
    const d = await r.json();
    if (d.ok) {
      NFM.toast('Regel hinzugefügt ✅','ok');
      const form = document.getElementById('add-rule-form');
      if (form) form.remove();
      NFM.loadRules();
    } else NFM.toast(d.message,'err');
  } catch(e) { NFM.toast('Fehler: '+e,'err'); }
};

// ══════════════════════════════════════════════════════════════
// LOGS  –  farbige, durchsuchbare Log-Anzeige
// ══════════════════════════════════════════════════════════════
NFM._currentLogLines = [];
NFM._currentLogType  = 'monitor';

NFM.loadLog = async (type) => {
  NFM._currentLogType = type || NFM._currentLogType || 'monitor';
  const c = document.getElementById('log-content');
  if (!c) return;
  try {
    const r = await fetch('/api/log?type=' + NFM._currentLogType);
    const d = await r.json();
    NFM._currentLogLines = d.lines || [];
    NFM._renderLog();
  } catch(e) { if (c) c.innerHTML = '<span style="color:var(--red)">Fehler: ' + NFM.escHtml(String(e)) + '</span>'; }
};

NFM._renderLog = () => {
  const c = document.getElementById('log-content');
  if (!c) return;
  const filter = (document.getElementById('log-search')?.value || '').toLowerCase();
  const lines  = NFM._currentLogLines;

  const html = lines
    .filter(l => !filter || l.toLowerCase().includes(filter))
    .map(line => {
      // Zeile parsen: [TIMESTAMP] [LEVEL] message
      // Format: 2026-03-16 22:17:42,719 [WARNING] Text
      const safe = NFM.escHtml(line);

      // Level-Farbe bestimmen
      let cls = 'll-i';
      if (/\[WARNING\]|WARNING:/i.test(line))  cls = 'll-w';
      if (/\[ERROR\]|ERROR:/i.test(line))      cls = 'll-e';
      if (/BLOCKED|🚫|⛔/i.test(line))         cls = 'll-bl';
      if (/UNBLOCKED|✅/i.test(line))          cls = 'll-ub';
      if (/☠️|Threat|threat_intel/i.test(line)) cls = 'll-w';

      // Timestamp hervorheben (erste 23 Zeichen wenn Datum-Format)
      const tsMatch = safe.match(/^(\d{4}-\d{2}-\d{2} \d{2}:\d{2}:\d{2}[,\d]*)\s/);
      if (tsMatch) {
        const ts   = tsMatch[1];
        const rest = safe.slice(ts.length);
        return `<div class="log-line ${cls}"><span class="ll-ts">${ts}</span>${rest}</div>`;
      }
      return `<div class="log-line ${cls}">${safe}</div>`;
    })
    .join('');

  c.innerHTML = html || '<div style="color:var(--text3);padding:8px;">Keine Einträge gefunden</div>';

  const autoScroll = document.getElementById('log-autoscroll');
  if (!autoScroll || autoScroll.checked) {
    c.scrollTop = c.scrollHeight;
  }
};

// ══════════════════════════════════════════════════════════════
// KONFIGURATION
// ══════════════════════════════════════════════════════════════
NFM.loadConfigUI = async () => {
  try {
    const r   = await fetch('/api/config');
    const cfg = await r.json();
    const set = (id, val) => {
      const el = document.getElementById('cfg-'+id);
      if (!el) return;
      if (el.classList.contains('tog')) {
        el.classList.toggle('on', !!val);
        el.dataset.v = val ? '1' : '0';
      } else {
        el.value = val ?? '';
      }
    };
    ['threshold','monitor_interval','average_period','firewall_mode','interface',
     'email_smtp','email_port','email_user','email_recipient',
     'threat_intel_update_interval','portscan_limit','report_rotate',
     'syslog_host','syslog_port','syslog_protocol','syslog_tag','bpf_filter']
      .forEach(k => set(k, cfg[k]));
    ['notify_desktop','notify_log','email_enabled','threat_intel_enabled',
     'threat_intel_auto_block','resolve_dns','geo_lookup','detect_portscan',
     'export_csv','export_json','syslog_enabled']
      .forEach(k => set(k, cfg[k]));
    const ifRaw = document.getElementById('cfg-interfaces-raw');
    if (ifRaw) ifRaw.value = (cfg.interfaces||[]).join(',');
  } catch(e) { console.warn('loadConfigUI:', e); }
};

NFM.toggleBool = el => {
  el.classList.toggle('on');
  el.dataset.v = el.classList.contains('on') ? '1' : '0';
};

NFM.saveConfig = async () => {
  try {
    const r   = await fetch('/api/config');
    const cfg = await r.json();
    const get = id => {
      const el = document.getElementById('cfg-'+id);
      if (!el) return undefined;
      if (el.classList.contains('tog')) return el.dataset.v === '1';
      if (el.type === 'number') return parseFloat(el.value)||0;
      return el.value;
    };
    ['firewall_mode','interface','bpf_filter','email_smtp','email_user','email_recipient',
     'syslog_host','syslog_protocol','syslog_tag'].forEach(k => {
       const v=get(k); if(v!==undefined) cfg[k]=v;
    });
    ['threshold','monitor_interval','average_period','email_port',
     'threat_intel_update_interval','portscan_limit','report_rotate','syslog_port']
      .forEach(k => { const v=get(k); if(v!==undefined) cfg[k]=v; });
    ['notify_desktop','notify_log','email_enabled','threat_intel_enabled',
     'threat_intel_auto_block','resolve_dns','geo_lookup','detect_portscan',
     'export_csv','export_json','syslog_enabled']
      .forEach(k => { const v=get(k); if(v!==undefined) cfg[k]=v; });
    const ifRaw = document.getElementById('cfg-interfaces-raw');
    if (ifRaw) cfg.interfaces = ifRaw.value.split(',').map(s=>s.trim()).filter(Boolean);

    const resp = await nfmFetch('/api/config', {
      method:'POST',
      headers:{'Content-Type':'application/json'},
      body: JSON.stringify(cfg)
    });
    const d = await resp.json();
    if (d.ok) NFM.toast('Konfiguration gespeichert ✅','ok');
    else       NFM.toast('Fehler: '+d.message,'err');
  } catch(e) { NFM.toast('Fehler beim Speichern','err'); }
};

// ── Auto-Refresh ─────────────────────────────────────────────
setInterval(() => {
  const alPage  = document.getElementById('page-alarms');
  const lgPage  = document.getElementById('page-logs');
  if (alPage?.classList.contains('active')) NFM.loadAlarms();
  if (lgPage?.classList.contains('active')) NFM.loadLog();   // behält aktuellen Log-Typ
}, 8000);
