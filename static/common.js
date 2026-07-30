/* Shared helpers + condition builder + presets + CSV export, used by backtest.html.
   Mirrors the equivalent (independently-maintained) code in index.html's inline script —
   kept as a separate file so index.html's already-verified behavior is never touched. */

/* ============================ helpers ============================ */
const $ = s => document.querySelector(s);
const el = (tag, attrs={}, html='') => { const e=document.createElement(tag);
  Object.entries(attrs).forEach(([k,v])=>e.setAttribute(k,v)); e.innerHTML=html; return e; };
const fmtP = v => { if(v==null||isNaN(v)) return '—';
  if(v>=1000) return v.toLocaleString('en-IN',{maximumFractionDigits:2});
  if(v>=1) return v.toFixed(4).replace(/0+$/,'').replace(/\.$/,'');
  return v.toPrecision(4); };
const fmtV = v => { if(v==null||isNaN(v)) return '—';
  if(v>=1e9) return (v/1e9).toFixed(2)+'B'; if(v>=1e6) return (v/1e6).toFixed(2)+'M';
  if(v>=1e3) return (v/1e3).toFixed(1)+'K'; return v.toFixed(1); };
const pctCls = v => v>0?'up':(v<0?'down':'mut');
const pct2 = v => v==null||isNaN(v) ? '' : v.toFixed(2);
let toastT;
function toast(msg, err=false){ const t=$('#toast'); t.textContent=msg; t.className='toast'+(err?' err':'');
  t.style.display='block'; clearTimeout(toastT); toastT=setTimeout(()=>t.style.display='none',3500); }
async function api(path, opts){ const r = await fetch(path, opts);
  const j = await r.json().catch(()=>({detail:'bad response'}));
  if(!r.ok) throw new Error(j.detail || r.status); return j; }
const isoIST = t => new Date(t).toLocaleString('en-IN',{hour12:false});
const INTERVAL_LABELS = {1:'1m',5:'5m',15:'15m',30:'30m',60:'1h',240:'4h',1440:'1d'};

/* ============================ theme ============================ */
(function(){
  const root = document.documentElement;
  const saved = localStorage.getItem('cs-theme');
  if(saved) root.setAttribute('data-theme', saved);
  const btn = $('#themeToggle');
  if(!btn) return;
  const sync = () => { btn.textContent = root.getAttribute('data-theme')==='light' ? '☀' : '🌙'; };
  btn.addEventListener('click', ()=>{
    const next = root.getAttribute('data-theme')==='light' ? 'dark' : 'light';
    root.setAttribute('data-theme', next); localStorage.setItem('cs-theme', next); sync();
  });
  sync();
})();

/* ============================ health dot ============================ */
(async()=>{ try{ const h = await api('/api/health');
    $('#keyDot').className = h.keys_configured ? 'ok' : 'bad';
    $('#keyTxt').textContent = h.keys_configured ? 'keys OK' : 'keys missing';
  }catch(e){ $('#keyDot').className='bad'; $('#keyTxt').textContent='server down'; } })();

/* ============================ condition builder ============================ */
const KINDS = [
  ['price','Price/Volume'], ['sma','SMA'], ['ema','EMA'], ['rsi','RSI'],
  ['highest','Highest of last N'], ['lowest','Lowest of last N'],
  ['change_pct','% change (N candles)'], ['abs_change_pct','|% change| (N candles)'],
  ['vwap','VWAP (day)'], ['vwap_dist','% dist from VWAP'],
  ['turnover','Turnover $ (candle)'], ['number','Number'],
];
const FIELDS = ['close','open','high','low','volume'];
const OPS = [['gt','&gt;'],['gte','&ge;'],['lt','&lt;'],['lte','&le;'],
             ['crosses_above','crosses ↑'],['crosses_below','crosses ↓']];

function opndHTML(side){
  return `<div class="opnd" data-side="${side}">
    <select class="k" title="What to measure:
Price/Volume = raw candle value · SMA/EMA = moving average · RSI = 0-100 strength
Highest/Lowest of last N = rolling extreme (breakout levels)
% change (N candles) = percent move of close over N candles (signed: + up, − down)
|% change| (N candles) = same, but unsigned — use with ALL match to catch a move in EITHER direction
VWAP (day) = volume-weighted avg price since IST midnight
% dist from VWAP = signed % of price vs VWAP (+above / −below)
Number = a constant you type">${KINDS.map(([v,l])=>`<option value="${v}">${l}</option>`).join('')}</select>
    <select class="f" title="Which candle value the indicator uses (close is standard; volume for volume conditions)">${FIELDS.map(f=>`<option>${f}</option>`).join('')}</select>
    <span class="mini per">len</span><input type="number" class="p" value="20" min="1" style="width:56px" title="Lookback length in candles. 20 on 5m = last 100 minutes.">
    <span class="mini off">ago</span><input type="number" class="o" value="0" min="0" style="width:48px" title="Candle offset: 0 = current candle, 1 = previous candle, 3 on 5m = 15 minutes ago.">
    <input type="number" class="n" value="0" step="any" style="width:86px;display:none" title="Constant to compare with. For % operands this is percent: 5 = 5%, -0.3 = minus 0.3%. For RSI: 0-100.">
  </div>`;
}
function condRow(cfg){
  const d = el('div',{class:'cond'});
  d.innerHTML = opndHTML('L') +
    `<select class="opsel op" title="Comparison:
> / ≥ / < / ≤ compare values right now.
crosses ↑ = was below (or equal) last candle, above now.
crosses ↓ = was above (or equal) last candle, below now.">${OPS.map(([v,l])=>`<option value="${v}">${l}</option>`).join('')}</select>` +
    `<span class="mini">×</span><input type="number" class="mult" value="1" step="any" style="width:64px" title="Multiplier on the RIGHT side: 1 = as-is, 1.2 = 20% more than right value, 2 = double, 0.8 = 20% less.">` +
    opndHTML('R') +
    `<button class="del" title="Remove this condition">✕</button>`;
  d.querySelector('.del').addEventListener('click',()=>{ d.remove(); updateSentence(); });
  d.addEventListener('change', ()=>{ d.querySelectorAll('.opnd').forEach(syncOpnd); updateSentence(); });
  d.addEventListener('input', updateSentence);
  if(cfg) applyCond(d,cfg);
  d.querySelectorAll('.opnd').forEach(syncOpnd);
  $('#conds').appendChild(d);
  updateSentence();
  return d;
}
function syncOpnd(o){
  const k = o.querySelector('.k').value;
  const show = (sel,on)=>{ o.querySelector(sel).style.display = on?'':'none'; };
  show('.f', ['price','sma','ema','highest','lowest'].includes(k));
  const hasP = ['sma','ema','rsi','highest','lowest','change_pct','abs_change_pct'].includes(k);
  show('.p',hasP); show('.per',hasP);
  const notNum = k!=='number';
  show('.o',notNum); show('.off',notNum);
  show('.n', k==='number');
}
function readOpnd(o){
  return { kind:o.querySelector('.k').value, field:o.querySelector('.f').value,
    period:+o.querySelector('.p').value||14, offset:+o.querySelector('.o').value||0,
    value:+o.querySelector('.n').value||0 };
}
function writeOpnd(o,c){
  o.querySelector('.k').value=c.kind; o.querySelector('.f').value=c.field||'close';
  o.querySelector('.p').value=c.period??20; o.querySelector('.o').value=c.offset??0;
  o.querySelector('.n').value=c.value??0; syncOpnd(o);
}
function readConds(){
  return [...document.querySelectorAll('#conds .cond')].map(d=>{
    const [L,R] = d.querySelectorAll('.opnd');
    return { left:readOpnd(L), op:d.querySelector('.opsel').value,
             right:readOpnd(R), mult:+d.querySelector('.mult').value||1 };
  });
}
function applyCond(d,c){
  const [L,R]=d.querySelectorAll('.opnd');
  writeOpnd(L,c.left); writeOpnd(R,c.right);
  d.querySelector('.opsel').value=c.op; d.querySelector('.mult').value=c.mult??1;
}
function opndText(c){
  const off = c.offset>0 ? ` (${c.offset} ago)` : '';
  switch(c.kind){
    case 'number': return String(c.value);
    case 'price': return `latest ${c.field}${off}`;
    case 'rsi': return `RSI(${c.period})${off}`;
    case 'change_pct': return `%chg over ${c.period} candles${off}`;
    case 'abs_change_pct': return `|%chg| over ${c.period} candles${off}`;
    case 'vwap': return `day VWAP${off}`;
    case 'vwap_dist': return `% dist from VWAP${off}`;
    case 'turnover': return `candle turnover $${off}`;
    case 'highest': return `highest ${c.field} of last ${c.period}${off}`;
    case 'lowest': return `lowest ${c.field} of last ${c.period}${off}`;
    default: return `${c.kind.toUpperCase()}(${c.field},${c.period})${off}`;
  }
}
const OPTXT = {gt:'>',gte:'≥',lt:'<',lte:'≤',crosses_above:'crosses above',crosses_below:'crosses below'};
function updateSentence(){
  const cs = readConds(); const itv = $('#interval').selectedOptions[0].text;
  const join = $('#logic').value==='any' ? 'OR' : 'AND';
  if(!cs.length){ $('#sentence').innerHTML = 'No conditions — add one.'; return; }
  $('#sentence').innerHTML = `On <b>${itv}</b> candles, show pairs where ` + cs.map(c=>{
    const m = c.mult!==1 ? `${c.mult} × ` : '';
    return `<b>${opndText(c.left)}</b> ${OPTXT[c.op]} ${m}<b>${opndText(c.right)}</b>`;
  }).join(` <span class="and">${join}</span> `);
}

/* plain-text one-line summary of a config — used as <option> hover tooltips */
function summarizeConfig(cfg){
  const cs = cfg.conditions||[];
  if(!cs.length) return 'no conditions';
  const itv = INTERVAL_LABELS[cfg.interval] || (cfg.interval+'m');
  const join = cfg.logic==='any' ? 'OR' : 'AND';
  const uni = cfg.exchange==='futures'?'Futures':cfg.exchange==='spot'?'Spot':cfg.exchange==='all'?'Spot+Futures':cfg.exchange;
  const conds = cs.map(c=>{
    const m = c.mult!==1 ? `${c.mult}x ` : '';
    return `${opndText(c.left)} ${OPTXT[c.op]} ${m}${opndText(c.right)}`;
  }).join(` ${join} `);
  return `${uni} · ${itv}\n${conds}`;
}

/* ============================ presets ============================ */
/* Kept in sync by hand with index.html's PRESETS — same filters, same names. */
const PRESETS = {
  pvspike:{ interval:60, conditions:[
    {left:{kind:'change_pct',field:'close',period:1,offset:0}, op:'gt', right:{kind:'number',value:3}, mult:2},
    {left:{kind:'price',field:'volume',offset:0}, op:'gte',
     right:{kind:'sma',field:'volume',period:20,offset:0}, mult:3},
  ]},
  pvspike5m:{ interval:5, conditions:[
    {left:{kind:'change_pct',field:'close',period:1,offset:0}, op:'gt', right:{kind:'number',value:3}, mult:1},
    {left:{kind:'price',field:'volume',offset:0}, op:'gte',
     right:{kind:'sma',field:'volume',period:20,offset:0}, mult:3},
  ]},
  trendvolspike5m:{ interval:5, conditions:[
    {left:{kind:'change_pct',field:'close',period:1,offset:0}, op:'gt', right:{kind:'number',value:1}, mult:1},
    {left:{kind:'price',field:'volume',offset:0}, op:'gte',
     right:{kind:'sma',field:'volume',period:20,offset:0}, mult:3},
    {left:{kind:'ema',field:'close',period:21,offset:0}, op:'lt',
     right:{kind:'price',field:'close',offset:0}, mult:1},
    {left:{kind:'price',field:'close',offset:0}, op:'gt', right:{kind:'vwap',offset:0}, mult:1},
  ]},
};
function loadPreset(name){
  const p = PRESETS[name]; if(!p) return;
  $('#conds').innerHTML='';
  if(p.interval) $('#interval').value = String(p.interval);
  if(p.universe) $('#universe').value = p.universe;
  if(p.lastClosed!==undefined) $('#lastClosed').value = p.lastClosed ? '1' : '0';
  $('#logic').value = 'all';
  p.conditions.forEach(c=>condRow(c));
  updateSentence();
}

/* ============================ shared scan-config builder ============================ */
function buildScanConfig(){
  const uni = $('#universe').value;
  const maxVolRaw = $('#maxVol').value.trim();
  const minChangeRaw = $('#minChange').value.trim();
  const cfg = {
    exchange: uni, quote: uni==='futures' ? 'USDT' : $('#quote').value,
    interval: +$('#interval').value, top_n: +$('#topN').value||50,
    min_quote_volume: (+$('#minVol').value||0) * 1_000_000,
    max_quote_volume: maxVolRaw!=='' ? (+maxVolRaw) * 1_000_000 : null,
    min_change_pct: minChangeRaw!=='' ? +minChangeRaw : null,
    use_last_closed: $('#lastClosed').value==='1',
    logic: $('#logic').value, conditions: readConds(),
  };
  const lb = document.querySelector('#lookbackDays');
  if(lb) cfg.lookback_days = +lb.value;
  return cfg;
}
function applyScanConfig(cfg){
  const uni = ['all','spot','futures'].includes(cfg.exchange) ? cfg.exchange : 'all';
  $('#universe').value = uni;
  if(cfg.quote && uni!=='futures') $('#quote').value=cfg.quote;
  $('#interval').value=String(cfg.interval||15);
  $('#topN').value=cfg.top_n??50;
  $('#minVol').value=+(((cfg.min_quote_volume??10000000)/1_000_000).toFixed(4));
  $('#maxVol').value = cfg.max_quote_volume!=null ? +((cfg.max_quote_volume/1_000_000).toFixed(4)) : '';
  $('#minChange').value = cfg.min_change_pct!=null ? cfg.min_change_pct : '';
  $('#logic').value=cfg.logic||'all';
  $('#lastClosed').value = cfg.use_last_closed?'1':'0';
  const lb = document.querySelector('#lookbackDays');
  if(lb && cfg.lookback_days) lb.value = String(cfg.lookback_days);
  $('#preset').value='';
  $('#conds').innerHTML='';
  (cfg.conditions||[]).forEach(c=>condRow(c));
  updateSentence();
}

/* ============================ CSV export ============================ */
function toCSV(rows, cols){
  const esc = v => { if(v==null) return ''; const s=String(v);
    return /[",\n]/.test(s) ? '"'+s.replace(/"/g,'""')+'"' : s; };
  const lines = [cols.map(c=>esc(c.label)).join(',')];
  rows.forEach(r=>lines.push(cols.map(c=>esc(c.get(r))).join(',')));
  return lines.join('\r\n');
}
function downloadCSV(csv, filename){
  const blob = new Blob([csv], {type:'text/csv;charset=utf-8;'});
  const url = URL.createObjectURL(blob);
  const a = el('a',{href:url,download:filename}); document.body.appendChild(a);
  a.click(); document.body.removeChild(a); URL.revokeObjectURL(url);
}
