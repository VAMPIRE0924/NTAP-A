#ifndef NTAP_A_WEB_ASSETS_H
#define NTAP_A_WEB_ASSETS_H

static const char NTAP_A_WEB_INDEX_0[] =
"<!doctype html>\n"
"<html lang='en'>\n"
"<head>\n"
"<meta charset='utf-8'>\n"
"<meta name='viewport' content='width=device-width,initial-scale=1'>\n"
"<title>NTAP Admin</title>\n"
"<style>\n"
":root{color-scheme:light;--bg:#f6f7f9;--panel:#fff;--line:#d8dde5;--text:#17202a;--muted:#647386;--accent:#087f8c;--accent2:#8a5a00;--bad:#b42318;--ok:#087443}\n"
"*{box-sizing:border-box}body{margin:0;background:var(--bg);color:var(--text);font:14px/1.45 system-ui,-apple-system,Segoe UI,Arial,sans-serif}header{display:flex;align-items:center;justify-content:space-between;gap:16px;padding:14px 18px;border-bottom:1px solid var(--line);background:#fff;position:sticky;top:0;z-index:2}h1{margin:0;font-size:18px;font-weight:700}main{max-width:1480px;margin:0 auto;padding:16px;display:grid;gap:14px}.bar{display:flex;gap:8px;align-items:end;flex-wrap:wrap}.field{display:grid;gap:4px;min-width:150px}.field.wide{min-width:260px}label{font-size:12px;color:var(--muted)}input,select,button{height:34px;border:1px solid var(--line);border-radius:6px;background:#fff;color:var(--text);font:inherit}input,select{padding:0 9px}button{padding:0 12px;cursor:pointer}button.primary{background:var(--accent);border-color:var(--accent);color:#fff}button.warn{background:var(--accent2);border-color:var(--accent2);color:#fff}.status{min-height:20px;color:var(--muted)}.status.bad{color:var(--bad)}.status.ok{color:var(--ok)}.tabs{display:flex;gap:6px;flex-wrap:wrap}.tabs button[aria-selected=true]{background:#17202a;color:#fff;border-color:#17202a}.grid{display:grid;grid-template-columns:repeat(12,1fr);gap:14px}.panel{background:var(--panel);border:1px solid var(--line);border-radius:8px;min-width:0}.panel h2{font-size:14px;margin:0;padding:11px 12px;border-bottom:1px solid var(--line)}.panel .body{padding:12px}.span4{grid-column:span 4}.span6{grid-column:span 6}.span8{grid-column:span 8}.span12{grid-column:1/-1}.tablewrap{overflow:auto;max-height:360px}table{border-collapse:collapse;width:100%;min-width:640px}th,td{text-align:left;border-bottom:1px solid var(--line);padding:7px 8px;white-space:nowrap;vertical-align:top}th{font-size:12px;color:var(--muted);background:#fbfcfd;position:sticky;top:0}pre{margin:0;white-space:pre-wrap;word-break:break-word;background:#f2f4f7;border:1px solid var(--line);border-radius:6px;padding:9px;max-height:260px;overflow:auto}.formgrid{display:grid;grid-template-columns:repeat(4,minmax(120px,1fr));gap:8px}.actions{display:flex;gap:8px;flex-wrap:wrap;margin-top:10px}@media(max-width:900px){header{align-items:flex-start;position:static}.grid{grid-template-columns:1fr}.span4,.span6,.span8,.span12{grid-column:1}.formgrid{grid-template-columns:1fr}.field,.field.wide{min-width:0}table{min-width:520px}}\n"
"</style>\n"
;

static const char NTAP_A_WEB_INDEX_1[] =
"</head>\n"
"<body>\n"
"<header><h1>NTAP Admin</h1><div id='status' class='status'>idle</div></header>\n"
"<main>\n"
"<section class='panel span12'><div class='body bar'>\n"
"<div class='field wide'><label for='apiKey'>API key</label><input id='apiKey' type='password' autocomplete='current-password'></div>\n"
"<button id='refresh' class='primary'>Refresh</button><button id='health'>Health</button><button id='clear'>Clear</button>\n"
"</div></section>\n"
"<nav class='tabs' aria-label='Views'><button data-view='overview' aria-selected='true'>Overview</button><button data-view='manage'>Manage</button><button data-view='direct'>Direct</button><button data-view='raw'>Raw</button></nav>\n"
"<section id='overview' class='grid view'></section>\n"
"<section id='manage' class='grid view' hidden></section>\n"
"<section id='direct' class='grid view' hidden></section>\n"
"<section id='raw' class='grid view' hidden><article class='panel span12'><h2>Response</h2><div class='body'><pre id='rawOut'>{}</pre></div></article></section>\n"
"</main>\n"
"<script>\n";

static const char NTAP_A_WEB_INDEX_2[] =
"const $=s=>document.querySelector(s);const statusEl=$('#status');const rawOut=$('#rawOut');let lastJson={};\n"
"const lists=[['Networks','/api/network/list'],['Nodes','/api/node/list'],['TAP Users','/api/tap-user/list'],['SOCKS Users','/api/socks-user/list'],['Sessions','/api/session/list'],['SOCKS Streams','/api/socks-stream/list']];\n"
"function setStatus(t,cls=''){statusEl.textContent=t;statusEl.className='status '+cls}\n"
"function hex(buf){return Array.from(new Uint8Array(buf)).map(b=>b.toString(16).padStart(2,'0')).join('')}\n"
"async function sha256(s){return hex(await crypto.subtle.digest('SHA-256',new TextEncoder().encode(s)))}\n"
"async function hmac(key,msg){const k=await crypto.subtle.importKey('raw',new TextEncoder().encode(key),{name:'HMAC',hash:'SHA-256'},false,['sign']);return hex(await crypto.subtle.sign('HMAC',k,new TextEncoder().encode(msg)))}\n"
"async function api(path,params={}){const key=$('#apiKey').value;if(!key){throw new Error('missing api key')}const body=new URLSearchParams(params).toString();const bodySha=await sha256(body);const ts=String(Math.floor(Date.now()/1000));const nonce=(crypto.randomUUID?crypto.randomUUID():String(Date.now())+Math.random());const sign=await hmac(key,['POST',path,bodySha,ts,nonce].join('\\n'));const r=await fetch(path,{method:'POST',headers:{'Content-Type':'application/x-www-form-urlencoded','X-NTAP-Timestamp':ts,'X-NTAP-Nonce':nonce,'X-NTAP-Body-SHA256':bodySha,'X-NTAP-Sign':sign},body});const text=await r.text();let json;try{json=JSON.parse(text)}catch(e){json={code:0,msg:text}}lastJson=json;rawOut.textContent=JSON.stringify(json,null,2);if(!r.ok){throw new Error(json.msg||r.statusText)}return json}\n"
"function rowsOf(json){if(Array.isArray(json.rows))return json.rows;if(json.data&&Array.isArray(json.data.rows))return json.data.rows;if(Array.isArray(json.data))return json.data;if(json.data)return[json.data];return[json]}\n"
"function table(rows){if(!rows.length)return '<div class=\"status\">empty</div>';const keys=[...new Set(rows.flatMap(r=>Object.keys(r)))];return '<div class=\"tablewrap\"><table><thead><tr>'+keys.map(k=>'<th>'+esc(k)+'</th>').join('')+'</tr></thead><tbody>'+rows.map(r=>'<tr>'+keys.map(k=>'<td>'+esc(r[k])+'</td>').join('')+'</tr>').join('')+'</tbody></table></div>'}\n"
"function esc(v){if(v===null||v===undefined)return'';return String(v).replace(/[&<>\"']/g,c=>({'&':'&amp;','<':'&lt;','>':'&gt;','\"':'&quot;',\"'\":'&#39;'}[c]))}\n"
"function panel(title,span,inner){return '<article class=\"panel '+span+'\"><h2>'+esc(title)+'</h2><div class=\"body\">'+inner+'</div></article>'}\n"
"async function loadPanel(title,path){try{const json=await api(path);$('#p-'+slug(title)).innerHTML=table(rowsOf(json))}catch(e){$('#p-'+slug(title)).innerHTML='<div class=\"status bad\">'+esc(e.message)+'</div>'}}\n"
"function slug(s){return s.toLowerCase().replace(/[^a-z0-9]+/g,'-')}\n"
"async function refresh(){setStatus('loading');await Promise.all(lists.map(([t,p])=>loadPanel(t,p)));setStatus('ready','ok')}\n"
"function form(fields){return '<div class=\"formgrid\">'+fields.map(f=>'<div class=\"field\"><label>'+esc(f.label||f.name)+'</label>'+input(f)+'</div>').join('')+'</div>'}\n"
"function input(f){if(f.options)return '<select name=\"'+esc(f.name)+'\">'+f.options.map(o=>'<option value=\"'+esc(o)+'\">'+esc(o)+'</option>').join('')+'</select>';return '<input name=\"'+esc(f.name)+'\" value=\"'+esc(f.value||'')+'\" type=\"'+esc(f.type||'text')+'\">'}\n"
"function vals(root){const out={};root.querySelectorAll('input,select').forEach(i=>{if(i.value!=='')out[i.name]=i.value});return out}\n"
"function actionPanel(title,path,fields,buttons){const id='f-'+slug(title);return panel(title,'span6','<form id=\"'+id+'\">'+form(fields)+'<div class=\"actions\">'+buttons.map(b=>'<button type=\"button\" data-path=\"'+esc(b.path||path)+'\" class=\"'+esc(b.cls||'')+'\">'+esc(b.text)+'</button>').join('')+'</div></form>')}\n"
"async function runAction(btn){const formEl=btn.closest('form');try{setStatus('saving');const json=await api(btn.dataset.path,vals(formEl));setStatus('saved','ok');rawOut.textContent=JSON.stringify(json,null,2);await refresh()}catch(e){setStatus(e.message,'bad')}}\n";

static const char NTAP_A_WEB_INDEX_3[] =
"function boot(){const overview=$('#overview');overview.innerHTML=lists.map(([t])=>panel(t,t==='SOCKS Streams'||t==='Sessions'?'span12':'span6','<div id=\"p-'+slug(t)+'\" class=\"status\">idle</div>')).join('');$('#manage').innerHTML=actionPanel('Network','/api/network/add',[{name:'name'},{name:'mtu',value:'1400'}],[{text:'Add',cls:'primary'}])+actionPanel('Node','/api/node/add',[{name:'name'},{name:'node_id'},{name:'node_key',type:'password'},{name:'network_id'},{name:'tap_name',value:'ntap-b0'},{name:'bridge_name'},{name:'mtu',value:'1400'},{name:'direct_port'},{name:'max_socks_streams',value:'32'},{name:'socks_idle_timeout_sec',value:'300'}],[{text:'Add',cls:'primary'}])+actionPanel('TAP User','/api/tap-user/add',[{name:'username'},{name:'password',type:'password'},{name:'network_id'}],[{text:'Add',cls:'primary'}])+actionPanel('SOCKS User','/api/socks-user/add',[{name:'username'},{name:'password',type:'password'},{name:'node_id'}],[{text:'Add',cls:'primary'}])+actionPanel('TAP Grant','/api/tap-user/grant',[{name:'user_id'},{name:'network_id'}],[{text:'Grant',cls:'primary'},{text:'Revoke',path:'/api/tap-user/revoke',cls:'warn'}])+actionPanel('SOCKS Grant','/api/socks-user/grant',[{name:'user_id'},{name:'node_id'}],[{text:'Grant',cls:'primary'},{text:'Revoke',path:'/api/socks-user/revoke',cls:'warn'}])+actionPanel('Service','/api/service/status',[{name:'node_id'},{name:'type',options:['tap','socks','direct']}],[{text:'Status'},{text:'Start',path:'/api/service/start',cls:'primary'},{text:'Stop',path:'/api/service/stop',cls:'warn'}]);$('#direct').innerHTML=actionPanel('Direct Probe','/api/direct/probe',[{name:'node_id'},{name:'addr'},{name:'timeout_ms',value:'1000'}],[{text:'Probe',cls:'primary'}])+actionPanel('Direct Strategy','/api/direct/strategy',[{name:'node_id'},{name:'tap_user_id'},{name:'addr'},{name:'ttl_sec',value:'60'}],[{text:'Strategy',cls:'primary'}])+actionPanel('Direct Token','/api/direct-token/issue',[{name:'node_id'},{name:'tap_user_id'},{name:'ttl_sec',value:'60'}],[{text:'Issue',cls:'primary'}]);document.querySelectorAll('.tabs button').forEach(b=>b.onclick=()=>{document.querySelectorAll('.tabs button').forEach(x=>x.setAttribute('aria-selected','false'));b.setAttribute('aria-selected','true');document.querySelectorAll('.view').forEach(v=>v.hidden=v.id!==b.dataset.view)});document.body.addEventListener('click',e=>{if(e.target.matches('form button'))runAction(e.target)});$('#refresh').onclick=refresh;$('#health').onclick=async()=>{try{setStatus('checking');rawOut.textContent=JSON.stringify(await api('/api/health'),null,2);setStatus('ok','ok')}catch(e){setStatus(e.message,'bad')}};$('#clear').onclick=()=>{$('#apiKey').value='';setStatus('idle');rawOut.textContent='{}'}}\n"
"boot();\n"
"</script>\n"
"</body>\n"
"</html>\n";

static const char *const NTAP_A_WEB_INDEX_PARTS[] = {
    NTAP_A_WEB_INDEX_0,
    NTAP_A_WEB_INDEX_1,
    NTAP_A_WEB_INDEX_2,
    NTAP_A_WEB_INDEX_3
};

#define NTAP_A_WEB_INDEX_PART_COUNT \
    (sizeof(NTAP_A_WEB_INDEX_PARTS) / sizeof(NTAP_A_WEB_INDEX_PARTS[0]))

#endif
