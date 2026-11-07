// Minimal DOM/browser stub to run the app logic headlessly and catch runtime errors.
const fs = require('fs');
function mkEl(){
  return new Proxy(function(){}, {
    get(t,p){
      if(p==='style') return mkEl();
      if(p==='classList') return {add(){},remove(){},toggle(){},contains(){return false}};
      if(p==='value') return '';
      if(p==='files') return [];
      if(p==='options'||p==='selectedOptions') return [];
      if(p==='innerHTML'||p==='textContent') return '';
      if(p==='dataset') return {};
      if(p==='clientWidth'||p==='clientHeight') return 400;
      if(typeof p==='symbol') return undefined;
      return mkEl();
    },
    set(){return true;}, apply(){return mkEl();}
  });
}
global.document = { querySelector:()=>mkEl(), querySelectorAll:()=>[], getElementById:()=>mkEl(), createElement:()=>mkEl(), addEventListener(){}, body:mkEl() };
global.window = { addEventListener(){}, print(){}, scrollTo(){}, innerWidth:1200, matchMedia:()=>({matches:false}) };
global.innerWidth = 1200;
global.location = { hash:'' };
const _ls={};
global.localStorage = { getItem:k=>_ls[k]||null, setItem:(k,v)=>{_ls[k]=v;}, removeItem:k=>{delete _ls[k];} };
global.Blob=function(){};global.URL={createObjectURL:()=>'blob:x',revokeObjectURL(){}};
global.FileReader=function(){this.readAsText=()=>{};};
global.prompt=()=>'Test';global.confirm=()=>true;global.alert=()=>{};
global.requestAnimationFrame=()=>{};global.navigator={};
global.setTimeout=()=>{};
global.Math.random = (()=>{let s=42;return ()=>{s=(s*1103515245+12345)&0x7fffffff;return s/0x7fffffff;};})();

const html = fs.readFileSync(require('path').join(__dirname,'..','index.html'),'utf8');
const scripts = [...html.matchAll(/<script>([\s\S]*?)<\/script>/g)].map(m=>m[1]);
const epilogue = `;globalThis.__X={IDX,REV,VIEWS,KB,C,gatherRecords,toSTIX,genQuiz,mapCorrelate,runSearch,kcForTech,recT,exMeta:(typeof exMeta==='function'?exMeta:null)};`;
const combined = scripts.join('\n;\n') + epilogue;
const vm = require('vm');
const ctx = vm.createContext(global);
let errors=[];
try{ vm.runInContext(combined, ctx, {filename:'app.js'}); }
catch(e){ errors.push('TOP-LEVEL: '+ (e.stack||e.message).split('\n').slice(0,4).join(' | ')); }
const X = global.__X || {};

function tryCall(name, fn){ try{ fn(); console.log('OK   '+name); }catch(e){ errors.push(name+': '+e.message); console.log('FAIL '+name+' -> '+e.message); } }
tryCall('index populated', ()=>{ if(!X.IDX || X.IDX.search.length<60) throw new Error('index size '+(X.IDX&&X.IDX.search.length)); });
tryCall('byId T1059/T1003/T1021/CAPEC-66/CWE-89', ()=>{ ['T1059','T1003','T1021','CAPEC-66','CWE-89'].forEach(id=>{ if(!X.IDX.byId[id]) throw new Error('missing '+id); }); });
tryCall('search T1003 top', ()=>{ const r=X.runSearch('T1003'); if(r[0].id!=='T1003') throw new Error('top='+(r[0]&&r[0].id)); });
tryCall('search credential', ()=>{ if(!X.runSearch('credential').length) throw new Error('empty'); });
tryCall('search fuzzy t1059.001', ()=>{ const r=X.runSearch('T1059.001'); if(!r.find(x=>x.id==='T1059.001')) throw new Error('no sub match'); });
tryCall('REV attack2capec T1190', ()=>{ if(!(X.REV.attack2capec['T1190']||[]).length) throw new Error('none'); });
tryCall('REV attack2d3 T1003', ()=>{ if(!(X.REV.attack2d3['T1003']||[]).length) throw new Error('none'); });
tryCall('REV cwe2cve CWE-502', ()=>{ if(!(X.REV.cwe2cve['CWE-502']||[]).includes('CVE-2021-44228')) throw new Error('log4shell link missing'); });
tryCall('killchain for T1566', ()=>{ if(!X.kcForTech(X.REV.techById['T1566']).length) throw new Error('none'); });
tryCall('gatherRecords all>=100', ()=>{ const r=X.gatherRecords('all'); if(r.length<100) throw new Error('only '+r.length); });
tryCall('toSTIX all has relationships', ()=>{ const recs=X.gatherRecords('all'); const b=X.toSTIX(recs,{generated:'2026-01-01T00:00:00Z',author:'t',classification:'x',dataset:{}}); if(b.type!=='bundle') throw new Error('not bundle'); const rels=b.objects.filter(o=>o.type==='relationship'); if(rels.length<10) throw new Error('rels='+rels.length); const aps=b.objects.filter(o=>o.type==='attack-pattern'); if(!aps.length) throw new Error('no attack-patterns'); });
tryCall('STIX ids well-formed', ()=>{ const b=X.toSTIX(X.gatherRecords('all'),{generated:'2026-01-01T00:00:00Z'}); b.objects.forEach(o=>{ if(!/^[a-z-]+--[0-9a-f-]{36}$/.test(o.id)) throw new Error('bad id '+o.id); }); });
tryCall('genQuiz valid', ()=>{ for(let k=0;k<5;k++){ const q=X.genQuiz(); if(q.pool.length<1) throw new Error('empty'); q.pool.forEach(p=>{ if(typeof p.c!=='number'||p.c<0||p.c>=p.a.length) throw new Error('bad c'); if(p.a.length<2) throw new Error('few opts'); }); } });
tryCall('all VIEWS functions', ()=>{ ['dashboard','attack','d3fend','capec','killchain','cwecve','methodology','mapping','matrix','graph','scenario','study','collections','export','settings','searchresults'].forEach(v=>{ if(typeof X.VIEWS[v]!=='function') throw new Error('missing '+v); }); });

// Render every view (exercises template strings end-to-end)
['dashboard','attack','d3fend','capec','killchain','cwecve','methodology','mapping','matrix','graph','scenario','study','collections','settings'].forEach(v=>{
  tryCall('render '+v, ()=>{ X.VIEWS[v](); });
});
tryCall('render export', ()=>{ X.VIEWS.export(); });
tryCall('counts match KB', ()=>{ if(X.C.attack_techniques!==X.KB.attack.techniques.length) throw new Error('attack count'); if(X.C.d3fend!==X.KB.d3fend.techniques.length) throw new Error('d3 count'); });

console.log('\n=== '+(errors.length?errors.length+' ERRORS':'ALL '+'' +'CHECKS PASSED')+' ===');
errors.forEach(e=>console.log(' • '+e));
process.exit(errors.length?1:0);
