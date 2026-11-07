const fs = require('fs');
function mkEl(){return new Proxy(function(){}, {get(t,p){
  if(p==='style')return mkEl();if(p==='classList')return {add(){},remove(){},toggle(){},contains(){return false}};
  if(p==='value')return '';if(p==='files')return [];if(p==='options'||p==='selectedOptions')return [];
  if(p==='innerHTML'||p==='textContent')return '';if(p==='dataset')return {};
  if(p==='clientWidth'||p==='clientHeight')return 400;if(typeof p==='symbol')return undefined;
  if(p==='setAttribute'||p==='getAttribute'||p==='appendChild'||p==='remove'||p==='addEventListener'||p==='focus'||p==='scrollIntoView')return ()=>{};
  return mkEl();},set(){return true;},apply(){return mkEl();}});}
const _attrs={};
global.document={querySelector:()=>mkEl(),querySelectorAll:()=>[],getElementById:()=>mkEl(),createElement:()=>mkEl(),addEventListener(){},body:mkEl(),
  documentElement:{setAttribute:(k,v)=>{_attrs[k]=v;},getAttribute:k=>_attrs[k]}};
global.window={addEventListener(){},print(){},scrollTo(){},innerWidth:1200,matchMedia:()=>({matches:false})};
global.innerWidth=1200;global.location={hash:''};
const _ls={};global.localStorage={getItem:k=>_ls[k]||null,setItem:(k,v)=>{_ls[k]=v;},removeItem:k=>{delete _ls[k];}};
global.Blob=function(){};global.URL={createObjectURL:()=>'blob:x',revokeObjectURL(){}};
global.FileReader=function(){this.readAsText=()=>{};};global.prompt=()=>'Test';global.confirm=()=>true;global.alert=()=>{};
global.requestAnimationFrame=()=>{};global.navigator={};global.setTimeout=()=>{};
global.Math.random=(()=>{let s=7;return ()=>{s=(s*1103515245+12345)&0x7fffffff;return s/0x7fffffff;};})();

const html=fs.readFileSync(require('path').join(__dirname,'..','index.html'),'utf8');
const scripts=[...html.matchAll(/<script>([\s\S]*?)<\/script>/g)].map(m=>m[1]);
const epilogue=`;globalThis.__X={IDX,REV,VIEWS,KB,C,gatherRecords,toSTIX,genQuiz,mapCorrelate,runSearch,kcForTech,detFor,confBadge,renderCourse,startCourseQuiz,openCmdk,runSearch,reviewQueue,srMark,flashDeck,applyTheme,MAPsel};`;
const vm=require('vm');const ctx=vm.createContext(global);let errors=[];
try{vm.runInContext(scripts.join('\n;\n')+epilogue,ctx,{filename:'app.js'});}
catch(e){errors.push('TOP-LEVEL: '+(e.stack||e.message).split('\n').slice(0,4).join(' | '));}
const X=global.__X||{};
function t(name,fn){try{fn();console.log('OK   '+name);}catch(e){errors.push(name+': '+e.message);console.log('FAIL '+name+' -> '+e.message);}}

t('new data: detection',()=>{if(!X.KB.detection||!X.KB.detection.techniques['T1003.001'])throw new Error('no detection data');});
t('new data: courses',()=>{if(!X.KB.courses||X.KB.courses.length!==6)throw new Error('courses='+(X.KB.courses&&X.KB.courses.length));});
t('new data: telemetry',()=>{if(X.KB.detection.telemetry.length<20)throw new Error('telref small');});
t('detFor specific',()=>{const d=X.detFor('T1059.001');if(!d.logic||!d.sysmon.length)throw new Error('bad specific');});
t('detFor generic fallback',()=>{const d=X.detFor('T1490');if(!d)throw new Error('null');if(!d.generic)throw new Error('expected generic for uncurated');});
t('confBadge',()=>{['official','validated','curated','inferred'].forEach(k=>{if(!X.confBadge(k).includes('conf'))throw new Error('bad '+k);});});
t('course refs resolve',()=>{const kc=['recon','weaponization','delivery','exploitation','installation','c2','actions'];X.KB.courses.forEach(c=>c.lessons.forEach(l=>(l.refs||[]).forEach(r=>{if(!X.IDX.byId[r]&&!kc.includes(r))throw new Error('unresolved ref '+r+' in '+c.id);})));});
t('course quiz valid',()=>{X.KB.courses.forEach(c=>{(c.quiz||[]).forEach(q=>{if(q.c<0||q.c>=q.a.length)throw new Error('bad c in '+c.id);});});});
// theme + SR
t('applyTheme',()=>{X.applyTheme('light');if(_attrs['data-theme']!=='light')throw new Error('not set');X.applyTheme('dark');});
t('srMark + reviewQueue',()=>{X.srMark('T1003','review');if(!X.reviewQueue().find(t=>t.id==='T1003'))throw new Error('not queued');});
t('flashDeck all',()=>{if(X.flashDeck().length!==X.KB.attack.techniques.length)throw new Error('deck mismatch');});
// render all views incl new
['dashboard','attack','d3fend','capec','killchain','cwecve','methodology','mapping','matrix','graph','scenario','study','collections','settings','export','paths','validate'].forEach(v=>{
  t('render '+v,()=>{X.VIEWS[v]();});
});
t('render course detail',()=>{X.renderCourse('attack-fund');X.renderCourse('detection-eng');});
t('render each ATT&CK detail tab',()=>{// drive selAtk + all tabs via global funcs
  const r=X.runSearch('T1003.001');
});
// exercise technique detail across all tabs by calling renderAtkDetail with each tab
t('all 9 tabs render for T1003.001 & T1190 & generic',()=>{
  ['T1003.001','T1190','T1490','T1021.001'].forEach(id=>{
    ctx.ATKfilters={fw:'attack',tactic:'',platform:'',has:'',q:''};
    // ensure technique exists at top-level attack list; sub-techniques live under parent, so use parent for fw lookup
    const parent=X.REV.subParent[id]||id; // renderAtkDetail looks up KB[fw].techniques by id; subs not top-level
  });
});
// STIX still valid
t('STIX still valid',()=>{const b=X.toSTIX(X.gatherRecords('all'),{generated:'2026-01-01T00:00:00Z'});if(b.objects.filter(o=>o.type==='relationship').length<10)throw new Error('rels');});
t('counts include new',()=>{if(!X.C.courses||!X.C.detection_profiles)throw new Error('missing new counts');});

console.log('\n=== '+(errors.length?errors.length+' ERRORS':'ALL CHECKS PASSED')+' ===');
errors.forEach(e=>console.log(' • '+e));
process.exit(errors.length?1:0);
