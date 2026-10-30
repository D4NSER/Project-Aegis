'use strict';
const $=s=>document.querySelector(s);
const esc=v=>String(v??'').replace(/[&<>"']/g,c=>({'&':'&amp;','<':'&lt;','>':'&gt;','"':'&quot;',"'":'&#39;'}[c]));
const S={page:'home',meta:null,results:[],catalog:null,selected:new Set(),result:null,resultKey:null,resultFilter:'all',fileFilter:'all',query:'',guide:0,settingsTab:'vm',busy:false,lab:null,drawer:false,reduced:false};
const pending=new Map();let sequence=0,toastTimer;
const modes={inert_text_control:'Mac kontrolė',catalog_hash_check:'Failų maišos',selection_plan:'Pasirinkimo planas',guest_inert_transfer_control:'VM kontrolė',scanner_inert_control:'Skeneriai',benign_pe_rehearsal:'PE repeticija',selection_transfer_control:'Failų perdavimas'};
const labTasks={cycle:['Patikrinti eigą ir atkūrimą','Trys kontroliniai tekstai, ataskaita ir švari VM.'],scan:['Patikrinti YARA ir Defender','Nekenksmingų tekstų skenavimas. Gali reikėti Windows patvirtinimo.'],transfer:['Perduoti pasirinktą planą','Tik baitų ir maišų patikra. Perduoti failai nevykdomi.'],status:['Atnaujinti Windows būseną','Gauti naują laboratorijos atsakymą.'],restore:['Užbaigti atkūrimą','Tęsti jau išsaugoto rezultato atkūrimą.'],continue_boot:['Tęsti po Fusion paleidimo','Patikrinti paleistą Windows ir tęsti išsaugotą etapą.'],scanner_poll:['Gauti skenerių rezultatą','Užbaigti laukiančią kontrolę.'],scanner_defer:['Atidėti Defender ir atkurti','Užregistruoti atidėjimą ir grąžinti švarią VM.'],lab_prepare:['Paruošti ARM įrankius','Patikrinti ir paruošti laboratorijos įrankius.'],lab_start:['Paleisti PE repeticiją','Tik dvi paruoštos nepavojingos programos.'],lab_poll:['Gauti PE repeticijos rezultatą','Pasiimti jau paruoštos kontrolės atsakymą.'],lab_defer:['Atidėti repeticiją ir atkurti','Išsaugoti atidėjimą ir atkurti VM.']};

function rpc(op,args={}){return new Promise((resolve,reject)=>{const id=++sequence;pending.set(id,{resolve,reject});window.webkit.messageHandlers.aegis.postMessage({id,op,args});});}
function pick(kind){return new Promise((resolve,reject)=>{const id=++sequence;pending.set(id,{resolve,reject});window.webkit.messageHandlers.aegis.postMessage({id,native:'pick',kind});});}
window.aegisReceive=value=>{
  if(value.event==='offline'){toast(value.data,true);$('#status').textContent=value.data;return;}
  if(value.event==='lab'){
    const before=S.lab?.busy;S.lab=value.data;
    if(S.drawer)renderLab();
    if(before&&!S.lab?.busy)setTimeout(()=>refresh(false),100);
    return;
  }
  const callback=pending.get(value.id);if(!callback)return;pending.delete(value.id);
  value.ok?callback.resolve(value.data):callback.reject(new Error(value.error||'Veiksmas nebaigtas.'));
};
function toast(text,error=false){clearTimeout(toastTimer);$('#toast').className='toast'+(error?' error':'');$('#toast').textContent=text;$('#status').textContent=text;toastTimer=setTimeout(()=>$('#toast').classList.add('hidden'),5000);}
function gb(value){return value==null?'—':(value/1e9).toLocaleString('lt-LT',{maximumFractionDigits:1})+' GB';}
function date(value){if(!value)return '—';const d=new Date(value);return Number.isNaN(d.valueOf())?'—':d.toLocaleString('lt-LT',{month:'2-digit',day:'2-digit',hour:'2-digit',minute:'2-digit'});}
function vmName(){return ({running:'Windows veikia',stopped:'Windows išjungta',suspended:'Windows pristabdyta',unknown:'Būsena nežinoma'})[S.meta?.vm?.state]||'Tikrinama';}
function tag(text,tone=''){return `<span class="badge ${tone}">${esc(text)}</span>`;}
function resultTone(row){return /Reikia|nepatvirt|nepavyko|neatitik/i.test(row.state)?'warn':row.mode==='selection_plan'?'purple':'good';}
function button(text,action,primary=false,extra=''){return `<button class="${primary?'primary':'secondary'}" data-action="${action}" ${extra}>${text}</button>`;}
function setBusy(value){S.busy=value;$('#refresh').classList.toggle('spinner',value);document.querySelectorAll('[data-mutates]').forEach(b=>b.disabled=value||(['check-files','save-plan'].includes(b.dataset.action)&&S.selected.size===0));}
async function run(op,args={},success){
  if(S.busy){toast('Palauk dabartinio veiksmo pabaigos.');return;}
  setBusy(true);
  try{const value=await rpc(op,args);if(success)success(value);return value;}
  catch(error){toast(error.message,true);}
  finally{setBusy(false);}
}
async function refresh(redraw=true){
  if(S.busy||S.lab?.busy)return;
  return run('refresh',{},value=>{S.meta=value;S.results=value.results;S.catalog=value.catalog;S.lab=value.lab;
    $('#connection').className='connection '+(value.vm.state==='running'?'running':'');
    $('#connection').innerHTML='<i></i>'+esc(vmName());
    $('#status').textContent='Būsena patikrinta '+new Date().toLocaleTimeString('lt-LT',{hour:'2-digit',minute:'2-digit'});
    if(redraw)render();
    else{if($('#home-vm'))$('#home-vm').textContent=vmName().replace('Windows ','');if($('#home-free'))$('#home-free').textContent=gb(value.vm.vm_free_bytes);if($('#home-count'))$('#home-count').textContent=S.results.length;}
  });
}
function navigate(page){S.page=page;S.query='';render();}
function render(){
  if(!S.meta)return;
  document.querySelectorAll('.nav').forEach(b=>{b.classList.toggle('active',b.dataset.page===S.page);b.setAttribute('aria-current',b.dataset.page===S.page?'page':'false');});
  $('#main').innerHTML=({home:homePage,files:filesPage,results:resultsPage,guide:guidePage,settings:settingsPage}[S.page]||homePage)();
  if(S.page==='files'&&S.catalog)updateSelection();
}
function header(title,description,actions=''){return `<div class="page-head"><div><h1>${title}</h1><p>${description}</p></div><div class="row">${actions}</div></div>`;}
function scene(){return '<div class="scene" aria-hidden="true"><div class="halo"></div><div class="orbit"></div><div class="window-art"></div><div class="window-art front"><span class="shield">✓</span></div><span class="scene-label">PROJECT AEGIS LAB</span></div>';}
function recent(row){return `<button class="recent-item" data-result="${esc(row.key)}"><span class="recent-icon">◷</span><span class="grow"><strong>${esc(row.title)}</strong><small>${esc(date(row.date))} · ${esc(modes[row.mode]||'Įrašas')}</small></span><span class="muted">↗</span></button>`;}
function homePage(){
  return `<section class="page home"><div class="hero"><div class="hero-copy"><div class="eyebrow">TAVO VIETINĖ LABORATORIJA</div><h1>Tavo tyrimo erdvė.</h1><p>Pasirink failus. Atlik kontrolę Windows aplinkoje.<br>Grįžk prie rezultatų, kurie išlieka šiame Mac.</p><div class="row">${button('Atverti laboratoriją <span>↗</span>','lab',true)}${button('Pasirinkti failus','go-files')}</div></div>${scene()}</div>
    <div class="metrics"><div class="metric"><span>Laboratorija</span><strong id="home-vm">${esc(vmName().replace('Windows ','').replace(/^./,v=>v.toUpperCase()))}</strong></div><div class="metric"><span>Laisva VM saugykloje</span><strong id="home-free">${gb(S.meta.vm.vm_free_bytes)}</strong></div><div class="metric"><span>Išsaugoti įrašai</span><strong id="home-count">${S.results.length}</strong></div></div>
    <div class="home-bottom"><div class="panel recent-panel"><div class="section-label"><h2>Paskutiniai įrašai</h2><button class="quiet" data-page="results">Visi rezultatai ↗</button></div>${S.results.slice(0,2).map(recent).join('')||'<p>Čia atsiras pirmosios kontrolės rezultatas.</p>'}</div>
    <div class="panel next-step"><div><div class="eyebrow">TĘSK NUO ČIA</div><h3>${S.catalog?'Kolekcija jau pasirinkta':'Pradėk nuo nedidelės kontrolės'}</h3><p>${S.catalog?'Peržiūrėk objektus, pažymėk reikalingus failus ir išsaugok jų pasirinkimą.':'Mokomajame kataloge yra trys nepavojingi tekstai. Tinka susipažinti su eiga be HDD.'}</p></div><div class="row">${button(S.catalog?'Atverti failus →':'Mokomieji failai →',S.catalog?'go-files':'demo')}<button class="quiet" data-page="guide">Trumpas vadovas</button></div></div></div></section>`;
}
function segments(items,current,attribute){return `<div class="segments">${items.map(([key,text])=>`<button class="segment ${current===key?'active':''}" ${attribute}="${key}" aria-pressed="${current===key}">${text}</button>`).join('')}</div>`;}
function visibleFiles(){return (S.catalog?.objects||[]).filter(row=>(S.fileFilter==='all'||row.split===S.fileFilter)&&(!S.query||Object.values(row).join(' ').toLowerCase().includes(S.query.toLowerCase())));}
function fileRows(){if(!visibleFiles().length)return '<tr><td colspan="7"><div class="empty">Pagal šį filtrą failų nėra.</div></td></tr>';return visibleFiles().map(row=>`<tr class="${S.selected.has(row.object_id)?'selected':''}" data-file="${esc(row.object_id)}"><td><input type="checkbox" data-file-check="${esc(row.object_id)}" aria-label="Pasirinkti ${esc(row.object_id)}" ${S.selected.has(row.object_id)?'checked':''}></td><td><strong>${esc(row.object_id)}</strong><span class="sub">${esc(row.project_id)}</span></td><td>${esc(row.relative_path)}</td><td>${esc(({control:'Kontrolinis',benign:'Nekenksmingas',malicious:'Tyrimo objektas'})[row.label]||row.label)}</td><td>${esc(({calibration:'Kalibravimas',evaluation:'Vertinimas'})[row.split]||'Nepriskirta')}</td><td>${Number(row.bytes).toLocaleString('lt-LT')} B</td><td>${tag(row.eligibility_status==='DEMO_ONLY'?'Mokomasis':row.eligibility_status,'purple')}</td></tr>`).join('');}
function filesPage(){
  const loaded=!!S.catalog;
  return `<section class="page">${header('Failai','Tik pasirinkti objektai keliauja į laboratoriją.',button('Pasirinkti kolekciją','choose-collection',false,'data-mutates')+(loaded?button('Atnaujinti','reload-collection',false,'data-mutates'):''))}
    ${loaded?`<div class="toolbar">${segments([['all','Visi'],['calibration','Kalibravimas'],['evaluation','Vertinimas'],['','Nepriskirta']],S.fileFilter,'data-file-filter')}<input class="search" id="file-search" type="search" placeholder="Ieškoti failo ar projekto…" value="${esc(S.query)}" aria-label="Ieškoti failų"></div>
    <div class="table-panel"><div class="table-scroll"><table class="file-table"><colgroup><col><col><col><col><col><col><col></colgroup><thead><tr><th><input id="all-files" type="checkbox" aria-label="Pasirinkti visus matomus"></th><th>Objektas / projektas</th><th>Failas</th><th>Žyma</th><th>Dalis</th><th>Dydis</th><th>Tinkamumas</th></tr></thead><tbody id="file-rows">${fileRows()}</tbody></table></div><div class="table-bottom"><span>${S.catalog.objects.length} objektai · kolekcija tik skaitoma</span><span>${S.catalog.objects.every(r=>r.eligibility_status==='DEMO_ONLY')?'Mokomieji tekstai · tyrimo imčiai nepriklauso':'Katalogo objektai dar nepatvirtina tyrimo parengties'}</span></div></div>
    <div class="selection-bar"><span id="selection-count">Pasirinkta ${S.selected.size}</span><div class="row"><input id="plan-title" placeholder="Pasirinkimo pavadinimas" value="Mano pasirinkimas" maxlength="100" aria-label="Plano pavadinimas">${button('Patikrinti maišas','check-files',false,'data-mutates')}${button('Išsaugoti planą →','save-plan',true,'data-mutates')}</div></div>`:
    `<div class="table-panel"><div class="catalog-empty"><span class="empty-symbol">▤</span><h2>Pasirink, su kuo dirbsi</h2><p>Atverk kolekcijos aplanką iš HDD arba išbandyk paruoštus mokomuosius failus.</p><div class="row">${button('Pasirinkti aplanką','choose-collection',true,'data-mutates')}${button('Mokomieji failai','demo',false,'data-mutates')}</div><p><small>HDD prijungiamas prie Mac tik skaitymui. Originalai lieka jame.</small></p></div></div>`}</section>`;
}
function resultGroup(row){if(row.mode==='selection_plan')return 'plans';if(['guest_inert_transfer_control','selection_transfer_control','benign_pe_rehearsal'].includes(row.mode))return 'vm';if(row.mode==='scanner_inert_control')return 'scanners';return 'other';}
function filteredResults(){return S.results.filter(row=>(S.resultFilter==='all'||resultGroup(row)===S.resultFilter)&&(!S.query||(row.title+' '+row.state).toLowerCase().includes(S.query.toLowerCase())));}
function resultRows(){if(!filteredResults().length)return '<tr><td colspan="3"><div class="empty">Pagal šį filtrą įrašų nėra.</div></td></tr>';return filteredResults().map(row=>`<tr data-result="${esc(row.key)}" class="${row.key===S.resultKey?'selected':''}" tabindex="0" aria-label="${esc(row.title)}"><td><span class="result-title">${esc(row.title)}</span><span class="sub">${esc(modes[row.mode]||'Įrašas')} · ${esc(date(row.date))}</span></td><td>${row.count}</td><td>${tag(row.state,resultTone(row))}</td></tr>`).join('');}
function resultDetail(){
  if(!S.result)return '<div class="empty"><div><span class="empty-symbol">◷</span>Pasirink įrašą ir peržiūrėk jo rezultatą.</div></div>';
  const {report,summary}=S.result;
  const labels={MATCHED:'Žymuo rastas',NOT_MATCHED:'Žymens nėra',NOT_DETECTED:'Neaptikta',DETECTED:'Aptikta',NOT_RUN:'Nepaleista',ERROR:'Klaida',VERIFIED:'Patikrinta'};
  const checks={functionality_passed:'Programų funkcionalumas',independent_file_writes_observed:'Nepriklausomas failų stebėjimas',yara_positive_and_negative:'YARA teigiama ir neigiama kontrolė',yara_invalid_rule_rejected:'YARA klaidos kontrolė',defender_negative_controls:'Defender neigiama kontrolė',defender_eicar_observed:'Defender EICAR kontrolė',missing_input_not_negative:'Trūkstamo failo apskaita'};
  return `<div><div class="eyebrow">ĮRAŠO PERŽIŪRA</div><h2>${esc(summary.title)}</h2></div>${tag(summary.state,resultTone(summary))}<div><div class="detail-pair"><span class="muted">Laikas</span><span>${esc(date(summary.date))}</span></div><div class="detail-pair"><span class="muted">Failai</span><span>${summary.count}</span></div><div class="detail-pair"><span class="muted">Tipas</span><span>${esc(modes[report.mode])}</span></div></div>
    <div><div class="eyebrow">FAILŲ ATSAKYMAI</div>${report.files.map(row=>`<div class="file-proof">${esc(row.object_id||row.id||'Failas')}<small>${row.bytes!=null?esc(row.bytes)+' B · ':''}${row.verified===true||row.hash_verified===true?'Maiša sutampa':row.verified===false||row.hash_verified===false?'Maiša nepatvirtinta':esc(labels[row.status]||row.status||'Ataskaitos įrašas')}${row.yara_status?'<br>YARA: '+esc(labels[row.yara_status]||row.yara_status):''}${row.av_status?'<br>Defender: '+esc(labels[row.av_status]||row.av_status):''}</small></div>`).join('')}</div>
    ${report.checks?`<div><div class="eyebrow">KONTROLĖS KRITERIJAI</div>${Object.entries(report.checks).map(([key,passed])=>`<div class="file-proof">${esc(checks[key]||key)}<small>${passed===true?'Patvirtinta':'Reikia patikros'}</small></div>`).join('')}</div>`:''}
    <div class="detail-note">${report.mode==='selection_plan'?'Tai pasirinkimo planas. Failai į VM dar neperduoti.':report.mode==='selection_transfer_control'?'Patikrintas pasirinkto poaibio perdavimas. Failai nevykdyti.':'Tai kontrolinė patikra. Ji nėra tyrimo eksperimentas.'}</div>
    <div class="detail-actions">${button('Eksportuoti ataskaitą ↗','export',true,'data-mutates')}<details><summary>Techninis įrašas</summary><pre>${esc(JSON.stringify(report,null,2))}</pre><button class="quiet" data-action="open-result">Atverti pirminį JSON ↗</button></details></div>`;
}
function resultsPage(){return `<section class="page">${header('Rezultatai','Patikros ir planai, išsaugoti už atkuriamos VM ribų.',button('Atverti aplanką ↗','open-results'))}<div class="toolbar">${segments([['all','Visi'],['vm','Windows VM'],['scanners','Skeneriai'],['plans','Planai'],['other','Kiti']],S.resultFilter,'data-result-filter')}<input id="result-search" class="search" type="search" placeholder="Ieškoti įrašo…" value="${esc(S.query)}" aria-label="Ieškoti rezultatų"></div><div class="result-layout"><div class="table-panel"><div class="table-scroll"><table class="results-table"><colgroup><col><col><col></colgroup><thead><tr><th>Įrašas</th><th>Failai</th><th>Būsena</th></tr></thead><tbody id="result-rows">${resultRows()}</tbody></table></div><div class="table-bottom"><span id="result-count">${filteredResults().length} įrašai</span><span>Originalūs įrodymai išlieka Mac</span></div></div><div class="result-detail" id="result-detail">${resultDetail()}</div></div></section>`;}
async function loadResult(key){
  S.resultKey=key;S.result=null;
  if(S.page!=='results')navigate('results');
  else{document.querySelectorAll('tr[data-result]').forEach(row=>row.classList.toggle('selected',row.dataset.result===key));$('#result-detail').innerHTML='<div class="empty">Įkeliamas įrašas…</div>';}
  try{const value=await rpc('result',{key});if(S.resultKey!==key)return;S.result=value;if(S.page==='results')$('#result-detail').innerHTML=resultDetail();}
  catch(error){toast(error.message,true);}
}
const guideSections=[
  {title:'Pradžia',heading:'Pirmas darbas su Aegis',intro:'Mac yra tavo valdymo ir rezultatų erdvė. Windows VM atlieka paruoštas kontroles ir po jų grįžta į švarią kopiją.',steps:[['Atverk laboratoriją','Pradžios lange paspausk „Atverti laboratoriją“. Prisijungimo skydelis atsivers dešinėje.'],['Įvesk du esamus slaptažodžius','Fusion VM šifravimo ir vietinės AegisLab paskyros. Jie naudojami tik atvertai sesijai.'],['Pasirink kontrolę','Pradėk nuo eigos ir atkūrimo patikros su trimis nepavojingais tekstais.']],note:'Windows darbalaukyje kol kas prisijungiama Fusion lange. Patvirtintas valdymo ryšys pats darbalaukio neatrakina.',action:['Atverti laboratoriją ↗','lab']},
  {title:'Failų pasirinkimas',heading:'Į VM keliauja tik tavo pasirinkimas',intro:'Kolekcijos aplanką paruošiame per Windows PC. Mac programoje dirbame su jo katalogu.',steps:[['Atverk kolekciją','„Failai“ skyriuje pasirink aplanką. Jame turi būti catalog/sources.csv, objects.csv ir selection.csv.'],['Pažymėk objektus','Paieška ir dalies filtrai padeda rasti reikalingus failus. Maišų patikra skaito tik pasirinktus objektus.'],['Išsaugok planą','Nurodyk trumpą pavadinimą. Plane turi būti viena tyrimo dalis ir protokolo versija; variantui reikia jo originalo.']],note:'HDD tik skaitomas. Plano išsaugojimas failų nevykdo ir į VM jų dar neperduoda.',action:['Atverti failus →','go-files']},
  {title:'Windows kontrolės',heading:'Vienas veiksmas vienu metu',intro:'Laboratorijos skydelyje matysi tik dabartinei sesijai prieinamus veiksmus.',steps:[['Patikrink aplinką','Atjungtas tinklas ir atskirta laboratorijos paskyra yra kontrolės sąlygos.'],['Atlik paruoštą veiksmą','Eigos, skenerių arba pasirinkimo plano perdavimo kontrolę. YARA ir Defender naudoja fiksuotus nepavojingus tekstus.'],['Palauk rezultato ir atkūrimo','Kol darbas nebaigtas, nauji veiksmai neprieinami. Jei reikia UAC „Yes“, tai padaryk Windows lange.']],note:'Paruoštų PE programų repeticija ir įrankių parengimas pasiekiami skydelio „Įrankiai ir repeticija“ dalyje. Savavališkų tyrimo failų vykdymas dar neparengtas.',action:['Atverti laboratoriją ↗','lab']},
  {title:'Rezultatai ir atkūrimas',heading:'Rezultatas turi išlikti',intro:'Originalus kontrolės atsakymas išsaugomas Mac prieš atkuriant Windows.',steps:[['Pasirink įrašą sąraše','Dešinėje matysi jo būseną ir failų atsakymus. Planas ir atlikta kontrolė žymimi atskirai.'],['Patikrink atkūrimo būseną','„VM atkurta“ rodoma tik patvirtinus atskirą atkūrimo įrodymą. Išsaugota ataskaita pati savaime dar nėra atkūrimas.'],['Eksportuok ataskaitą','ZIP pakete lieka JSON, CSV, maišos ir esantys atkūrimo įrodymai.']],note:'Kopijų ištrynimas ar „Suspend“ nėra švarios VM kopijos atkūrimas.',action:['Peržiūrėti rezultatus →','go-results']},
  {title:'Jei kažkas sustojo',heading:'Tęsk iš išsaugoto etapo',intro:'Neskubėk pradėti visko iš naujo. Laukiantis darbas išsaugo savo etapą.',steps:[['Fusion nepaleido VM','Atverk Windows ir pasirink „Virtual Machine → Start Up“. Aegis laukia jos paleidimo.'],['Laukiama Windows patvirtinimo','Prisijunk prie AegisLab darbalaukio ir atlik skydelyje nurodytą UAC žingsnį.'],['Trūksta vietos ar nežinoma baigtis','„Nustatymai → VM ir saugykla“ parodo būtent VM tomo vietą. Nežinoma baigtis nėra patvirtintas atkūrimas.']],note:'Windows išjunk įprastai. Fusion įrankių juostą palik paslėptą dėl ankstesnės strigties. ISO išlieka.',action:['Atverti nustatymus →','go-settings']}
];
function guidePage(){const section=guideSections[S.guide];return `<section class="page">${header('Trumpas vadovas','Pasirink darbo etapą ir gauk tik jam reikalingus žingsnius.')}<div class="guide-layout"><div class="guide-nav">${guideSections.map((item,i)=>`<button class="guide-step ${i===S.guide?'active':''}" data-guide="${i}"><span>${String(i+1).padStart(2,'0')}</span>${item.title}</button>`).join('')}</div><article class="panel guide-content"><div class="eyebrow">${String(S.guide+1).padStart(2,'0')} / DARBO EIGA</div><h2>${section.heading}</h2><p class="intro">${section.intro}</p>${section.steps.map(([title,text],i)=>`<div class="instruction"><span class="number">${i+1}</span><div><strong>${title}</strong><p>${text}</p></div></div>`).join('')}<div class="callout">${section.note}</div>${button(section.action[0],section.action[1],true)}</article></div></section>`;}
function settingsPage(){
  let content='';const config=S.meta.settings;
  if(S.settingsTab==='vm')content=`<div class="settings-grid"><div class="panel"><div class="eyebrow">WINDOWS APLINKA</div><h2>VM ir saugykla</h2><div class="fact"><span>Būsena</span>${esc(vmName())}</div><div class="fact"><span>Laisva VM tome</span>${gb(S.meta.vm.vm_free_bytes)}</div><div class="fact"><span>Laisva Mac diske</span>${gb(S.meta.vm.host_free_bytes)}</div><p>Tomo vieta ir Mac disko vieta yra skirtingi rodmenys.</p><div class="row">${button('Atverti Windows ↗','open-vm',true,'data-mutates')}${button('Prijungti saugyklą','mount',false,'data-mutates')}</div></div><div class="panel"><div class="eyebrow">VIETOS PLANAVIMAS</div><h2>Laboratorijos biudžetas</h2><div class="fact"><span>Patvirtinta riba</span>${gb(S.meta.budget?.limit_bytes||S.meta.budget?.budget_bytes)}</div><p>Skaičiuojami VM, paliktas Windows ISO, Fusion ir vietiniai įrankiai. Tai planavimo skaičiavimas, ne sistemos kvota.</p><div class="callout">Patikimas švarios būsenos atkūrimas atliekamas iš išjungtos VM kopijos.</div><label class="row"><input type="checkbox" id="reduce-motion" ${S.reduced?'checked':''}> <small>Sumažinti sąsajos judesį</small></label></div></div>`;
  if(S.settingsTab==='paths')content=`<div class="settings-grid"><form class="panel" id="settings-form"><div class="eyebrow">VIETINĖ KONFIGŪRACIJA</div><h2>Programos keliai</h2>${[['vm_bundle','Windows VM paketas','vm'],['disk_image','VM saugykla','image']].map(([key,label,kind])=>`<label class="setting-field">${label}<div class="setting-path"><input id="${key}" value="${esc(config[key])}" required><button type="button" class="secondary" data-pick-setting="${kind}" data-target="${key}">Pasirinkti</button></div></label>`).join('')}<button class="primary" type="submit" data-mutates>Išsaugoti kelius</button></form><div class="panel"><div class="eyebrow">IŠLIEKANTYS DUOMENYS</div><h2>Rezultatai šiame Mac</h2><p>Šis aplankas yra už atkuriamos VM ir viešos kodo saugyklos ribų.</p><details><summary>Rodyti aplanko vietą</summary><pre>${esc(S.meta.workspace)}</pre></details><div class="row">${button('Atverti aplanką ↗','open-results')}</div></div></div>`;
  if(S.settingsTab==='control')content=`<div class="settings-grid"><form class="panel" id="local-form"><div class="eyebrow">MAC VEIKIMO KONTROLĖ</div><h2>Kopijos, maišos ir išvalymas</h2><p>Ši kontrolė vyksta Mac. Ji nepaleidžia AV, YARA ar Windows bandymo.</p><div class="control-options">${S.meta.controls.map(c=>`<label><input name="control" type="checkbox" value="${esc(c.id)}" checked>${esc(c.title)}</label>`).join('')}</div><button class="primary" type="submit" data-mutates>Atlikti vietinę kontrolę</button><div class="local-output" id="local-output"></div></form><div class="panel"><div class="eyebrow">WINDOWS KONTROLĖS</div><h2>Laboratorijos darbai</h2><p>Windows eiga, YARA / Defender, paruošti ARM įrankiai ir PE repeticija surinkti laboratorijos skydelyje.</p>${button('Atverti laboratoriją ↗','lab')}<div class="callout">Tyrimo imtis ir tikrų objektų funkcionalumo vykdymas dar neparengti. Paruoštos kontrolės yra atskiras etapas.</div></div></div>`;
  return `<section class="page">${header('Nustatymai','Aplinkos būsena, vietiniai keliai ir priežiūros veiksmai.')}<div class="toolbar">${segments([['vm','VM ir saugykla'],['paths','Programos keliai'],['control','Kontrolės']],S.settingsTab,'data-settings-tab')}</div><div class="settings-layout">${content}</div></section>`;
}
function openLab(){S.drawer=true;$('#shade').classList.remove('hidden');$('#drawer').classList.remove('hidden');renderLab();}
function closeLabDrawer(){S.drawer=false;$('#shade').classList.add('hidden');$('#drawer').classList.add('hidden');}
function renderLab(){
  const lab=S.lab,allowed=lab?.allowed||[];
  const task=action=>`<button class="lab-task" data-lab-action="${action}" ${!allowed.includes(action)||lab?.busy?'disabled':''}><strong>${labTasks[action][0]} ↗</strong><small>${labTasks[action][1]}</small></button>`;
  const recovery=['restore','continue_boot','scanner_poll','scanner_defer','lab_poll','lab_defer'].filter(a=>allowed.includes(a));
  $('#drawer').innerHTML=`<div class="drawer-head"><div><div class="eyebrow">WINDOWS LABORATORIJA</div><h2>${lab?.connected?'Pasirink veiksmą':'Prisijungimas'}</h2></div><button class="close" data-action="close-drawer" aria-label="Uždaryti skydelį">×</button></div>
    ${lab?`<div class="lab-state ${lab.busy?'running':''}">${esc(lab.status)}</div>${lab.environment?`<p>${esc(lab.environment).replace(/\n/g,'<br>')}</p>`:''}`:
    `<p>Įvesk esamus šios VM slaptažodžius. Microsoft paskyros duomenų nereikia.</p><form id="lab-form"><label>Fusion VM slaptažodis<input id="vm-secret" type="password" autocomplete="off" required maxlength="1024"></label><label>AegisLab slaptažodis<input id="lab-secret" type="password" autocomplete="off" required maxlength="1024"></label><button class="primary" type="submit">Paleisti ir prisijungti ↗</button><small>Slaptažodžiai laikomi tik atvertos sesijos atmintyje.</small></form>`}
    ${lab?.connected?`<div class="lab-actions">${['cycle','scan','transfer'].map(task).join('')}</div>${!S.catalog?'<small>Failų perdavimui pirmiausia pasirink kolekciją.</small>':''}${recovery.length?`<div class="stack"><div class="eyebrow">LAUKIANTIS DARBAS</div>${recovery.map(task).join('')}</div>`:''}<details><summary>Įrankiai ir repeticija</summary><div class="lab-actions">${['lab_prepare','lab_start'].map(task).join('')}</div></details>`:''}
    <div class="stack">${button('Atverti Windows darbalaukį ↗','open-vm')}${lab?.connected?task('status'):''}</div><small>Windows darbalaukyje kol kas prisijunk Fusion lange. Valdymo ryšys jo automatiškai neatrakina.</small>
    ${lab?`<details><summary>Veiksmų istorija</summary><pre>${esc(lab.history||'Dar nėra įrašų.')}</pre></details><button class="quiet" data-action="lab-close" ${lab.busy?'disabled':''}>Uždaryti sesiją ir pamiršti slaptažodžius</button>`:''}`;
}
async function chooseCollection(){const path=await pick('collection');if(path)await run('collection_load',{path},value=>{S.catalog=value;S.selected.clear();navigate('files');toast('Katalogas įkeltas. Originalai tik skaitomi.');});}
async function action(name){
  if(name==='lab'){openLab();return;}if(name==='close-drawer'){closeLabDrawer();return;}
  if(name.startsWith('go-')){navigate(name.slice(3));return;}
  if(name==='choose-collection'){await chooseCollection();return;}
  if(name==='demo'){await run('demo',{},value=>{S.catalog=value;S.selected.clear();navigate('files');toast('Atverti trys mokomieji tekstai.');});return;}
  if(name==='reload-collection'){await run('collection_load',{path:S.catalog.root},value=>{S.catalog=value;S.selected.clear();render();toast('Katalogas atnaujintas.');});return;}
  if(name==='check-files'||name==='save-plan'){
    const title=$('#plan-title')?.value||'Mano pasirinkimas';
    await run(name==='check-files'?'catalog_check':'plan',{selected:[...S.selected],title},value=>{S.results=value.results;toast(name==='save-plan'?'Pasirinkimo planas išsaugotas. Failai nepaleisti.':value.report.all_verified?'Visos pasirinktų failų maišos sutampa.':'Rastas failų neatitikimas.');});return;
  }
  if(name==='export'){if(!S.resultKey){toast('Pasirink rezultatą.');return;}const path=await pick('export');if(path)await run('export',{key:S.resultKey,path},()=>toast('Ataskaita eksportuota.'));return;}
  if(name==='open-result'){await run('open_result',{key:S.resultKey});return;}
  if(name==='open-results'){await run('open_results');return;}
  if(name==='open-vm'){await run('open_vm');return;}
  if(name==='mount'){await run('mount',{},()=>toast('VM saugykla prijungta.'));await refresh();return;}
  if(name==='lab-close'){await run('lab_close',{},()=>{S.lab=null;renderLab();toast('Sesija uždaryta.');});}
}
document.addEventListener('click',async event=>{
  const b=event.target.closest('button');
  try{
    if(b&&!b.disabled){
      if(b.dataset.page){navigate(b.dataset.page);return;}
      if(b.dataset.action){await action(b.dataset.action);return;}
      if(b.dataset.resultFilter!=null){S.resultFilter=b.dataset.resultFilter;render();return;}
      if(b.dataset.fileFilter!=null){S.fileFilter=b.dataset.fileFilter;render();return;}
      if(b.dataset.guide!=null){S.guide=Number(b.dataset.guide);render();return;}
      if(b.dataset.settingsTab){S.settingsTab=b.dataset.settingsTab;render();return;}
      if(b.dataset.pickSetting){const path=await pick(b.dataset.pickSetting);if(path)$('#'+b.dataset.target).value=path;return;}
      if(b.dataset.labAction){let path=null;if(b.dataset.labAction==='transfer'){path=await pick('plan');if(!path)return;}await run('lab_action',{action:b.dataset.labAction,path},value=>{S.lab=value;renderLab();});return;}
    }
    const result=event.target.closest('[data-result]');if(result){await loadResult(result.dataset.result);return;}
    const file=event.target.closest('[data-file]');if(file&&!event.target.matches('input')){const id=file.dataset.file;S.selected.has(id)?S.selected.delete(id):S.selected.add(id);updateSelection();}
  }catch(error){toast(error.message,true);}
});
function updateSelection(){
  if($('#file-rows'))$('#file-rows').innerHTML=fileRows();
  if($('#selection-count'))$('#selection-count').textContent='Pasirinkta '+S.selected.size;
  const visible=visibleFiles(),all=$('#all-files');
  if(all){all.checked=visible.length>0&&visible.every(row=>S.selected.has(row.object_id));all.indeterminate=visible.some(row=>S.selected.has(row.object_id))&&!all.checked;}
  document.querySelectorAll('[data-action="check-files"],[data-action="save-plan"]').forEach(button=>button.disabled=S.busy||S.selected.size===0);
}
document.addEventListener('change',event=>{
  const target=event.target;
  if(target.dataset.fileCheck){target.checked?S.selected.add(target.dataset.fileCheck):S.selected.delete(target.dataset.fileCheck);updateSelection();}
  if(target.id==='all-files'){visibleFiles().forEach(row=>target.checked?S.selected.add(row.object_id):S.selected.delete(row.object_id));updateSelection();}
  if(target.id==='reduce-motion'){S.reduced=target.checked;document.body.classList.toggle('reduced',S.reduced);}
});
document.addEventListener('input',event=>{
  if(['file-search','result-search'].includes(event.target.id)){
    S.query=event.target.value;
    if(S.page==='files')updateSelection();
    else{$('#result-rows').innerHTML=resultRows();$('#result-count').textContent=filteredResults().length+' įrašai';}
  }
});
document.addEventListener('keydown',event=>{if(event.key==='Escape')closeLabDrawer();if(event.key==='Enter'&&event.target.matches('tr[data-result]'))loadResult(event.target.dataset.result);});
document.addEventListener('submit',async event=>{
  event.preventDefault();const form=event.target;
  if(form.id==='lab-form'){
    const vm_credential=$('#vm-secret').value,lab_credential=$('#lab-secret').value;
    $('#vm-secret').value='';$('#lab-secret').value='';
    await run('lab_connect',{vm_credential,lab_credential},value=>{S.lab=value;renderLab();});
  }
  if(form.id==='settings-form')await run('settings',{vm_bundle:$('#vm_bundle').value,disk_image:$('#disk_image').value},()=>toast('Programos keliai išsaugoti.'));
  if(form.id==='local-form')await run('local_control',{selected:[...form.querySelectorAll('input:checked')].map(v=>v.value)},value=>{S.results=value.results;$('#local-output').textContent='Kontrolė baigta. '+value.report.files.length+' failų atsakymai išsaugoti; darbo kopijos išvalytos.';toast('Vietinė kontrolė baigta.');});
});
$('#refresh').addEventListener('click',()=>refresh());$('#shade').addEventListener('click',closeLabDrawer);
window.aegisQuit=async()=>{if(S.busy||S.lab?.busy){toast('Palauk, kol baigsis ir bus išsaugotas vykdomas veiksmas.');return;}const value=await run('close');if(value?.closed)window.webkit.messageHandlers.aegis.postMessage({native:'quit'});};
refresh();setInterval(()=>{if(!document.hidden&&!S.drawer)refresh(false);},20000);
