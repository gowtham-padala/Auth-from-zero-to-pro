import json, os, re, glob

import os as _os
ROOT = _os.path.dirname(_os.path.dirname(_os.path.abspath(__file__)))

# collect files in a canonical order
order = ["README.md", "GLOSSARY.md", "SOURCES.md",
         "appendix/decision-tree.md", "appendix/rfc-index.md", "appendix/excluded.md"]
for t in "abcdefghijk":
    for f in sorted(glob.glob(os.path.join(ROOT, f"book/track-{t}/*.md"))):
        order.append(os.path.relpath(f, ROOT))

book = {}
titles = {}
for rel in order:
    with open(os.path.join(ROOT, rel)) as fh:
        txt = fh.read()
    book[rel] = txt
    m = re.search(r'^#\s+(.+)$', txt, re.M)
    titles[rel] = m.group(1).strip() if m else rel

# sidebar structure
track_names = {
 "a":"How the web actually works","b":"Crypto foundations","c":"The map",
 "d":"Authentication","e":"Sessions & tokens","f":"Delegated authz — OAuth 2",
 "g":"Federated identity & SSO","h":"Authorization","i":"Lifecycle & operations",
 "j":"Machine, workload & agent identity","k":"The capstone"}

nav = {"front":[("README.md","Contents"),("GLOSSARY.md","Glossary"),
                ("appendix/decision-tree.md","Decision tree"),
                ("appendix/rfc-index.md","RFC & spec index"),
                ("SOURCES.md","Sources"),("appendix/excluded.md","Excluded")],
       "tracks":[]}
for t in "abcdefghijk":
    chs = [r for r in order if r.startswith(f"book/track-{t}/")]
    items=[]
    for r in chs:
        code = os.path.basename(r).split("-")[0]
        # short title = strip "CODE — " prefix
        ttl = titles[r]
        ttl = re.sub(r'^[A-K]\d+\s*—\s*', '', ttl)
        items.append([r, code, ttl])
    nav["tracks"].append([t.upper(), track_names[t], items])

BOOK_JSON = json.dumps(book, ensure_ascii=False).replace("</", "<\\/")
NAV_JSON = json.dumps(nav, ensure_ascii=False)
TITLES_JSON = json.dumps(titles, ensure_ascii=False)

HTML = r'''<title>Auth, from Zero to Pro</title>
<meta name="viewport" content="width=device-width, initial-scale=1">
<link rel="preconnect" href="https://fonts.googleapis.com">
<link rel="preconnect" href="https://fonts.gstatic.com" crossorigin>
<link rel="stylesheet" href="https://fonts.googleapis.com/css2?family=Archivo:wght@500;600;700;800&family=IBM+Plex+Mono:wght@400;500;600&family=IBM+Plex+Sans:wght@400;500;600&display=swap">
<script src="https://cdnjs.cloudflare.com/ajax/libs/marked/4.3.0/marked.min.js"></script>
<style>
:root{
  --ground:#f3f6f5;--surface:#ffffff;--surface-2:#eaf0ee;--sunk:#e4ebe8;
  --line:#d3ddd9;--line-soft:#e2e9e6;
  --ink:#131f1e;--ink-2:#37474a;--muted:#5c6d6b;--faint:#8b9a98;
  --accent:#0c8a80;--accent-2:#0aa398;--accent-ghost:rgba(12,138,128,.10);
  --key:#a7761c;--attack:#c0464b;
  --shadow:0 1px 2px rgba(16,32,30,.05),0 10px 30px rgba(16,32,30,.08);
  color-scheme:light;
}
@media (prefers-color-scheme:dark){:root:not([data-theme="light"]){
  --ground:#0d1316;--surface:#141c20;--surface-2:#18232a;--sunk:#0f171b;
  --line:#26343b;--line-soft:#1d282e;
  --ink:#e8f0f0;--ink-2:#b9cac9;--muted:#8ba0a1;--faint:#5f7375;
  --accent:#4fd6c9;--accent-2:#66e0d4;--accent-ghost:rgba(79,214,201,.12);
  --key:#e6b45a;--attack:#ec7a7e;
  --shadow:0 1px 2px rgba(0,0,0,.3),0 16px 44px rgba(0,0,0,.45);
  color-scheme:dark;}}
:root[data-theme="dark"]{
  --ground:#0d1316;--surface:#141c20;--surface-2:#18232a;--sunk:#0f171b;
  --line:#26343b;--line-soft:#1d282e;
  --ink:#e8f0f0;--ink-2:#b9cac9;--muted:#8ba0a1;--faint:#5f7375;
  --accent:#4fd6c9;--accent-2:#66e0d4;--accent-ghost:rgba(79,214,201,.12);
  --key:#e6b45a;--attack:#ec7a7e;
  --shadow:0 1px 2px rgba(0,0,0,.3),0 16px 44px rgba(0,0,0,.45);
  color-scheme:dark;}

*{box-sizing:border-box;margin:0}
html{scroll-behavior:smooth}
@media(prefers-reduced-motion:reduce){html{scroll-behavior:auto}}
body{background:var(--ground);color:var(--ink);font-family:"IBM Plex Sans",system-ui,sans-serif;font-size:16px;line-height:1.6;-webkit-font-smoothing:antialiased}
.mono{font-family:"IBM Plex Mono",ui-monospace,monospace}
a{color:var(--accent);text-decoration:none}
a:hover{text-decoration:underline}
::selection{background:var(--accent);color:var(--ground)}
h1,h2,h3,h4{font-family:"Archivo",system-ui,sans-serif;line-height:1.14;letter-spacing:-.02em;text-wrap:balance}

/* top bar */
.bar{position:sticky;top:0;z-index:60;height:56px;display:flex;align-items:center;gap:14px;padding:0 18px;
  background:color-mix(in srgb,var(--ground) 88%,transparent);backdrop-filter:blur(12px);border-bottom:1px solid var(--line-soft)}
.brand{display:flex;align-items:center;gap:10px;font-family:"Archivo";font-weight:800;font-size:15px;color:var(--ink);text-decoration:none}
.brand .glyph{width:25px;height:25px;border-radius:7px;background:var(--accent);color:var(--ground);display:grid;place-items:center;font-family:"IBM Plex Mono";font-weight:600;font-size:13px;flex:none}
.bar .sp{margin-left:auto}
.iconbtn{border:1px solid var(--line);background:var(--surface);color:var(--ink-2);width:34px;height:34px;border-radius:9px;cursor:pointer;font-size:15px;display:grid;place-items:center}
.iconbtn:hover{border-color:var(--accent);color:var(--accent)}
.iconbtn:focus-visible{outline:2px solid var(--accent);outline-offset:2px}
#menubtn{display:none}

/* layout */
.app{display:grid;grid-template-columns:300px 1fr;min-height:calc(100vh - 56px)}
.side{border-right:1px solid var(--line-soft);background:var(--sunk);position:sticky;top:56px;height:calc(100vh - 56px);overflow-y:auto;padding:18px 0}
.side::-webkit-scrollbar{width:9px}.side::-webkit-scrollbar-thumb{background:var(--line);border-radius:6px}
.search{margin:0 16px 14px}
.search input{width:100%;background:var(--surface);border:1px solid var(--line);border-radius:9px;padding:9px 12px;color:var(--ink);font-family:"IBM Plex Mono";font-size:12.5px}
.search input:focus{outline:none;border-color:var(--accent)}
.nav-sec{font-family:"IBM Plex Mono";font-size:10.5px;letter-spacing:.16em;text-transform:uppercase;color:var(--faint);padding:14px 20px 6px}
.nav-a{display:block;padding:6px 20px;font-size:13.5px;color:var(--ink-2);border-left:2px solid transparent}
.nav-a:hover{color:var(--accent);text-decoration:none;background:var(--accent-ghost)}
.nav-a.active{color:var(--accent);border-left-color:var(--accent);background:var(--accent-ghost);font-weight:500}
.trk{margin-top:4px}
.trk-h{display:flex;align-items:center;gap:9px;width:100%;text-align:left;background:none;border:none;cursor:pointer;padding:8px 18px;color:var(--ink);font-family:"Archivo";font-weight:700;font-size:13.5px;letter-spacing:-.01em}
.trk-h:hover{color:var(--accent)}
.trk-h .code{font-family:"IBM Plex Mono";font-weight:600;font-size:11px;color:var(--accent);background:var(--accent-ghost);padding:2px 6px;border-radius:5px;flex:none}
.trk-h .arw{margin-left:auto;color:var(--faint);font-size:10px;transition:transform .15s}
.trk.open .arw{transform:rotate(90deg)}
.trk-list{display:none;padding:2px 0 8px}
.trk.open .trk-list{display:block}
.ch{display:flex;gap:9px;padding:5px 20px 5px 30px;font-size:12.5px;color:var(--muted);border-left:2px solid transparent;align-items:baseline}
.ch:hover{color:var(--accent);text-decoration:none;background:var(--accent-ghost)}
.ch.active{color:var(--accent);border-left-color:var(--accent);background:var(--accent-ghost)}
.ch .cc{font-family:"IBM Plex Mono";font-size:10.5px;color:var(--faint);flex:none;width:26px}
.ch.active .cc{color:var(--accent)}

/* main */
.main{min-width:0}
.reader{max-width:820px;margin:0 auto;padding:44px 40px 100px}
.crumbs{font-family:"IBM Plex Mono";font-size:11.5px;color:var(--faint);letter-spacing:.04em;margin-bottom:22px;display:flex;gap:8px;flex-wrap:wrap}
.crumbs a{color:var(--muted)}

/* prose */
.prose{font-size:16.5px;line-height:1.68;color:var(--ink-2)}
.prose>*+*{margin-top:16px}
.prose h1{font-size:clamp(28px,4.4vw,40px);font-weight:800;color:var(--ink);margin:6px 0 6px;line-height:1.1}
.prose h2{font-size:23px;font-weight:700;color:var(--ink);margin-top:40px;padding-top:8px;border-top:1px solid var(--line-soft)}
.prose h3{font-size:18.5px;font-weight:700;color:var(--ink);margin-top:30px}
.prose h4{font-size:15px;font-weight:600;color:var(--ink);margin-top:22px}
.prose p{margin-top:15px}
.prose strong{color:var(--ink);font-weight:600}
.prose ul,.prose ol{margin-top:14px;padding-left:24px}
.prose li{margin-top:6px}
.prose li::marker{color:var(--accent)}
.prose blockquote{margin-top:20px;padding:4px 20px;border-left:3px solid var(--accent);background:var(--accent-ghost);border-radius:0 10px 10px 0;color:var(--ink)}
.prose blockquote p{margin-top:8px}.prose blockquote>*:first-child{margin-top:8px}
.prose code{font-family:"IBM Plex Mono";font-size:.86em;background:var(--surface-2);border:1px solid var(--line-soft);padding:1px 6px;border-radius:5px;color:var(--ink)}
.prose pre{margin-top:18px;background:var(--sunk);border:1px solid var(--line);border-radius:12px;padding:16px 18px;overflow-x:auto;line-height:1.55}
.prose pre code{background:none;border:none;padding:0;font-size:12.5px;color:var(--ink-2);white-space:pre}
.prose hr{border:none;border-top:1px solid var(--line-soft);margin:34px 0}
.prose a{font-weight:500}
.prose table{margin-top:18px;border-collapse:collapse;width:100%;font-size:14px;display:block;overflow-x:auto}
.prose th,.prose td{border:1px solid var(--line);padding:8px 12px;text-align:left;vertical-align:top}
.prose th{background:var(--surface-2);font-family:"Archivo";font-weight:600;color:var(--ink);font-size:13px}
.prose tr:nth-child(even) td{background:color-mix(in srgb,var(--surface-2) 45%,transparent)}
.prose img{max-width:100%}

/* home */
.home{max-width:1060px;margin:0 auto;padding:40px 40px 90px}
.hero{position:relative;padding:44px 0 34px}
.eyebrow{font-family:"IBM Plex Mono";font-size:12px;font-weight:500;letter-spacing:.22em;text-transform:uppercase;color:var(--accent)}
.hero h1{font-size:clamp(38px,6vw,68px);font-weight:800;letter-spacing:-.03em;margin:16px 0 0;color:var(--ink)}
.hero h1 .t{color:var(--accent)}
.hero .thesis{margin-top:22px;font-size:clamp(17px,2vw,20px);color:var(--ink-2);max-width:44ch}
.hero .thesis b{color:var(--ink);font-weight:600}
.cta{display:flex;flex-wrap:wrap;gap:12px;margin-top:28px}
.btn{display:inline-flex;align-items:center;gap:8px;font-family:"IBM Plex Mono";font-size:14px;padding:12px 20px;border-radius:11px;border:1px solid var(--line);cursor:pointer;background:var(--surface);color:var(--ink)}
.btn:hover{border-color:var(--accent);color:var(--accent);text-decoration:none;transform:translateY(-2px)}
.btn.primary{background:var(--accent);color:var(--ground);border-color:var(--accent);font-weight:600}
.btn.primary:hover{background:var(--accent-2);color:var(--ground)}
.stats{display:grid;grid-template-columns:repeat(5,1fr);gap:1px;background:var(--line-soft);border:1px solid var(--line-soft);border-radius:14px;overflow:hidden;margin-top:32px}
.stat{background:var(--surface);padding:20px}
.stat .n{font-family:"Archivo";font-weight:800;font-size:28px;letter-spacing:-.03em;color:var(--ink)}
.stat .l{font-family:"IBM Plex Mono";font-size:11px;color:var(--muted);margin-top:3px}
.home h2{font-size:26px;font-weight:700;color:var(--ink);margin:56px 0 6px}
.home .sub{color:var(--muted);margin-bottom:24px}
.grid{display:grid;grid-template-columns:repeat(auto-fill,minmax(240px,1fr));gap:14px}
.card{background:var(--surface);border:1px solid var(--line);border-radius:14px;padding:18px;cursor:pointer;position:relative;overflow:hidden;transition:transform .14s,border-color .15s,box-shadow .15s}
.card::before{content:"";position:absolute;left:0;top:0;bottom:0;width:3px;background:var(--accent);opacity:.5}
.card:hover{transform:translateY(-3px);border-color:var(--accent);box-shadow:var(--shadow)}
.card .top{display:flex;justify-content:space-between;align-items:baseline}
.card .tc{font-family:"IBM Plex Mono";font-weight:600;font-size:12.5px;color:var(--accent)}
.card .cn{font-family:"IBM Plex Mono";font-size:11px;color:var(--faint)}
.card h3{font-size:16px;font-weight:700;color:var(--ink);margin:8px 0 5px;letter-spacing:-.01em}
.card p{font-size:13px;color:var(--muted);line-height:1.45}
@media(max-width:760px){.stats{grid-template-columns:repeat(2,1fr)}}

/* mobile */
.scrim{display:none;position:fixed;inset:56px 0 0;background:rgba(0,0,0,.4);z-index:40}
@media(max-width:900px){
  #menubtn{display:grid}
  .app{grid-template-columns:1fr}
  .side{position:fixed;top:56px;left:0;width:300px;z-index:50;transform:translateX(-100%);transition:transform .2s}
  .app.nav-open .side{transform:none}
  .app.nav-open .scrim{display:block}
  .reader{padding:32px 22px 90px}.home{padding:28px 22px 80px}
}
</style>

<header class="bar">
  <button class="iconbtn" id="menubtn" aria-label="Toggle navigation">☰</button>
  <a class="brand" href="#/"><span class="glyph">01</span>Auth · Zero to Pro</a>
  <span class="sp"></span>
  <button class="iconbtn" id="themebtn" aria-label="Toggle theme" title="Toggle theme">◐</button>
</header>

<div class="app" id="app">
  <aside class="side" id="side"></aside>
  <div class="scrim" id="scrim"></div>
  <main class="main"><div id="view"></div></main>
</div>

<script>
const BOOK = __BOOK__;
const NAV = __NAV__;
const TITLES = __TITLES__;

marked.setOptions({gfm:true, headerIds:true, mangle:false});

/* ---- path helpers ---- */
function dirname(p){const i=p.lastIndexOf("/");return i<0?"":p.slice(0,i);}
function resolvePath(base, rel){
  if(/^https?:/.test(rel)) return null;         // external
  let stack = base ? base.split("/") : [];
  for(const part of rel.split("/")){
    if(part==="."||part==="") continue;
    if(part===".."){ stack.pop(); } else stack.push(part);
  }
  return stack.join("/");
}

/* ---- sidebar ---- */
function buildNav(){
  const s=document.getElementById("side");
  let h='<div class="search"><input id="q" type="search" placeholder="Filter chapters…" autocomplete="off"></div>';
  h+='<div class="nav-sec">The book</div>';
  for(const [key,label] of NAV.front){
    h+=`<a class="nav-a" data-key="${key}" href="#/${key}">${label}</a>`;
  }
  h+='<div class="nav-sec">The graph</div>';
  for(const [T,name,items] of NAV.tracks){
    h+=`<div class="trk" data-trk="${T}"><button class="trk-h"><span class="code">${T}</span><span>${name}</span><span class="arw">▶</span></button><div class="trk-list">`;
    for(const [key,code,ttl] of items){
      h+=`<a class="ch" data-key="${key}" data-search="${(code+' '+ttl).toLowerCase()}" href="#/${key}"><span class="cc">${code}</span><span>${ttl}</span></a>`;
    }
    h+=`</div></div>`;
  }
  s.innerHTML=h;
  s.querySelectorAll(".trk-h").forEach(b=>b.addEventListener("click",()=>b.parentElement.classList.toggle("open")));
  document.getElementById("q").addEventListener("input",e=>{
    const v=e.target.value.trim().toLowerCase();
    document.querySelectorAll(".trk").forEach(t=>{
      let any=false;
      t.querySelectorAll(".ch").forEach(c=>{
        const m=!v||c.dataset.search.includes(v);
        c.style.display=m?"":"none"; if(m)any=true;
      });
      t.style.display=any?"":"none";
      if(v&&any)t.classList.add("open");
    });
  });
}

/* ---- link rewriting after render ---- */
function rewriteLinks(container, baseKey){
  const base=dirname(baseKey);
  container.querySelectorAll("a[href]").forEach(a=>{
    let href=a.getAttribute("href");
    if(!href) return;
    if(/^https?:/.test(href)){ a.target="_blank"; a.rel="noopener"; return; }
    if(href.startsWith("#") && !href.startsWith("#/")){ return; } // same-page anchor
    // split off anchor
    let anchor=""; const hi=href.indexOf("#");
    if(hi>=0){ anchor=href.slice(hi+1); href=href.slice(0,hi); }
    if(!href.endsWith(".md")){ return; }
    const key=resolvePath(base, href);
    if(key && BOOK[key]!==undefined){
      a.setAttribute("href", "#/"+key+(anchor?("::"+anchor):""));
    }
  });
}

/* ---- render ---- */
function setActive(key){
  document.querySelectorAll(".nav-a,.ch").forEach(a=>a.classList.toggle("active",a.dataset.key===key));
  // open the track containing the active chapter
  const active=document.querySelector(".ch.active");
  if(active){const trk=active.closest(".trk"); if(trk&&!trk.classList.contains("open"))trk.classList.add("open");}
}
function trackTitleFor(key){
  const m=key.match(/track-([a-k])\//);
  if(!m) return "The book";
  const T=m[1].toUpperCase();
  const row=NAV.tracks.find(r=>r[0]===T);
  return row?`Track ${T} — ${row[1]}`:"The book";
}
function renderPage(key, anchor){
  const view=document.getElementById("view");
  const md=BOOK[key];
  if(md===undefined){ renderHome(); return; }
  const crumb = key==="README.md" ? "Contents" : trackTitleFor(key);
  const html='<div class="reader"><div class="crumbs"><a href="#/">Auth · Zero to Pro</a><span>›</span><span>'+crumb+'</span></div><div class="prose">'+marked.parse(md)+'</div></div>';
  view.innerHTML=html;
  rewriteLinks(view, key);
  setActive(key);
  // scroll
  if(anchor){const el=document.getElementById(anchor); if(el){el.scrollIntoView();return;}}
  window.scrollTo(0,0); document.querySelector(".main").scrollTop=0;
}

function renderHome(){
  const view=document.getElementById("view");
  const cards=NAV.tracks.map(([T,name,items])=>{
    const first=items[0][0];
    const blurbs={A:"HTTP, cookies, origins — the prerequisites every auth tutorial skips.",
      B:"Bits to certificates. Hashing, HMAC, signatures, timing attacks. Why the rest works.",
      C:"Where \"auth\" stops being one word: five separable problems.",
      D:"Proving who someone is. Passwords in 2026, TOTP, passkeys, recovery.",
      E:"Keeping someone logged in. What a JWT really is, revocation, CSRF, XSS.",
      F:"App A calling API B for a user. OAuth's flow, PKCE, and its failure modes.",
      G:"\"Sign in with Google\" and enterprise SSO. OIDC, SAML, multi-tenant.",
      H:"What a known user may do — where the breaches are. RBAC, ReBAC, IDOR.",
      I:"The half of auth that only shows up in production.",
      J:"Auth with no human. API keys, mTLS, SPIFFE, AI agents over MCP.",
      K:"Assemble every layer into one application, then review it."};
    return `<div class="card" data-key="${first}"><div class="top"><span class="tc">Track ${T}</span><span class="cn">${items.length} ch</span></div><h3>${name}</h3><p>${blurbs[T]||""}</p></div>`;
  }).join("");
  view.innerHTML=`<div class="home">
    <div class="hero">
      <span class="eyebrow">A complete curriculum · no assumed knowledge</span>
      <h1>Auth, from zero to <span class="t">pro.</span></h1>
      <p class="thesis">Authentication &amp; authorization written the way the subject works: <b>a dependency graph, not a playlist</b> — from what a byte is to authenticating AI agents.</p>
      <div class="cta">
        <button class="btn primary" data-key="README.md">Table of contents →</button>
        <button class="btn" data-key="book/track-e/E05-jwt-part-1-three-parts.md">Start: what a JWT is</button>
        <button class="btn" data-key="appendix/decision-tree.md">What should I use?</button>
      </div>
      <div class="stats">
        <div class="stat"><div class="n">140</div><div class="l">chapters</div></div>
        <div class="stat"><div class="n">11</div><div class="l">tracks</div></div>
        <div class="stat"><div class="n">5</div><div class="l">problems</div></div>
        <div class="stat"><div class="n">496</div><div class="l">glossary terms</div></div>
        <div class="stat"><div class="n">1</div><div class="l">running app</div></div>
      </div>
    </div>
    <h2>The eleven tracks</h2>
    <p class="sub">Built bottom-up. Each chapter declares what it needs — enter where you are.</p>
    <div class="grid">${cards}</div>
  </div>`;
  view.querySelectorAll("[data-key]").forEach(el=>el.addEventListener("click",()=>{location.hash="#/"+el.dataset.key;}));
  setActive(null);
  window.scrollTo(0,0);
}

/* ---- routing ---- */
function route(){
  const h=location.hash.replace(/^#\//,"");
  closeNav();
  if(!h||h==="#/"||location.hash===""||location.hash==="#/"){ renderHome(); setActive(null); return; }
  let key=h, anchor="";
  const ci=h.indexOf("::"); if(ci>=0){anchor=h.slice(ci+2);key=h.slice(0,ci);}
  key=decodeURIComponent(key);
  if(BOOK[key]!==undefined) renderPage(key, anchor);
  else renderHome();
}
window.addEventListener("hashchange",route);

/* ---- theme + nav ---- */
const root=document.documentElement;
function setTheme(t){t?root.setAttribute("data-theme",t):root.removeAttribute("data-theme");}
try{const s=localStorage.getItem("auth-book-theme");if(s)setTheme(s);}catch(e){}
document.getElementById("themebtn").addEventListener("click",()=>{
  const cur=root.getAttribute("data-theme");
  const sys=matchMedia&&matchMedia("(prefers-color-scheme:dark)").matches;
  const next=(cur||(sys?"dark":"light"))==="dark"?"light":"dark";
  setTheme(next);try{localStorage.setItem("auth-book-theme",next);}catch(e){}
});
const app=document.getElementById("app");
function closeNav(){app.classList.remove("nav-open");}
document.getElementById("menubtn").addEventListener("click",()=>app.classList.toggle("nav-open"));
document.getElementById("scrim").addEventListener("click",closeNav);

buildNav();
route();
</script>
'''

HTML = (HTML.replace("__BOOK__", BOOK_JSON)
            .replace("__NAV__", NAV_JSON)
            .replace("__TITLES__", TITLES_JSON))

out = os.path.join(ROOT, "index.html")
with open(out, "w") as fh:
    fh.write(HTML)
print("wrote", out, len(HTML), "bytes")
