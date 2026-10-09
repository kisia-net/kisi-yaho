"""Local browser-test server only. Never copied by the deployment installer."""
import json
import tempfile
from pathlib import Path
from flask import Flask,render_template,request,g,jsonify
from jinja2 import ChoiceLoader,DictLoader,FileSystemLoader
from test_backend import FakeAPI,C1,C2
from hawki_vr.store import Store
from hawki_vr.web import install
from install import patch_base

ROOT=Path(__file__).resolve().parents[1]
app=Flask(__name__,static_folder=str(ROOT/"static"));app.secret_key="browser-test-only"
app.jinja_loader=ChoiceLoader([DictLoader({"base.html":patch_base((ROOT/"tests/fixtures/base.html").read_text())}),FileSystemLoader(str(ROOT/"templates"))])
app.jinja_env.globals["csrf_token"]=lambda:"browser-token"
temp=tempfile.TemporaryDirectory();store=Store(Path(temp.name)/"db.sqlite3");store.beat(True)
api=FakeAPI()
api.flows["F.BROWSER"]=dict(flow_id="F.BROWSER",client_id=C1,state="FINISHED",create_time=1791265500000000,start_time=1791265500000000,total_collected_rows=2,request={"artifacts":["Linux.Search.FileFinder"]},artifacts_with_results=["Linux.Search.FileFinder"])
api.rows["F.BROWSER"]=[dict(OSPath='/tmp/<img src=x onerror="window.injection=1">',Size=512,MTime="2026-10-06T03:00:00Z",CTime="2026-10-06T03:10:00Z",Mode="-rw-r--r--",Hash={"SHA256":"a"*64}),dict(OSPath="/tmp/second-file",Size=256,MTime="2026-10-06T02:00:00Z",CTime="2026-10-06T02:00:00Z",Mode="-rw-------")]

@app.before_request
def auth():
    store.beat(True)
    g.user={"id":2,"username":"test-analyst","role":"approver"}
    if request.method=="POST" and request.headers.get("X-CSRF-Token")!="browser-token":return jsonify(error="CSRF"),400

install(app,lambda role:lambda fn:fn,lambda *a:None,transport=api,store=store)

@app.get("/api/status")
def status():return jsonify(services={"velociraptor":{"ok":True,"configured":True}})

@app.get("/hunts")
@app.get("/response")
def page():
    name=request.path.lstrip("/")
    return render_template(name+".html",active_page=name,page_title="파일 추적" if name=="hunts" else "호스트 대응",asset_version="test",velociraptor_url="/velociraptor/app/index.html",vendor_scripts=[],build_id="test")

@app.get("/static/style.css")
def base_css():
    return """:root{--bg:#091322;--sidebar:#101e33;--panel:#111f33;--panel-2:#15253b;--text:#e4edf7;--muted:#8fa5be;--line:#2a3c55;--accent:#51d3b0;--accent-soft:#173b40;--input-bg:#0c192b;--blue:#67b5ff;--danger:#fb7185;--success:#51d3b0;--warning:#fbbf24;--code-bg:#091522;--on-accent:#032b21}body{margin:0;background:var(--bg);color:var(--text);font-family:Arial,sans-serif}.app-shell{display:grid;grid-template-columns:220px minmax(0,1fr);min-height:100vh}.sidebar{background:var(--sidebar);padding:24px 16px}.sidebar a{color:var(--text);text-decoration:none;display:block;font-size:13px;padding:10px 0}.nav-group-label,.sidebar-label{color:var(--muted);font-size:11px;margin-top:24px}.nav-item.active{color:var(--accent)}.brand strong{font-size:21px}.brand small{display:block;color:var(--muted);font-size:10px}.brand-mark{display:none}.nav-item span{margin-right:8px}.nav-group-label{margin-bottom:5px}.service-link{font-size:12px}.sidebar-footer{margin-top:40px;color:var(--muted);font-size:11px}.sidebar-footer small{display:block}.main-content{min-width:0}.workspace-content{padding:24px}.topbar{display:flex;justify-content:space-between;align-items:center;padding:20px 26px;border-bottom:1px solid var(--line)}.topbar h1{font-size:22px;margin:0}.topbar-actions{display:flex;gap:10px;align-items:center}.topbar-actions svg{width:16px;height:16px}.theme-icon-moon{display:none}.global-health{font-size:11px;color:var(--muted)}.topbar-icon-button{color:var(--muted);border:0;background:none}.sr-only{display:none}@media(max-width:900px){.sidebar{display:none}.app-shell{grid-template-columns:1fr}.workspace-content{padding:12px}.topbar-actions{display:none}}""",200,{"Content-Type":"text/css"}

@app.get("/static/theme-init.js")
def theme():return "document.documentElement.dataset.theme='dark';",200,{"Content-Type":"text/javascript"}

@app.get("/static/fonts/pretendard-1.3.9/pretendard.css")
def font():return "",200,{"Content-Type":"text/css"}

if __name__=="__main__":app.run(host="127.0.0.1",port=18765,debug=False)
