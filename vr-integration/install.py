#!/usr/bin/env python3
"""Scoped installer for /opt/hawki. Does not launch endpoint collections."""
import argparse
import ast
import copy
import json
import os
import re
import subprocess
import tempfile
from pathlib import Path

PACKAGE=Path(__file__).resolve().parent
VERSION="2026.10.06.1"
BEGIN="# BEGIN HAWKI VELOCIRAPTOR WORKSPACE"
END="# END HAWKI VELOCIRAPTOR WORKSPACE"


def patch_app(text):
    tree=ast.parse(text)
    names={n.name for n in tree.body if isinstance(n,(ast.FunctionDef,ast.AsyncFunctionDef))}
    if not {"role_required","append_audit","load_account_and_protect_routes","hunts_page","response_page"}<=names:
        raise RuntimeError("Current app.py does not have the expected integration points")
    text=re.sub(re.escape(BEGIN)+r".*?"+re.escape(END)+r"\n?","",text,flags=re.S)
    code=BEGIN+"\nfrom hawki_vr.web import install as _install_vr_workspace\n_install_vr_workspace(app, role_required, append_audit)\n"+END+"\n\n"
    tree=ast.parse(text)
    positions=[n.lineno for n in tree.body if isinstance(n,ast.If) and "__name__" in ast.unparse(n.test) and "__main__" in ast.unparse(n.test)]
    lines=text.splitlines(keepends=True)
    at=min(positions)-1 if positions else len(lines)
    lines.insert(at,"\n"+code)
    result="".join(lines);ast.parse(result)
    return result


def patch_base(text):
    # The old app.js has multiple legacy DOM repair handlers. These two pages
    # now load one page controller; other pages retain the existing controller.
    marker="<!-- HAWKI VR ASSETS -->"
    if marker not in text:
        needle="</head>"
        if text.count(needle)!=1: raise RuntimeError("Unexpected base template head")
        text=text.replace(needle,marker+"\n{% if active_page in ['hunts', 'response'] %}\n<link rel=\"stylesheet\" href=\"{{ url_for('static', filename='vr-workspace.css', v=asset_version) }}\">\n{% endif %}\n"+needle)
        script='<script src="{{ url_for(\'static\', filename=\'app.js\', v=asset_version) }}"></script>'
        if text.count(script)!=1: raise RuntimeError("Expected one shared app.js asset")
        text=text.replace(script,"{% if active_page in ['hunts', 'response'] %}\n<script type=\"module\" src=\"{{ url_for('static', filename='vr-workspace.js', v=asset_version) }}\"></script>\n{% else %}\n"+script+"\n{% endif %}")
    # Only the two replaced screens lose the obsolete pilot badge.
    text=re.sub(r'(<a\b[^>]*href="/(?:hunts|response)"[^>]*>.*?)\s*<small class="nav-badge">시범</small>',r'\1',text,flags=re.S)
    return text


def patch_compose(doc,root):
    doc=copy.deepcopy(doc)
    web=doc["services"]["hawki-web"]
    if "build" not in web: raise RuntimeError("hawki-web must build the local Dockerfile")
    if not isinstance(web.get("environment",{}),dict): raise RuntimeError("Expected mapping environment")
    data=[]
    for volume in web.get("volumes",[]):
        if isinstance(volume,str):
            parts=volume.split(":")
            if len(parts)>=2 and parts[1]=="/app/data":data.append(volume)
        elif isinstance(volume,dict) and volume.get("target")=="/app/data":data.append(volume)
    if len(data)!=1: raise RuntimeError("Expected one persistent /app/data mount")
    web["image"]="hawki-vr-workspace:"+VERSION
    web.setdefault("environment",{})["HAWKI_VR_DB"]="/app/data/velociraptor/workspace.sqlite3"
    worker=dict(image=web["image"],restart="unless-stopped",command=["python","-m","hawki_vr.worker"],
                environment={"HAWKI_VR_DB":"/app/data/velociraptor/workspace.sqlite3","VELOCIRAPTOR_EXEC_API_CONFIG":"/run/vr-execution/api.yaml","PYTHONDONTWRITEBYTECODE":"1","PYTHONUNBUFFERED":"1"},
                volumes=data+[dict(type="bind",source=str(root/"secrets/velociraptor-execution"),target="/run/vr-execution",read_only=True)],
                healthcheck={"test":["CMD","python","-c","from hawki_vr.store import Store; import sys; sys.exit(0 if Store().health()['ready'] else 1)"],"interval":"30s","timeout":"5s","retries":3},
                read_only=True,tmpfs=["/tmp"],cap_drop=["ALL"],security_opt=["no-new-privileges:true"],mem_limit="384m",cpus=0.5)
    for key in ("networks","network_mode","extra_hosts","dns"):
        if key in web:worker[key]=copy.deepcopy(web[key])
    existing=doc["services"].get("vr-dispatcher")
    if existing and existing.get("command")!=["python","-m","hawki_vr.worker"]:
        raise RuntimeError("vr-dispatcher service name is already used")
    doc["services"]["vr-dispatcher"]=worker
    return doc


def yaml_parse(text,compose):
    try:
        import yaml
        return yaml.safe_load(text)
    except ImportError:
        command=compose+["exec","-T","hawki-web","python","-c","import sys,yaml,json; print(json.dumps(yaml.safe_load(sys.stdin.read())))"]
        p=subprocess.run(command,input=text,text=True,capture_output=True,check=True)
        return json.loads(p.stdout)


def atomic(path,content,mode=0o644):
    path.parent.mkdir(parents=True,exist_ok=True)
    fd,name=tempfile.mkstemp(prefix=".vr-install-",dir=path.parent)
    try:
        os.fchmod(fd,mode)
        with os.fdopen(fd,"wb") as f:f.write(content)
        os.replace(name,path)
    finally:
        if os.path.exists(name):os.unlink(name)


def main():
    p=argparse.ArgumentParser()
    p.add_argument("--root",type=Path,default=Path("/opt/hawki"))
    p.add_argument("--apply",action="store_true")
    p.add_argument("--no-start",action="store_true")
    args=p.parse_args();root=args.root.resolve()
    if root!=Path("/opt/hawki"):raise SystemExit("This installer is scoped to /opt/hawki")
    if os.geteuid()!=0:raise SystemExit("Run this installer with sudo")
    compose=["docker","compose","-f",str(root/"compose.yaml")]
    for name in ("app.py","Dockerfile","compose.yaml","templates/base.html","static/app.js"):
        if not (root/name).is_file():raise SystemExit("Missing required file: "+name)
    old_compose=(root/"compose.yaml").read_text()
    document=yaml_parse(old_compose,compose)
    updated=patch_compose(document,root)
    proposed={root/"app.py":patch_app((root/"app.py").read_text()).encode(),root/"templates/base.html":patch_base((root/"templates/base.html").read_text()).encode()}
    docker=(root/"Dockerfile").read_text()
    if "COPY hawki_vr /app/hawki_vr" not in docker:
        if docker.count("USER hawki")!=1:raise SystemExit("Unexpected Dockerfile user declaration")
        docker=docker.replace("USER hawki","COPY hawki_vr /app/hawki_vr\nUSER hawki")
    proposed[root/"Dockerfile"]=docker.encode()
    # JSON is valid Compose/YAML, preserves literal environment interpolation and
    # avoids requiring PyYAML on the host. Existing service values are retained.
    proposed[root/"compose.yaml"]=(json.dumps(updated,ensure_ascii=False,indent=2)+"\n").encode()
    for folder in ("hawki_vr","templates","static"):
        for source in sorted((PACKAGE/folder).rglob("*")):
            if source.is_file() and source.suffix in {".py",".html",".css",".js"}:
                proposed[root/source.relative_to(PACKAGE)]=source.read_bytes()
    actions=root/"templates/actions.html"
    if actions.exists():
        text=actions.read_text()
        if "HAWKI VR APPROVAL LINK" not in text:
            anchor="{% block content %}"
            if text.count(anchor)!=1:raise SystemExit("Unexpected actions template")
            text=text.replace(anchor,anchor+'\n<!-- HAWKI VR APPROVAL LINK -->\n<p><a class="button secondary" href="/response?tab=jobs">Velociraptor 수집 요청</a></p>')
            proposed[actions]=text.encode()
    print("Files to update:")
    for path in proposed:print(" "+str(path.relative_to(root)))
    print("Services: hawki-web, vr-dispatcher. No endpoint collections are started.")
    if not args.apply:return
    originals={path:(path.read_bytes(),path.stat().st_mode&0o777) if path.exists() else None for path in proposed}
    secret_dir=root/"secrets/velociraptor-execution"
    secret_dir.mkdir(parents=True,exist_ok=True)
    os.chown(secret_dir,0,999);os.chmod(secret_dir,0o750)
    try:
        for path,data in proposed.items():atomic(path,data,originals[path][1] if originals[path] else 0o644)
        subprocess.run(compose+["config","--quiet"],check=True)
        subprocess.run(compose+["build","hawki-web"],check=True)
        subprocess.run(compose+["run","--rm","--no-deps","-T","--entrypoint","python","hawki-web","-m","hawki_vr.preflight"],check=True)
    except Exception:
        for path,old in originals.items():
            if old:atomic(path,*old)
            elif path.exists():path.unlink()
        raise SystemExit("Preflight failed; source files restored. Running services were not changed.")
    if not args.no_start:
        subprocess.run(compose+["up","-d","--no-deps","hawki-web","vr-dispatcher"],check=True)
        subprocess.run(compose+["ps","hawki-web","vr-dispatcher"],check=True)
    print("Workspace installed. Install the execution API credential to enable collection.")


if __name__=="__main__":main()
