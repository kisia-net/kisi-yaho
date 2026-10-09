import ast
from pathlib import Path
import sys

from flask import Flask, render_template

sys.path.insert(0,str(Path(__file__).resolve().parents[1]))
from install import patch_app, patch_base, patch_compose


def test_installer_registers_once_and_keeps_other_routes():
    source="app=None\n"+"\n".join(f"def {n}(): pass" for n in ("role_required","append_audit","load_account_and_protect_routes","hunts_page","response_page"))+"\nif __name__ == '__main__':\n app.run()\n"
    updated=patch_app(source)
    assert patch_app(updated).count("_install_vr_workspace(app")==1
    ast.parse(updated)


def test_compose_key_is_worker_only_and_other_services_untouched():
    doc=dict(services={"hawki-web":{"build":".","environment":{"LLM_API_KEY":"${LLM_API_KEY}"},"volumes":["hawki-data:/app/data","./data/assets:/app/data/assets:ro"]},"other":{"image":"other"}},volumes={"hawki-data":{}})
    changed=patch_compose(doc,Path("/opt/hawki"))
    assert changed["services"]["other"]==doc["services"]["other"]
    assert "VELOCIRAPTOR_EXEC_API_CONFIG" not in changed["services"]["hawki-web"]["environment"]
    assert len(changed["services"]["vr-dispatcher"]["volumes"])==2
    assert changed["services"]["hawki-web"]["environment"]["LLM_API_KEY"]=="${LLM_API_KEY}"
    assert "ENABLE_RESPONSE_ACTIONS" not in changed["services"]["hawki-web"]["environment"]
    assert changed==patch_compose(changed,Path("/opt/hawki"))


def test_replacement_templates_no_legacy_controller_or_agent_forms(tmp_path):
    root=Path(__file__).resolve().parents[1]
    base=(root/"tests/fixtures/base.html").read_text()
    updated=patch_base(base);assert patch_base(updated)==updated
    templates=tmp_path/"templates";templates.mkdir()
    (templates/"base.html").write_text(updated)
    for name in ("hunts.html","response.html","vr_workspace.html"):(templates/name).write_text((root/"templates"/name).read_text())
    app=Flask(__name__,template_folder=str(templates))
    app.jinja_env.globals["csrf_token"]=lambda:"test-token"
    with app.test_request_context("/"):
        for name,mode in (("hunts","files"),("response","host")):
            html=render_template(name+".html",active_page=name,velociraptor_url="/velociraptor/app/index.html",vendor_scripts=[],asset_version="test")
            assert f'data-mode="{mode}"' in html
            assert 'src="/static/app.js' not in html
            assert 'vr-workspace.js' in html and 'vr-workspace.css' in html
            assert "-agent-form" not in html and "에이전트에서" not in html
            assert "임의의 VQL" not in html and "ENABLE_RESPONSE_ACTIONS" not in html
