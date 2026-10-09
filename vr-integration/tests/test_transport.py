import json
from types import SimpleNamespace
import pytest
from hawki_vr.transport import Transport, RemoteError, run


class Channel:
    def __enter__(self):return self
    def __exit__(self,*args):return False


class Stream:
    def __init__(self,blocks):self.blocks=blocks;self.cancelled=False
    def __iter__(self):return iter(self.blocks)
    def cancel(self):self.cancelled=True


def setup(monkeypatch,blocks):
    import hawki_vr.transport as m
    captured={};stream=Stream(blocks)
    monkeypatch.setattr(m.pyvelociraptor,"LoadConfigFile",lambda p:dict(api_connection_string="test:8001",ca_certificate="CA",client_private_key="PRIVATE",client_cert="CERT"))
    monkeypatch.setattr(m.grpc,"ssl_channel_credentials",lambda **kw:object())
    monkeypatch.setattr(m.grpc,"secure_channel",lambda *a,**kw:Channel())
    class Stub:
        def __init__(self,*a):pass
        def Query(self,request,timeout):captured.update(request=request,timeout=timeout);return stream
    monkeypatch.setattr(m.api_pb2_grpc,"APIStub",Stub)
    return Transport("test-only"),captured,stream


def test_actual_protobuf_environment_deadline_and_stream_closure(monkeypatch):
    t,c,s=setup(monkeypatch,[SimpleNamespace(Response='[{"ok":1}]',log="")])
    payload={"path":"/tmp/' OR x", "rule":"rule x { condition: false }"}
    rows=run(t,"SELECT 1 AS ok FROM scope()",payload,max_rows=1)
    assert rows==[{"ok":1}]
    assert json.loads(c["request"].env[0].value)==payload
    assert payload["path"] not in c["request"].Query[0].VQL
    assert c["timeout"]==23 and s.cancelled


def test_server_error_log_cannot_look_like_empty_success(monkeypatch):
    t,_,s=setup(monkeypatch,[SimpleNamespace(Response="",log="ERROR: User is not allowed to launch flows")])
    with pytest.raises(RemoteError,match="query_rejected"):run(t,"SELECT 1 FROM scope()")
    assert s.cancelled


def test_client_enforces_total_response_cap_not_grpc_batch_size(monkeypatch):
    t,_,s=setup(monkeypatch,[SimpleNamespace(Response='[{"a":1},{"a":2}]',log="")])
    with pytest.raises(RemoteError,match="result_too_large"):run(t,"SELECT 1 FROM scope()",max_rows=1)
    assert s.cancelled
