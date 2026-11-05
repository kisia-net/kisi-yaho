"""Bounded mTLS transport. Application inputs travel only in VQL env."""
import json
import os
import re
from urllib.parse import urlsplit

import grpc
import pyvelociraptor
from pyvelociraptor import api_pb2, api_pb2_grpc


class RemoteError(RuntimeError):
    def __init__(self, code="query_failed"):
        self.code = code
        super().__init__(code)


class Transport:
    def __init__(self, config_path=None):
        self.config_path = config_path or os.getenv("VELOCIRAPTOR_API_CONFIG", "")

    def query(self, vql, env=None, *, max_rows=1000, timeout=20, max_bytes=8 * 1048576):
        if not self.config_path:
            raise RemoteError("not_configured")
        try:
            config = pyvelociraptor.LoadConfigFile(self.config_path)
            target = str(config["api_connection_string"])
            if "://" in target:
                target = urlsplit(target).netloc
            credentials = grpc.ssl_channel_credentials(
                root_certificates=config["ca_certificate"].encode(),
                private_key=config["client_private_key"].encode(),
                certificate_chain=config["client_cert"].encode(),
            )
            args = api_pb2.VQLCollectorArgs(
                org_id=str(config.get("org_id", "")), timeout=timeout,
                max_wait=1, max_row=100,
                env=[api_pb2.VQLEnv(key=k, value=json.dumps(v, ensure_ascii=False)) for k, v in (env or {}).items()],
                Query=[api_pb2.VQLRequest(Name="HAWKIWorkspace", VQL=vql)],
            )
            options = [("grpc.ssl_target_name_override", config.get("pinned_server_name") or "VelociraptorServer"), ("grpc.max_receive_message_length", max_bytes)]
            rows, size = [], 0
            with grpc.secure_channel(target, credentials, options=options) as channel:
                stream = api_pb2_grpc.APIStub(channel).Query(args, timeout=timeout + 3)
                try:
                    for response in stream:
                        if response.log and re.search(r"(?i)(\berror\b|permission denied|not allowed|symbol .+ not found|panic)", response.log):
                            raise RemoteError("query_rejected")
                        if not response.Response:
                            continue
                        size += len(response.Response.encode())
                        if size > max_bytes:
                            raise RemoteError("result_too_large")
                        block = json.loads(response.Response)
                        if not isinstance(block, list) or any(not isinstance(x, dict) for x in block):
                            raise RemoteError("invalid_response")
                        rows.extend(block)
                        if len(rows) > max_rows:
                            raise RemoteError("result_too_large")
                finally:
                    stream.cancel()
            return rows
        except RemoteError:
            raise
        except grpc.RpcError as exc:
            code = "permission_denied" if exc.code() == grpc.StatusCode.PERMISSION_DENIED else "timeout" if exc.code() == grpc.StatusCode.DEADLINE_EXCEEDED else "connection_failed"
            raise RemoteError(code) from exc
        except Exception as exc:
            raise RemoteError("connection_failed") from exc


PREFIX = "LET P <= parse_json(data=Payload)\n"


def run(transport, query, values=None, **kw):
    return transport.query(PREFIX + query, {"Payload": values or {}}, **kw)
