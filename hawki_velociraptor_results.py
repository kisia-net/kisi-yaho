"""Bounded, read-only Velociraptor flow-result access for HAW-KI."""

from __future__ import annotations

import json
import os
import re
from urllib.parse import urlsplit

import grpc
import pyvelociraptor
from pyvelociraptor import api_pb2
from pyvelociraptor import api_pb2_grpc

_ALLOWED_ID = re.compile(r"^[A-Za-z0-9][A-Za-z0-9._-]{0,159}$")
_ALLOWED_ARTIFACT = re.compile(r"^[A-Za-z0-9][A-Za-z0-9._/-]{0,299}$")
_MAX_LIMIT = 50


class ReadError(RuntimeError):
    """A safe read-only Velociraptor access failure."""


def _value(name: str) -> str:
    value = os.getenv(name, "").strip()
    if not value:
        raise ReadError(f"missing_{name.lower()}")
    return value


def _checked(value: str, pattern: re.Pattern[str], name: str) -> str:
    if not isinstance(value, str) or not pattern.fullmatch(value):
        raise ValueError(f"invalid_{name}")
    return value


def _config():
    try:
        return pyvelociraptor.LoadConfigFile(_value("VELOCIRAPTOR_API_CONFIG"))
    except Exception as exc:
        raise ReadError("config_load_failed") from exc


def _query(query: str, limit: int) -> list[dict]:
    config = _config()
    connection = str(config["api_connection_string"])
    if "://" in connection:
        connection = urlsplit(connection).netloc

    try:
        credentials = grpc.ssl_channel_credentials(
            root_certificates=str(config["ca_certificate"]).encode("utf-8"),
            private_key=str(config["client_private_key"]).encode("utf-8"),
            certificate_chain=str(config["client_cert"]).encode("utf-8"),
        )

        request = api_pb2.VQLCollectorArgs(
            org_id=str(config.get("org_id", "")),
            max_wait=1,
            max_row=limit,
            Query=[
                api_pb2.VQLRequest(
                    Name="HAWKIFlowResults",
                    VQL=query,
                )
            ],
        )

        rows: list[dict] = []
        options = (
            (
                "grpc.ssl_target_name_override",
                str(config.get("pinned_server_name", "VelociraptorServer")),
            ),
        )

        with grpc.secure_channel(
            connection,
            credentials,
            options=options,
        ) as channel:
            stub = api_pb2_grpc.APIStub(channel)
            for response in stub.Query(request):
                if not response.Response:
                    continue
                payload = json.loads(response.Response)
                if isinstance(payload, list):
                    rows.extend(
                        item for item in payload if isinstance(item, dict)
                    )
                elif isinstance(payload, dict):
                    rows.append(payload)
                if len(rows) >= limit:
                    break

        return rows[:limit]
    except ReadError:
        raise
    except Exception as exc:
        raise ReadError("query_failed") from exc


def read_flow_results(
    client_id: str,
    flow_id: str,
    artifact: str,
    limit: int = 50,
) -> dict:
    client_id = _checked(client_id, _ALLOWED_ID, "client_id")
    flow_id = _checked(flow_id, _ALLOWED_ID, "flow_id")
    artifact = _checked(artifact, _ALLOWED_ARTIFACT, "artifact")

    limit = max(1, min(int(limit), _MAX_LIMIT))

    query = (
        "SELECT * FROM flow_results("
        f"client_id={json.dumps(client_id)},"
        f"flow_id={json.dumps(flow_id)},"
        f"artifact={json.dumps(artifact)}"
        f") LIMIT {limit}"
    )

    rows = _query(query, limit)
    return {
        "status": "ok",
        "client_id": client_id,
        "flow_id": flow_id,
        "artifact": artifact,
        "returned_rows": len(rows),
        "limit": limit,
        "rows": rows,
    }
