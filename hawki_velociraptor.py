"""Bounded, fixed-query Velociraptor reader."""
import json
import os
import re
import time
from datetime import datetime, timezone
from pathlib import Path

LIMIT = 20
QUERY = """
LET registered <=
 SELECT client_id, os_info.hostname AS hostname, last_seen_at
 FROM clients() LIMIT 20
SELECT whoami() AS identity, 1 AS api_ok,
 len(list=registered) AS returned_clients,
 registered AS clients
FROM scope()
"""

class ReadError(Exception):
    def __init__(self, kind):
        self.kind = kind
        super().__init__(kind)

def read_inventory():
    path = os.getenv("VELOCIRAPTOR_API_CONFIG", "").strip()
    if not path:
        raise ReadError("not_configured")

    try:
        import grpc
        import yaml
        from pyvelociraptor import api_pb2, api_pb2_grpc
    except ImportError:
        raise ReadError("missing_dependency") from None

    try:
        raw = Path(path).read_bytes()
        if len(raw) > 1_000_000:
            raise ValueError()
        config = yaml.safe_load(raw)
        required = (
            "api_connection_string", "ca_certificate",
            "client_private_key", "client_cert", "name",
        )
        if not isinstance(config, dict) or not all(
            isinstance(config.get(key), str) and config[key].strip()
            for key in required
        ):
            raise ValueError()
        credentials = grpc.ssl_channel_credentials(
            root_certificates=config["ca_certificate"].encode(),
            private_key=config["client_private_key"].encode(),
            certificate_chain=config["client_cert"].encode(),
        )
        server_name = (
            config.get("pinned_server_name") or "VelociraptorServer"
        )
        if not isinstance(server_name, str):
            raise ValueError()
    except (OSError, ValueError, TypeError, yaml.YAMLError):
        raise ReadError("credential_configuration") from None

    rows = []
    try:
        with grpc.secure_channel(
            config["api_connection_string"],
            credentials,
            options=(
                ("grpc.ssl_target_name_override", server_name),
                ("grpc.max_receive_message_length", 2 * 1024 * 1024),
            ),
        ) as channel:
            request = api_pb2.VQLCollectorArgs(
                org_id=config.get("org_id") or "",
                max_wait=1,
                max_row=LIMIT,
                timeout=5,
                Query=[api_pb2.VQLRequest(
                    Name="HAWKI.ReadOnlyInventory", VQL=QUERY
                )],
            )
            for message in api_pb2_grpc.APIStub(channel).Query(
                request, timeout=6
            ):
                if message.log and re.search(
                    r"\berror\b|\bdenied\b|\bunauthorized\b",
                    message.log, re.I,
                ):
                    raise ReadError("query_rejected")
                if message.Response:
                    if len(message.Response) > 100_000:
                        raise ReadError("response_limit")
                    part = json.loads(message.Response)
                    if not isinstance(part, list):
                        raise ReadError("invalid_response")
                    rows.extend(part)
                    if len(rows) > 1:
                        raise ReadError("invalid_response")
    except grpc.RpcError as exc:
        raise ReadError("grpc_" + exc.code().name.lower()) from None
    except (ValueError, TypeError):
        raise ReadError("invalid_response") from None

    if len(rows) != 1 or not isinstance(rows[0], dict):
        raise ReadError("invalid_response")
    result = rows[0]
    clients = result.get("clients")
    if (
        result.get("identity") != config["name"]
        or result.get("api_ok") != 1
        or not isinstance(clients, list)
        or len(clients) > LIMIT
        or result.get("returned_clients") != len(clients)
        or not all(isinstance(client, dict) for client in clients)
    ):
        raise ReadError("invalid_response")

    return {
        **result,
        "checked_at": datetime.now(timezone.utc).isoformat(),
        "inventory_limit": LIMIT,
    }

def check_service():
    started = time.perf_counter()
    result = {
        "ok": False,
        "configured": bool(
            os.getenv("VELOCIRAPTOR_API_CONFIG", "").strip()
        ),
        "protocol": "grpc_mtls",
        "status_code": None,
    }
    try:
        inventory = read_inventory()
        result.update(
            ok=True,
            identity=inventory["identity"],
            returned_clients=inventory["returned_clients"],
            inventory_limit=LIMIT,
        )
    except ReadError as exc:
        result.update(
            error_kind=exc.kind,
            error="Velociraptor API check failed: " + exc.kind,
        )
    except Exception:
        result.update(
            error_kind="internal",
            error="Velociraptor API check failed: internal",
        )
    result["latency_ms"] = round(
        (time.perf_counter() - started) * 1000
    )
    return "velociraptor", result


def read_clients(query=""):
    if not isinstance(query, str) or len(query) > 500:
        raise ValueError("Query must be a string of at most 500 characters.")
    inventory = read_inventory()
    needle = query.strip().casefold()
    clients = inventory["clients"]
    matches = [
        client for client in clients
        if not needle or any(
            needle in str(client.get(key, "")).casefold()
            for key in ("client_id", "hostname")
        )
    ]
    matches = [dict(client) for client in matches]
    for client in matches:
        value = client.get("last_seen_at")
        client["last_seen_at_iso"] = None
        if isinstance(value, (int, float)) and not isinstance(value, bool):
            try:
                client["last_seen_at_iso"] = datetime.fromtimestamp(
                    value / 1_000_000, timezone.utc
                ).isoformat()
            except (ValueError, OverflowError, OSError):
                pass
    return {
        "status": "success",
        "source": "velociraptor_api",
        "checked_at": inventory["checked_at"],
        "identity": inventory["identity"],
        "query": query,
        "retrieved_clients": len(clients),
        "inventory_cap_reached": len(clients) >= LIMIT,
        "matching_records": len(matches),
        "inventory_limit": inventory["inventory_limit"],
        "last_seen_unit": "microseconds_since_unix_epoch",
        "items": matches,
        "coverage": (
            "At most 20 registered clients were retrieved. Filtering applies "
            "only to that bounded inventory. Counts are not server totals; "
            "last_seen_at is a recorded check-in, not proof of current availability. "
            "This query does not retrieve collection results or schedule actions."
        ),
    }

_HUNT_QUERY = """
LET registered <=
 SELECT hunt_id, hunt_description, state,
        start_request.artifacts AS artifacts
 FROM hunts() LIMIT 20
SELECT whoami() AS identity, 1 AS api_ok,
 len(list=registered) AS returned_clients,
 registered AS clients
FROM scope()
"""

def _read_hunt_inventory():
    path = os.getenv("VELOCIRAPTOR_API_CONFIG", "").strip()
    if not path:
        raise ReadError("not_configured")

    try:
        import grpc
        import yaml
        from pyvelociraptor import api_pb2, api_pb2_grpc
    except ImportError:
        raise ReadError("missing_dependency") from None

    try:
        raw = Path(path).read_bytes()
        if len(raw) > 1_000_000:
            raise ValueError()
        config = yaml.safe_load(raw)
        required = (
            "api_connection_string", "ca_certificate",
            "client_private_key", "client_cert", "name",
        )
        if not isinstance(config, dict) or not all(
            isinstance(config.get(key), str) and config[key].strip()
            for key in required
        ):
            raise ValueError()
        credentials = grpc.ssl_channel_credentials(
            root_certificates=config["ca_certificate"].encode(),
            private_key=config["client_private_key"].encode(),
            certificate_chain=config["client_cert"].encode(),
        )
        server_name = (
            config.get("pinned_server_name") or "VelociraptorServer"
        )
        if not isinstance(server_name, str):
            raise ValueError()
    except (OSError, ValueError, TypeError, yaml.YAMLError):
        raise ReadError("credential_configuration") from None

    rows = []
    try:
        with grpc.secure_channel(
            config["api_connection_string"],
            credentials,
            options=(
                ("grpc.ssl_target_name_override", server_name),
                ("grpc.max_receive_message_length", 2 * 1024 * 1024),
            ),
        ) as channel:
            request = api_pb2.VQLCollectorArgs(
                org_id=config.get("org_id") or "",
                max_wait=1,
                max_row=LIMIT,
                timeout=5,
                Query=[api_pb2.VQLRequest(
                    Name="HAWKI.ReadOnlyInventory", VQL=_HUNT_QUERY
                )],
            )
            for message in api_pb2_grpc.APIStub(channel).Query(
                request, timeout=6
            ):
                if message.log and re.search(
                    r"\berror\b|\bdenied\b|\bunauthorized\b",
                    message.log, re.I,
                ):
                    raise ReadError("query_rejected")
                if message.Response:
                    if len(message.Response) > 100_000:
                        raise ReadError("response_limit")
                    part = json.loads(message.Response)
                    if not isinstance(part, list):
                        raise ReadError("invalid_response")
                    rows.extend(part)
                    if len(rows) > 1:
                        raise ReadError("invalid_response")
    except grpc.RpcError as exc:
        raise ReadError("grpc_" + exc.code().name.lower()) from None
    except (ValueError, TypeError):
        raise ReadError("invalid_response") from None

    if len(rows) != 1 or not isinstance(rows[0], dict):
        raise ReadError("invalid_response")
    result = rows[0]
    clients = result.get("clients")
    if (
        result.get("identity") != config["name"]
        or result.get("api_ok") != 1
        or not isinstance(clients, list)
        or len(clients) > LIMIT
        or result.get("returned_clients") != len(clients)
        or not all(isinstance(client, dict) for client in clients)
    ):
        raise ReadError("invalid_response")

    return {
        **result,
        "checked_at": datetime.now(timezone.utc).isoformat(),
        "inventory_limit": LIMIT,
    }

def read_hunts():
    result = _read_hunt_inventory()
    hunts = result["clients"]
    if not all(
        isinstance(item.get("hunt_id"), str) and item["hunt_id"]
        for item in hunts
    ):
        raise ReadError("invalid_hunt_response")
    return {
        "status": "success",
        "source": "velociraptor_api",
        "checked_at": result["checked_at"],
        "returned_hunts": len(hunts),
        "inventory_limit": LIMIT,
        "hunts": hunts,
        "coverage": "At most 20 server hunt records; not a total or collection-result query.",
    }


_FLOW_LIMIT = 10

def _read_flow_rows(vql):
    path = os.getenv("VELOCIRAPTOR_API_CONFIG", "").strip()
    if not path:
        raise ReadError("not_configured")

    try:
        import grpc
        import yaml
        from pyvelociraptor import api_pb2, api_pb2_grpc
    except ImportError:
        raise ReadError("missing_dependency") from None

    try:
        raw = Path(path).read_bytes()
        config = yaml.safe_load(raw)
        required = (
            "api_connection_string",
            "ca_certificate",
            "client_private_key",
            "client_cert",
            "name",
        )
        if (
            not isinstance(config, dict)
            or not all(
                isinstance(config.get(key), str)
                and config[key].strip()
                for key in required
            )
        ):
            raise ValueError()
        credentials = grpc.ssl_channel_credentials(
            root_certificates=config["ca_certificate"].encode(),
            private_key=config["client_private_key"].encode(),
            certificate_chain=config["client_cert"].encode(),
        )
        server_name = config.get("pinned_server_name") or "VelociraptorServer"
    except (OSError, ValueError, TypeError, yaml.YAMLError):
        raise ReadError("credential_configuration") from None

    rows = []
    try:
        with grpc.secure_channel(
            config["api_connection_string"],
            credentials,
            options=(
                ("grpc.ssl_target_name_override", server_name),
                ("grpc.max_receive_message_length", 2 * 1024 * 1024),
            ),
        ) as channel:
            request = api_pb2.VQLCollectorArgs(
                org_id=config.get("org_id") or "",
                max_wait=1,
                max_row=_FLOW_LIMIT,
                timeout=5,
                Query=[
                    api_pb2.VQLRequest(
                        Name="HAWKI.ReadOnlyFlows",
                        VQL=vql,
                    )
                ],
            )
            for message in api_pb2_grpc.APIStub(channel).Query(
                request, timeout=6
            ):
                if message.log and re.search(
                    r"\berror\b|\bdenied\b|\bunauthorized\b",
                    str(message.log),
                    re.I,
                ):
                    raise ReadError("query_rejected")
                if message.Response:
                    if len(message.Response) > 250_000:
                        raise ReadError("response_limit")
                    part = json.loads(message.Response)
                    if not isinstance(part, list):
                        raise ReadError("invalid_response")
                    rows.extend(part)
                    if len(rows) > _FLOW_LIMIT:
                        raise ReadError("response_limit")
    except grpc.RpcError as exc:
        raise ReadError("grpc_" + exc.code().name.lower()) from None
    except (ValueError, TypeError):
        raise ReadError("invalid_response") from None

    return config, rows


def read_flows(client_id="", host=""):
    client_id = str(client_id or "").strip()
    host = str(host or "").strip()

    if not client_id and re.fullmatch(r"C\.[0-9A-Fa-f]+", host):
        client_id = host

    if not client_id:
        if not host:
            raise ReadError("client_required")
        all_clients = read_clients().get("items", [])
        requested_host = host.casefold()
        matches = [
            item for item in all_clients
            if str(item.get("hostname", "")).casefold() == requested_host
        ]
        if not matches:
            raise ReadError("client_not_found")
        if len(matches) != 1:
            raise ReadError("client_not_unique")
        client_id = matches[0].get("client_id", "")

    if not re.fullmatch(r"C\.[0-9A-Fa-f]+", client_id):
        raise ReadError("invalid_client_id")

    vql = (
        "SELECT * FROM flows("
        f"client_id={json.dumps(client_id)}, summary=TRUE"
        f") LIMIT {_FLOW_LIMIT}"
    )
    config, rows = _read_flow_rows(vql)

    return {
        "status": "success",
        "source": "velociraptor_api",
        "checked_at": datetime.now(timezone.utc).isoformat(),
        "identity": config["name"],
        "client_id": client_id,
        "host": host or None,
        "returned_flows": len(rows),
        "query_limit": _FLOW_LIMIT,
        "flows": rows,
        "coverage": (
            "At most 10 existing flow summaries for one client. "
            "This reads existing collection metadata only; it does not "
            "schedule a collection or execute a response action."
        ),
    }
