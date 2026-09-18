"""HAW-KI SIEM aggregation service.

Combines Wazuh Indexer data with Wazuh Server API state.
Read-only by construction.
"""

from __future__ import annotations

from datetime import datetime, timedelta, timezone
from typing import Any

from .wazuh import WazuhIndexerClient, WazuhIndexerError
from .wazuh_api import WazuhServerAPIClient


def _hit_total(payload: dict[str, Any]) -> int:
    hits = payload.get("hits", {})
    total = hits.get("total", 0)

    if isinstance(total, dict):
        total = total.get("value", 0)

    try:
        return int(total)
    except (TypeError, ValueError):
        return 0


class SiemService:
    def __init__(
        self,
        indexer: WazuhIndexerClient,
        api: WazuhServerAPIClient,
        *,
        alert_index: str,
        archive_index: str,
        timestamp_field: str = "timestamp",
    ):
        self.indexer = indexer
        self.api = api
        self.alert_index = alert_index
        self.archive_index = archive_index
        self.timestamp_field = timestamp_field

    def _count_since(
        self,
        index: str,
        since: str,
    ) -> int:
        payload = self.indexer.search(
            index,
            {
                "size": 0,
                "track_total_hits": True,
                "query": {
                    "range": {
                        self.timestamp_field: {
                            "gte": since,
                            "lte": "now",
                        }
                    }
                },
            },
        )

        return _hit_total(payload)

    def overview(self) -> dict[str, Any]:
        checked_at = datetime.now(timezone.utc).isoformat()

        indexer_reachable = True
        indexer_error = ""

        try:
            alerts_24h = self._count_since(
                self.alert_index,
                "now-24h",
            )

            raw_1h = self._count_since(
                self.archive_index,
                "now-1h",
            )

        except WazuhIndexerError as exc:
            indexer_reachable = False
            indexer_error = str(exc)
            alerts_24h = None
            raw_1h = None

        api_health = self.api.health()

        return {
            "checked_at": checked_at,
            "indexer": {
                "reachable": indexer_reachable,
                "error": indexer_error or None,
            },
            "server_api": {
                "reachable": api_health.get(
                    "reachable",
                    False,
                ),
                "error": api_health.get("error"),
            },
            "manager": api_health.get(
                "manager",
                {},
            ),
            "agents": api_health.get(
                "agents",
                {
                    "total": None,
                    "active": None,
                },
            ),
            "alerts": {
                "last_24h": alerts_24h,
            },
            "raw_events": {
                "last_1h": raw_1h,
            },
        }

    def hosts(self) -> dict[str, Any]:
        """Return monitored Wazuh endpoints from the Server API."""

        payload = self.api.agents()
        items = (
            payload
            .get("data", {})
            .get("affected_items", [])
        )

        hosts: list[dict[str, Any]] = []

        for item in items:
            if not isinstance(item, dict):
                continue

            agent_id = str(item.get("id") or "").strip()

            if not agent_id or agent_id == "000":
                continue

            os_info = (
                item.get("os")
                if isinstance(item.get("os"), dict)
                else {}
            )

            groups = item.get("group")
            if not isinstance(groups, list):
                groups = []

            hosts.append(
                {
                    "id": agent_id,
                    "name": str(item.get("name") or ""),
                    "ip": str(item.get("ip") or ""),
                    "status": str(item.get("status") or "unknown"),
                    "last_keepalive": item.get("lastKeepAlive"),
                    "date_added": item.get("dateAdd"),
                    "wazuh_version": str(item.get("version") or ""),
                    "manager": str(item.get("manager") or ""),
                    "node": str(item.get("node_name") or ""),
                    "groups": groups,
                    "group_config_status": str(
                        item.get("group_config_status") or ""
                    ),
                    "os": {
                        "name": str(os_info.get("name") or ""),
                        "version": str(os_info.get("version") or ""),
                        "platform": str(os_info.get("platform") or ""),
                        "arch": str(os_info.get("arch") or ""),
                    },
                }
            )

        hosts.sort(key=lambda item: item["id"])

        return {
            "total": len(hosts),
            "active": sum(
                1 for item in hosts
                if item["status"].lower() == "active"
            ),
            "hosts": hosts,
        }

    def host_detail(
        self,
        agent_id: str,
        *,
        recent_limit: int = 20,
    ) -> dict[str, Any]:
        """Join Wazuh endpoint state with recent detections."""

        agent_id = str(agent_id or "").strip()

        if (
            not agent_id
            or not agent_id.isdigit()
            or len(agent_id) > 8
        ):
            raise ValueError("Invalid Wazuh agent ID.")

        recent_limit = max(
            1,
            min(int(recent_limit), 100),
        )

        inventory = self.hosts()
        agent = next(
            (
                item
                for item in inventory["hosts"]
                if item["id"] == agent_id
            ),
            None,
        )

        if agent is None:
            raise LookupError(
                f"Wazuh agent {agent_id} was not found."
            )

        os_payload = self.api.agent_os(agent_id)
        os_items = (
            os_payload
            .get("data", {})
            .get("affected_items", [])
        )

        sys_os = (
            os_items[0]
            if os_items
            and isinstance(os_items[0], dict)
            else {}
        )

        os_info = (
            sys_os.get("os")
            if isinstance(sys_os.get("os"), dict)
            else {}
        )

        scan = (
            sys_os.get("scan")
            if isinstance(sys_os.get("scan"), dict)
            else {}
        )

        alert_payload = self.indexer.search(
            self.alert_index,
            {
                "size": recent_limit,
                "track_total_hits": True,
                "sort": [
                    {
                        self.timestamp_field: {
                            "order": "desc",
                            "unmapped_type": "date",
                        }
                    }
                ],
                "_source": [
                    "timestamp",
                    "agent",
                    "rule",
                    "decoder",
                    "location",
                    "data",
                    "full_log",
                ],
                "query": {
                    "bool": {
                        "must": [
                            {
                                "query_string": {
                                    "query": (
                                        f'agent.id:"{agent_id}"'
                                    )
                                }
                            }
                        ],
                        "filter": [
                            {
                                "range": {
                                    self.timestamp_field: {
                                        "gte": "now-24h",
                                        "lte": "now",
                                    }
                                }
                            }
                        ],
                    }
                },
            },
        )

        recent: list[dict[str, Any]] = []

        for hit in (
            alert_payload
            .get("hits", {})
            .get("hits", [])
        ):
            source = hit.get("_source", {})

            if not isinstance(source, dict):
                continue

            rule = (
                source.get("rule")
                if isinstance(source.get("rule"), dict)
                else {}
            )

            data = (
                source.get("data")
                if isinstance(source.get("data"), dict)
                else {}
            )

            recent.append(
                {
                    "id": str(hit.get("_id") or ""),
                    "index": str(hit.get("_index") or ""),
                    "timestamp": source.get("timestamp"),
                    "rule_id": str(rule.get("id") or ""),
                    "rule_level": rule.get("level"),
                    "description": str(
                        rule.get("description") or "Wazuh alert"
                    ),
                    "groups": (
                        rule.get("groups")
                        if isinstance(rule.get("groups"), list)
                        else []
                    ),
                    "source_ip": str(
                        data.get("srcip")
                        or (
                            data.get("eventdata", {}).get("sourceIp")
                            if isinstance(
                                data.get("eventdata"),
                                dict,
                            )
                            else ""
                        )
                        or ""
                    ),
                    "location": str(source.get("location") or ""),
                }
            )

        host = {
            **agent,
            "system": {
                "hostname": str(sys_os.get("hostname") or ""),
                "architecture": str(
                    sys_os.get("architecture") or ""
                ),
                "sysname": str(sys_os.get("sysname") or ""),
                "kernel_release": str(
                    sys_os.get("release") or ""
                ),
                "kernel_version": str(
                    sys_os.get("version") or ""
                ),
                "os_name": str(
                    os_info.get("name")
                    or agent["os"].get("name")
                    or ""
                ),
                "os_version": str(
                    os_info.get("version")
                    or agent["os"].get("version")
                    or ""
                ),
                "os_platform": str(
                    os_info.get("platform")
                    or agent["os"].get("platform")
                    or ""
                ),
                "scan_time": scan.get("time"),
            },
        }

        return {
            "checked_at": datetime.now(
                timezone.utc
            ).isoformat(),
            "host": host,
            "alerts": {
                "last_24h": _hit_total(alert_payload),
                "recent": recent,
            },
        }

    def dashboard_visuals(
        self,
        *,
        hours: int = 24,
    ) -> dict[str, Any]:
        """Return compact analyst-facing alert aggregations."""

        hours = max(1, min(int(hours), 168))
        since = f"now-{hours}h"

        payload = self.indexer.search(
            self.alert_index,
            {
                "size": 0,
                "track_total_hits": False,
                "query": {
                    "range": {
                        self.timestamp_field: {
                            "gte": since,
                            "lte": "now",
                        }
                    }
                },
                "aggs": {
                    "activity": {
                        "date_histogram": {
                            "field": self.timestamp_field,
                            "fixed_interval": "1h",
                            "min_doc_count": 0,
                            "extended_bounds": {
                                "min": since,
                                "max": "now",
                            },
                        }
                    },
                    "levels": {
                        "terms": {
                            "field": "rule.level",
                            "size": 16,
                            "order": {
                                "_key": "asc"
                            },
                        }
                    },
                },
            },
        )

        aggs = payload.get("aggregations", {})

        activity = [
            {
                "time": bucket.get("key_as_string"),
                "count": int(bucket.get("doc_count", 0)),
            }
            for bucket in (
                aggs.get("activity", {})
                .get("buckets", [])
            )
        ]

        levels = [
            {
                "level": int(bucket.get("key", 0)),
                "count": int(bucket.get("doc_count", 0)),
            }
            for bucket in (
                aggs.get("levels", {})
                .get("buckets", [])
            )
        ]

        return {
            "hours": hours,
            "activity": activity,
            "levels": levels,
        }

    def host_security_context(
        self,
        agent_id: str,
    ) -> dict[str, Any]:
        """Return compact security posture for one Wazuh endpoint."""

        agent_id = str(agent_id or "").strip()

        if (
            not agent_id
            or not agent_id.isdigit()
            or len(agent_id) > 8
        ):
            raise ValueError("Invalid Wazuh agent ID.")

        # SCA is authoritative through the Wazuh Server API.
        sca_payload = self.api.get(
            f"/sca/{agent_id}",
            params={"limit": 20},
        )

        sca_items = (
            sca_payload
            .get("data", {})
            .get("affected_items", [])
        )

        policies: list[dict[str, Any]] = []

        for item in sca_items:
            if not isinstance(item, dict):
                continue

            policies.append(
                {
                    "id": str(item.get("policy_id") or ""),
                    "name": str(item.get("name") or ""),
                    "score": item.get("score"),
                    "pass": int(item.get("pass") or 0),
                    "fail": int(item.get("fail") or 0),
                    "invalid": int(item.get("invalid") or 0),
                    "total_checks": int(
                        item.get("total_checks") or 0
                    ),
                    "start_scan": item.get("start_scan"),
                    "end_scan": item.get("end_scan"),
                }
            )

        # /syscheck returns the current tracked FIM inventory.
        # It must not be interpreted as a count of recent changes.
        fim_payload = self.api.get(
            f"/syscheck/{agent_id}",
            params={"limit": 1},
        )

        fim_data = (
            fim_payload.get("data", {})
            if isinstance(fim_payload.get("data"), dict)
            else {}
        )

        tracked_entries = int(
            fim_data.get("total_affected_items") or 0
        )

        # Vulnerability state is stored in the Indexer.
        vuln_payload = self.indexer.search(
            "wazuh-states-vulnerabilities-*",
            {
                "size": 0,
                "track_total_hits": True,
                "query": {
                    "term": {
                        "agent.id": agent_id
                    }
                },
                "aggs": {
                    "by_severity": {
                        "terms": {
                            "field": "vulnerability.severity",
                            "size": 10,
                        }
                    },
                    "under_evaluation": {
                        "filter": {
                            "term": {
                                "vulnerability.under_evaluation": True
                            }
                        }
                    },
                },
            },
        )

        severities = {
            "critical": 0,
            "high": 0,
            "medium": 0,
            "low": 0,
            "unknown": 0,
        }

        vuln_aggs = vuln_payload.get("aggregations", {})

        for bucket in (
            vuln_aggs
            .get("by_severity", {})
            .get("buckets", [])
        ):
            name = str(
                bucket.get("key", "")
            ).lower()

            count = int(
                bucket.get("doc_count", 0)
            )

            if name in severities:
                severities[name] = count
            else:
                severities["unknown"] += count

        # Actual recent FIM activity is represented by Wazuh alerts,
        # not by the current syscheck inventory.
        fim_alert_payload = self.indexer.search(
            self.alert_index,
            {
                "size": 0,
                "track_total_hits": True,
                "query": {
                    "bool": {
                        "must": [
                            {
                                "query_string": {
                                    "query": (
                                        f'agent.id:"{agent_id}" '
                                        'AND rule.groups:syscheck'
                                    )
                                }
                            }
                        ],
                        "filter": [
                            {
                                "range": {
                                    self.timestamp_field: {
                                        "gte": "now-24h",
                                        "lte": "now",
                                    }
                                }
                            }
                        ],
                    }
                },
            },
        )

        return {
            "agent_id": agent_id,
            "sca": {
                "policy_count": len(policies),
                "policies": policies,
            },
            "vulnerabilities": {
                "total_findings": _hit_total(
                    vuln_payload
                ),
                "severity": severities,
                "under_evaluation": int(
                    vuln_aggs
                    .get("under_evaluation", {})
                    .get("doc_count", 0)
                ),
            },
            "fim": {
                "tracked_entries": tracked_entries,
                "detections_last_24h": _hit_total(
                    fim_alert_payload
                ),
            },
        }

    def vulnerability_summary(self) -> dict[str, Any]:
        payload = self.indexer.search(
            "wazuh-states-vulnerabilities-*",
            {
                "size": 0,
                "track_total_hits": True,
                "aggs": {
                    "by_severity": {
                        "terms": {
                            "field": "vulnerability.severity",
                            "size": 10,
                        }
                    },
                    "by_agent": {
                        "terms": {
                            "field": "agent.id",
                            "size": 20,
                        },
                        "aggs": {
                            "sample": {
                                "top_hits": {
                                    "size": 1,
                                    "_source": ["agent.name"],
                                }
                            }
                        },
                    },
                    "under_evaluation": {
                        "filter": {
                            "term": {
                                "vulnerability.under_evaluation": True
                            }
                        }
                    },
                },
            },
        )

        total = _hit_total(payload)
        aggs = payload.get("aggregations", {})

        severities = {
            "critical": 0,
            "high": 0,
            "medium": 0,
            "low": 0,
            "unknown": 0,
        }

        buckets = (
            aggs.get("by_severity", {})
            .get("buckets", [])
        )

        for bucket in buckets:
            name = str(bucket.get("key", "")).lower()
            count = int(bucket.get("doc_count", 0))

            if name in severities:
                severities[name] = count
            else:
                severities["unknown"] += count

        agents = []

        for bucket in (
            aggs.get("by_agent", {})
            .get("buckets", [])
        ):
            name = ""

            hits = (
                bucket.get("sample", {})
                .get("hits", {})
                .get("hits", [])
            )

            if hits:
                name = (
                    hits[0]
                    .get("_source", {})
                    .get("agent", {})
                    .get("name", "")
                )

            agents.append(
                {
                    "id": str(bucket.get("key", "")),
                    "name": name,
                    "count": int(
                        bucket.get("doc_count", 0)
                    ),
                }
            )

        under_evaluation = int(
            aggs.get(
                "under_evaluation",
                {},
            ).get(
                "doc_count",
                0,
            )
        )

        return {
            "total": total,
            "severity": severities,
            "under_evaluation": under_evaluation,
            "agents": agents,
        }

    def web_activity_scenarios(
        self,
        *,
        hours: int = 24,
        limit: int = 20,
    ) -> dict[str, Any]:
        """Group repeated web detections by agent and source IP."""

        hours = max(1, min(int(hours), 168))
        limit = max(1, min(int(limit), 100))

        payload = self.indexer.search(
            self.alert_index,
            {
                "size": 0,
                "track_total_hits": True,
                "query": {
                    "bool": {
                        "filter": [
                            {
                                "range": {
                                    self.timestamp_field: {
                                        "gte": f"now-{hours}h",
                                        "lte": "now",
                                    }
                                }
                            },
                            {
                                "terms": {
                                    "rule.id": [
                                        "31101",
                                        "31333",
                                        "31151",
                                        "31301",
                                        "31516",
                                    ]
                                }
                            },
                        ]
                    }
                },
                "aggs": {
                    "by_agent": {
                        "terms": {
                            "field": "agent.id",
                            "size": 20,
                        },
                        "aggs": {
                            "by_source": {
                                "terms": {
                                    "field": "data.srcip",
                                    "size": limit,
                                    "min_doc_count": 2,
                                },
                                "aggs": {
                                    "first_seen": {
                                        "min": {
                                            "field": self.timestamp_field
                                        }
                                    },
                                    "last_seen": {
                                        "max": {
                                            "field": self.timestamp_field
                                        }
                                    },
                                    "highest_level": {
                                        "max": {
                                            "field": "rule.level"
                                        }
                                    },
                                    "distinct_rules": {
                                        "cardinality": {
                                            "field": "rule.id"
                                        }
                                    },
                                    "rules": {
                                        "terms": {
                                            "field": "rule.id",
                                            "size": 20,
                                        }
                                    },
                                    "sample": {
                                        "top_hits": {
                                            "size": 5,
                                            "sort": [
                                                {
                                                    self.timestamp_field: {
                                                        "order": "desc"
                                                    }
                                                }
                                            ],
                                            "_source": [
                                                "timestamp",
                                                "agent",
                                                "rule",
                                                "data",
                                            ],
                                        }
                                    },
                                },
                            }
                        },
                    }
                },
            },
        )

        scenarios: list[dict[str, Any]] = []

        for agent_bucket in (
            payload
            .get("aggregations", {})
            .get("by_agent", {})
            .get("buckets", [])
        ):
            agent_id = str(agent_bucket.get("key", ""))

            for bucket in (
                agent_bucket
                .get("by_source", {})
                .get("buckets", [])
            ):
                samples = []

                for hit in (
                    bucket
                    .get("sample", {})
                    .get("hits", {})
                    .get("hits", [])
                ):
                    source = hit.get("_source", {})
                    data = (
                        source.get("data")
                        if isinstance(source.get("data"), dict)
                        else {}
                    )
                    rule = (
                        source.get("rule")
                        if isinstance(source.get("rule"), dict)
                        else {}
                    )

                    samples.append(
                        {
                            "timestamp": source.get("timestamp"),
                            "rule_id": str(rule.get("id") or ""),
                            "rule_level": rule.get("level"),
                            "description": str(
                                rule.get("description") or ""
                            ),
                            "method": str(
                                data.get("protocol") or ""
                            ),
                            "status": str(
                                data.get("id") or ""
                            ),
                            "url": str(
                                data.get("url") or ""
                            ),
                        }
                    )

                scenarios.append(
                    {
                        "agent_id": agent_id,
                        "source_ip": str(
                            bucket.get("key", "")
                        ),
                        "count": int(
                            bucket.get("doc_count", 0)
                        ),
                        "distinct_rules": int(
                            bucket
                            .get("distinct_rules", {})
                            .get("value", 0)
                        ),
                        "highest_rule_level": int(
                            bucket
                            .get("highest_level", {})
                            .get("value", 0)
                            or 0
                        ),
                        "first_seen": (
                            bucket
                            .get("first_seen", {})
                            .get("value_as_string")
                        ),
                        "last_seen": (
                            bucket
                            .get("last_seen", {})
                            .get("value_as_string")
                        ),
                        "rules": [
                            {
                                "id": str(x.get("key", "")),
                                "count": int(
                                    x.get("doc_count", 0)
                                ),
                            }
                            for x in (
                                bucket
                                .get("rules", {})
                                .get("buckets", [])
                            )
                        ],
                        "samples": samples,
                    }
                )

        scenarios.sort(
            key=lambda item: item["count"],
            reverse=True,
        )

        return {
            "hours": hours,
            "total_alerts": _hit_total(payload),
            "scenario_count": len(scenarios),
            "scenarios": scenarios[:limit],
        }

    def alert_enrichment(
        self,
        alert_id: str,
    ) -> dict[str, Any]:
        """Build deterministic recurrence context for one alert."""

        alert_id = str(alert_id or "").strip()

        if not alert_id:
            raise ValueError("alert_id is required")

        selected = self.indexer.search(
            self.alert_index,
            {
                "size": 1,
                "query": {
                    "ids": {
                        "values": [alert_id]
                    }
                },
            },
        )

        hits = (
            selected
            .get("hits", {})
            .get("hits", [])
        )

        if not hits:
            raise LookupError(
                f"Alert {alert_id} was not found"
            )

        source = hits[0].get("_source", {})

        timestamp = str(
            source.get(self.timestamp_field, "")
        ).strip()

        agent = (
            source.get("agent")
            if isinstance(source.get("agent"), dict)
            else {}
        )

        rule = (
            source.get("rule")
            if isinstance(source.get("rule"), dict)
            else {}
        )

        data = (
            source.get("data")
            if isinstance(source.get("data"), dict)
            else {}
        )

        eventdata = (
            data.get("eventdata")
            if isinstance(data.get("eventdata"), dict)
            else {}
        )

        agent_id = str(agent.get("id") or "").strip()
        rule_id = str(rule.get("id") or "").strip()

        source_ip = str(
            data.get("srcip")
            or eventdata.get("sourceIp")
            or ""
        ).strip()

        if not timestamp:
            raise ValueError(
                "Selected alert has no usable timestamp"
            )

        parsed = datetime.fromisoformat(
            timestamp
            .replace("Z", "+00:00")
            .replace("+0000", "+00:00")
        )

        start = (
            parsed - timedelta(hours=24)
        ).isoformat()

        end = (
            parsed + timedelta(hours=1)
        ).isoformat()

        aggs: dict[str, Any] = {}

        if agent_id:
            aggs["same_agent"] = {
                "filter": {
                    "term": {
                        "agent.id": agent_id
                    }
                }
            }

        if rule_id:
            aggs["same_rule"] = {
                "filter": {
                    "term": {
                        "rule.id": rule_id
                    }
                }
            }

        if source_ip:
            source_filter = {
                "bool": {
                    "should": [
                        {
                            "term": {
                                "data.srcip": source_ip
                            }
                        },
                        {
                            "term": {
                                "data.eventdata.sourceIp": source_ip
                            }
                        },
                    ],
                    "minimum_should_match": 1,
                }
            }

            aggs["same_source"] = {
                "filter": source_filter,
                "aggs": {
                    "distinct_rules": {
                        "cardinality": {
                            "field": "rule.id"
                        }
                    },
                    "distinct_agents": {
                        "cardinality": {
                            "field": "agent.id"
                        }
                    },
                },
            }

        result = self.indexer.search(
            self.alert_index,
            {
                "size": 0,
                "query": {
                    "range": {
                        self.timestamp_field: {
                            "gte": start,
                            "lte": end,
                        }
                    }
                },
                "aggs": aggs,
            },
        )

        values = result.get("aggregations", {})

        source_bucket = values.get(
            "same_source",
            {},
        )

        return {
            "alert_id": alert_id,
            "window": {
                "start": start,
                "end": end,
            },
            "agent_id": agent_id or None,
            "rule_id": rule_id or None,
            "source_ip": source_ip or None,
            "same_agent_count": int(
                values.get(
                    "same_agent",
                    {},
                ).get(
                    "doc_count",
                    0,
                )
            ),
            "same_rule_count": int(
                values.get(
                    "same_rule",
                    {},
                ).get(
                    "doc_count",
                    0,
                )
            ),
            "same_source": {
                "count": int(
                    source_bucket.get(
                        "doc_count",
                        0,
                    )
                ),
                "distinct_rules": int(
                    source_bucket.get(
                        "distinct_rules",
                        {},
                    ).get(
                        "value",
                        0,
                    )
                ),
                "distinct_agents": int(
                    source_bucket.get(
                        "distinct_agents",
                        {},
                    ).get(
                        "value",
                        0,
                    )
                ),
            },
        }

    def raw_context(
        self,
        alert_id: str,
        *,
        window_seconds: int = 300,
        limit: int = 100,
    ) -> dict[str, Any]:
        alert_id = str(alert_id or "").strip()

        if not alert_id:
            raise ValueError("alert_id is required")

        window_seconds = max(
            1,
            min(int(window_seconds), 3600),
        )

        limit = max(
            1,
            min(int(limit), 500),
        )

        alert_payload = self.indexer.search(
            self.alert_index,
            {
                "size": 1,
                "query": {
                    "ids": {
                        "values": [alert_id]
                    }
                },
            },
        )

        alert_hits = (
            alert_payload
            .get("hits", {})
            .get("hits", [])
        )

        if not alert_hits:
            raise LookupError(
                f"Alert {alert_id} was not found"
            )

        alert_hit = alert_hits[0]
        alert = alert_hit.get("_source", {})

        timestamp = str(
            alert.get(
                self.timestamp_field,
                "",
            )
        ).strip()

        agent = alert.get("agent", {})
        agent_id = str(
            agent.get("id", "")
            if isinstance(agent, dict)
            else ""
        ).strip()

        agent_name = str(
            agent.get("name", "")
            if isinstance(agent, dict)
            else ""
        ).strip()

        if not timestamp:
            raise ValueError(
                "Selected alert has no usable timestamp"
            )

        if not agent_id:
            raise ValueError(
                "Selected alert has no agent.id"
            )

        parsed = datetime.fromisoformat(
            timestamp
            .replace("Z", "+00:00")
            .replace("+0000", "+00:00")
        )

        start = (
            parsed - timedelta(
                seconds=window_seconds
            )
        ).isoformat()

        end = (
            parsed + timedelta(
                seconds=window_seconds
            )
        ).isoformat()

        raw_payload = self.indexer.search(
            self.archive_index,
            {
                "size": limit,
                "track_total_hits": True,
                "sort": [
                    {
                        self.timestamp_field: {
                            "order": "asc",
                            "unmapped_type": "date",
                        }
                    }
                ],
                "_source": [
                    "timestamp",
                    "agent",
                    "manager",
                    "location",
                    "decoder",
                    "rule",
                    "data",
                    "full_log",
                    "input",
                ],
                "query": {
                    "bool": {
                        "filter": [
                            {
                                "term": {
                                    "agent.id": agent_id
                                }
                            },
                            {
                                "range": {
                                    self.timestamp_field: {
                                        "gte": start,
                                        "lte": end,
                                    }
                                }
                            },
                        ]
                    }
                },
            },
        )

        raw_hits = (
            raw_payload
            .get("hits", {})
            .get("hits", [])
        )

        events = [
            {
                "id": hit.get("_id"),
                "index": hit.get("_index"),
                "source": hit.get("_source", {}),
            }
            for hit in raw_hits
            if isinstance(hit, dict)
        ]

        return {
            "alert": {
                "id": alert_hit.get("_id"),
                "index": alert_hit.get("_index"),
                "timestamp": timestamp,
                "agent": {
                    "id": agent_id,
                    "name": agent_name,
                },
                "rule": alert.get("rule", {}),
                "location": alert.get("location"),
            },
            "window": {
                "seconds_before": window_seconds,
                "seconds_after": window_seconds,
                "start": start,
                "end": end,
            },
            "raw_events": {
                "total": _hit_total(raw_payload),
                "returned": len(events),
                "events": events,
            },
        }
