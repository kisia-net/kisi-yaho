# HAW-KI Velociraptor integration

Release: 2026.10.06.1

This package replaces the File Hunt and Host Response pages and adds operational API collection. It was built against the application functions, templates, dependency versions, and artifact schemas supplied on 6 October 2026. It has not been deployed to the AWS hosts from this workspace.

## What changes

| Surface | Functions |
|---|---|
| File Hunt | Host search; recent file collection sorted by modification time; scoped metadata search; SHA-256 search; YARA; saved directory listings and explicit refresh; individual file acquisition; native hunts and their collections; request approvals |
| Host Response | Process, network, service, cron, SSH authorization, account, login and disk snapshots; nine-component triage; evidence acquisition; component status and job history |
| Results | Collections started in the GUI or HAW-KI; named result sources; readable timestamps; primary columns; complete original record; logs; upload metadata; pagination; export of the displayed result page with provenance |
| Comparison | Newly observed, changed and no-longer-listed paths between two complete, comparable HAW-KI FileFinder scans |
| Execution | Separate worker; API credential mounted only there; SQLite requests and approvals; immutable reviewed parameters; single dispatch claim; actual flow/hunt identifiers; cancellation tracking |

Fourteen operations use the installed native artifacts. Triage creates separate flows so a failed component remains visible. Multihost requests, YARA, and file acquisition require an approver. Other bounded, explicitly reviewed collections may be launched by an analyst. The existing HAW-KI login, role and CSRF handlers protect all new endpoints.

The new pages have no agent forms. Other pages and the agent backend keep their current behavior. The generic response-action switch is not enabled or repurposed. Existing Suricata and red-team integrations are not modified.

## Installation on 10.0.10.176

The easiest path with SSM is to open `terminal-install.txt`, copy its entire contents, and paste it into the HAW-KI host's SSM terminal. It is a self-contained installer; it downloads nothing. It checks the embedded package checksum, extracts the files under `/opt/hawki/vr-integration`, builds the application, runs read-only preflight, and starts `hawki-web` and `vr-dispatcher`.

Alternatively, place this extracted directory at `/opt/hawki/vr-integration`, then run:

```bash
cd /opt/hawki
sudo python3 /opt/hawki/vr-integration/install.py
sudo python3 /opt/hawki/vr-integration/install.py --apply
```

The first command lists affected files. The second applies the update. No endpoint collection is launched by installation or preflight. Existing application data, credentials, source history and other services are not deleted. No Git operation is performed. If build or preflight fails, edited source/configuration files are restored from memory before the installer exits, and running services are left in place. A new image tag avoids replacing the prior application image during that preflight. A failure during the final Compose restart is reported by Compose and requires inspecting its output.

The installer changes `app.py`, the Dockerfile, Compose, the base/actions templates, and the two page templates, and adds `hawki_vr/` and three static assets. It preserves Compose values but serializes the file as JSON, which Compose accepts as YAML; comments/formatting are not preserved. Only the two new pages switch from the legacy shared controller to their dedicated controller.

The dispatcher initially has no execution key. Existing result browsing can work immediately; launching is unavailable until the next section is completed. Its Docker health status may be `unhealthy` during this unconfigured stage.

## Connect the execution identity

Keep the existing read API identity unchanged. The new identity receives only `any_query`, `read_results`, `collect_client`, and `start_hunt`; it does not receive administrator, server collection, or server filesystem permissions. These permissions are still broad enough to launch client artifacts if the credential is used outside HAW-KI, which is why the key is isolated from the web process. HAW-KI's catalog and validation further restrict the operations exposed to operators.

Use the three terminal files in this order. Only the public transfer certificate, a checksum, and encrypted credential text move through the terminal clipboard. Do not paste an API private key into chat.

1. **HAW-KI, 10.0.10.176:** paste `terminal-receiver.txt`. Copy its complete public certificate output.
2. **Velociraptor, 10.0.10.212:** paste `terminal-sender.txt`, then paste that public certificate when prompted. This creates `hawki-collector-…`, assigns the four permissions, saves `/etc/velociraptor/hawki-collector.api.yaml`, and restarts `velociraptor_server.service` once so the identity is recognized. Copy the printed credential SHA-256 and complete `BEGIN CMS` / `END CMS` block. Existing collector credentials at that path are reused, not overwritten.
3. **HAW-KI, 10.0.10.176:** paste `terminal-receive.txt`, then supply the checksum and encrypted CMS block when prompted. The plaintext is written only to `/opt/hawki/secrets/velociraptor-execution/api.yaml`, owned by root and readable by group 999. The dispatcher already has that directory mounted read-only and detects the file automatically.

The receiver's RSA private key stays in `/opt/hawki/secrets/vr-transfer` with root-only access. CMS uses AES-256-GCM and RSA-OAEP/SHA-256. Transfer tooling is separate from application startup. The worker does not have the transfer private key or any web application environment secrets.

Check on HAW-KI:

```bash
cd /opt/hawki
sudo docker compose -f /opt/hawki/compose.yaml ps hawki-web vr-dispatcher
sudo docker compose -f /opt/hawki/compose.yaml exec -T hawki-web \
  python -m hawki_vr.preflight
```

Expected: read API and templates `ok`, anonymous API access protected, and worker `ready: true` after its next connection check. This readiness confirms a working authenticated connection; the first collection also verifies the collection permission end to end.

## First live acceptance check

1. Open `http://localhost:8080/hunts`. Select one intended Linux host by its full client ID.
2. Select **파일 탐색**, use `/tmp`, and choose **새 목록 수집**. Review the exact target and select **수집 시작**.
3. In **수집 요청**, open the request. Verify that it has a real `F.…` identifier, then inspect status, logs and `System.VFS.ListDirectory/Listing` results. A completed collection can legitimately contain zero entries; a missing result source or query error remains distinct.
4. Open `http://localhost:8080/response`. Select the same host and run **초동 조사 수집**. Check each component separately. This collects endpoint data and should be done deliberately, after the read-only installer checks pass.
5. For multi-host work, use **헌트 → 새 헌트** and explicitly select up to ten hosts. An approver reviews the request under **수집 요청** (also linked from the existing approvals page).

No live collection or destructive response was executed during package development. The above is the remaining deployment acceptance check.

## Behavior and limits

- File timestamps are not creation events. The recent-file view orders existing FileFinder rows by `MTime`. `CTime` is labeled metadata change. A first scan does not mark every file as newly added.
- Comparison requires two finished HAW-KI FileFinder collections with identical normalized parameters and artifact/dependency fingerprints. It rejects missing, duplicate, incomplete, differently scoped or oversized results. Disappearing from a scan is not labeled confirmed deletion. GUI collections remain readable, but are not automatically eligible for this stricter baseline comparison because HAW-KI did not record their definition fingerprints.
- Directory browsing reads saved `System.VFS.ListDirectory/Listing` results for the requested path. It searches the latest 100 directory collections and reports when that search is incomplete. It does not mirror every historical VFS cache node. New directory collection is a separate explicit operation.
- Lists and results are paginated. Export is labeled **표시 결과 내보내기** and contains only the displayed page, pagination state and native provenance. Raw acquired-file binaries remain downloadable in the native Velociraptor GUI; HAW-KI displays their upload metadata.
- Native GUI hunts are visible. HAW-KI creates fixed-target hunts paused, with a unique include label that is not assigned to endpoints, collects only the reviewed client IDs, and attaches those flows to the hunt. The native paused state prevents automatic enrollment of other hosts. Do not start or relabel these fixed-target hunts in the GUI if you want to retain their original scope. Full dynamic label-based hunt lifecycle remains in the native GUI.
- Every component uses a 300-second timeout, a 30% CPU target, an I/O target of 100 operations/second, at most 10,000 rows, and a transfer cap. These are throttles/limits, not a promise of zero endpoint impact. Acquisition is one exact path, nonrecursive, capped at 50 MiB. Other operations cap upload at 1 MiB and disable upload options. Hash/YARA presets also require a file-size cap.
- Up to two active components per endpoint and six globally are dispatched. Remaining components wait. Offline endpoint work can remain scheduled; the displayed check-in is not proof of current availability. The one-hour request expiry prevents new component submissions after expiry; it does not retroactively unschedule work already accepted by Velociraptor.
- A timed-out or interrupted submission becomes **접수 확인 필요**. It is never automatically resubmitted. Inspect the native GUI and the request history before creating a replacement request. There is no automated ambiguous-submission reconciliation in this release.
- A cancellation request is not reported as completed cancellation until the native flow reports it. Already finished work is not reversed. A request cancelled after it completed remains recorded as completed.
- Automatic quarantine, network restoration, process termination, persistence deletion, arbitrary shell/VQL, broad acquisition and continuous FIM were not added. The current source capture does not establish the endpoint recovery path or remediation prerequisites. The native GUI remains available for those operations; this package introduces no nonfunctional controls for them.

## Verification

Backend tests use the supplied authentication hooks and installed parameter schemas. They cover authentication, CSRF, roles, immutable requests, concurrent claims, idempotency, definition changes, ambiguous submission, cancellation, named sources, directory components, complete-baseline requirements, protobuf parameterization and bounded transport failures. Installer tests cover asset replacement and credential separation.

```bash
python -m pytest -q tests
node --test tests/ui-utils.test.mjs
```

The browser test uses a local test-only server and synthetic records. It is not copied into the deployed application or image:

```bash
PYTHONPATH=. python tests/browser_server.py
# In a second terminal with Playwright installed:
node tests/browser.test.cjs
```

Live API compatibility cannot be proved with local fixtures. The installer therefore runs `hawki_vr.preflight` against the existing read credential before restarting HAW-KI. Actual collection is verified separately by the first live check above. The package contains no API credentials, seeded production jobs or demo content.

## Technical references

- [Velociraptor API: environment parameters and asynchronous collection](https://docs.velociraptor.app/docs/server_automation/server_api/)
- [collect_client parameters and resource limits](https://docs.velociraptor.app/vql_reference/server/collect_client/)
- [Native hunt creation](https://docs.velociraptor.app/vql_reference/server/hunt/)
- [Attaching existing flows with hunt_add](https://docs.velociraptor.app/vql_reference/server/hunt_add/)
- [Named result sources and pagination](https://docs.velociraptor.app/vql_reference/server/source/)
- [Linux.Search.FileFinder definition](https://docs.velociraptor.app/artifact_references/pages/linux.search.filefinder/)
- [VFS cache and collection behavior](https://docs.velociraptor.app/docs/clients/vfs/)
- [CLI ACL changes and restart requirement](https://docs.velociraptor.app/docs/cli/commands/acl/)
