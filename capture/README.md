# capture/

Working directory for turning a packet capture into collected Suricata logs.

```
capture/
├── pcap/    put .pcap files here      (input,  read-only in the container)
└── out/     Suricata writes eve.json  (output, ingested from the host)
```

Neither directory is committed — captures can be large and may contain data
that does not belong in a repository.

## Use

Extract the archive first — the download is a password-protected zip, and the
password is on the source site's "about" page. Then place the `.pcap` itself:

```bash
cp ~/Downloads/2026-08-11-traffic.pcap capture/pcap/capture.pcap

docker compose run --rm suricata-update      # once: fetch ET Open rules
docker compose run --rm suricata             # replay -> capture/out/eve.json

python -m hawki_alert_analysis.ingest capture/out \
    --out data/scenarios/real_001 --host web-01
```

Replay a different file without renaming it:

```bash
PCAP_FILE=2026-08-11-traffic.pcap docker compose run --rm suricata
```

## If Suricata reports no alerts

Read its own output before assuming a rule problem:

```
Notice: pcap: read 0 files, 0 packets, 0 bytes
```

That means Suricata never saw the capture. The usual cause is that
`capture/pcap/capture.pcap` does not exist as a file — Docker creates a bind
mount target as an empty **directory** when the path is missing, and Suricata
then reports `Argument /capture/capture.pcap was a directory` and reads
nothing. Check it:

```bash
ls -l capture/pcap/          # capture.pcap must be a file, not a directory
```

If packets were read and alerts are still zero, the ruleset genuinely matched
nothing on that traffic — that is a finding about the capture, not a fault.

## Record where the capture came from

Suricata's output is only as trustworthy as its input. Keep a note of the
source and a checksum next to each capture, so a later reader can tell whether
two runs used the same evidence:

```bash
sha256sum capture/pcap/capture.pcap >> capture/pcap/SOURCES.txt
```
