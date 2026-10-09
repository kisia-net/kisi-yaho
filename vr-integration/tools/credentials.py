#!/usr/bin/env python3
"""Private-key material is never printed. Run only on the named server."""
import argparse
import hashlib
import os
import re
import socket
import subprocess
import tempfile
from datetime import datetime,timezone
from pathlib import Path

RECEIVER=Path("/opt/hawki/secrets/vr-transfer")
DEST=Path("/opt/hawki/secrets/velociraptor-execution/api.yaml")


def command(args,**kw):
    result=subprocess.run(args,capture_output=True,**kw)
    if result.returncode:raise SystemExit("Command failed: "+args[0]+" (exit "+str(result.returncode)+")")
    return result.stdout


def require_host(ip):
    addresses=command(["hostname","-I"]).decode().split()
    if ip not in addresses:raise SystemExit("Run this step on host "+ip)


def receiver():
    require_host("10.0.10.176")
    RECEIVER.mkdir(parents=True,exist_ok=True,mode=0o700);os.chmod(RECEIVER,0o700)
    key=RECEIVER/"receiver.key";cert=RECEIVER/"receiver.crt"
    if key.exists() != cert.exists():raise SystemExit("Incomplete transfer pair; inspect the receiver directory")
    if not key.exists():
        command(["openssl","req","-x509","-newkey","rsa:3072","-nodes","-days","7","-subj","/CN=HAWKI-VR-Execution-Transfer","-keyout",str(key),"-out",str(cert)])
    print(command(["openssl","x509","-in",str(cert),"-noout","-fingerprint","-sha256"]).decode().strip())
    print(cert.read_text(),end="")


def sender(cert_path):
    require_host("10.0.10.212")
    if not cert_path.is_file():raise SystemExit("Recipient public certificate is required")
    # Validate the public recipient before creating any new identity.
    command(["openssl","x509","-in",str(cert_path),"-noout","-checkend","0"])
    binary="/usr/local/bin/velociraptor";cfg="/etc/velociraptor/server.config.yaml"
    keyfile=Path("/etc/velociraptor/hawki-collector.api.yaml")
    if not keyfile.exists():
        name="hawki-collector-"+datetime.now(timezone.utc).strftime("%Y%m%dT%H%M%S%fZ")
        with tempfile.TemporaryDirectory(prefix="hawki-exec-",dir="/opt/velociraptor") as temp:
            import pwd
            user=pwd.getpwnam("velociraptor");os.chown(temp,user.pw_uid,user.pw_gid)
            staged=Path(temp)/"api.yaml"
            base=["runuser","-u","velociraptor","--",binary,"--config",cfg]
            command(base+["config","api_client","--name",name,"--role","api",str(staged)])
            command(base+["acl","grant",name,'{"any_query":true,"read_results":true,"collect_client":true,"start_hunt":true}'])
            data=staged.read_bytes()
            data,count=re.subn(rb"(?m)^api_connection_string:.*$",b"api_connection_string: 10.0.10.212:8001",data)
            if count!=1:raise SystemExit("Unexpected API connection format")
            with keyfile.open("xb") as f:f.write(data)
            os.chmod(keyfile,0o600)
        command(["systemctl","restart","velociraptor_server.service"])
        command(["systemctl","is-active","--quiet","velociraptor_server.service"])
    else:
        data=keyfile.read_bytes()
    encrypted=command(["openssl","cms","-encrypt","-binary","-aes-256-gcm","-outform","PEM","-recip",str(cert_path),"-keyopt","rsa_padding_mode:oaep","-keyopt","rsa_oaep_md:sha256"],input=data)
    print("Credential SHA-256:",hashlib.sha256(data).hexdigest())
    print(encrypted.decode(),end="")


def receive(cms,expected):
    require_host("10.0.10.176")
    if not re.fullmatch(r"[0-9a-f]{64}",expected):raise SystemExit("A SHA-256 digest is required")
    data=command(["openssl","cms","-decrypt","-binary","-inform","PEM","-in",str(cms),"-recip",str(RECEIVER/"receiver.crt"),"-inkey",str(RECEIVER/"receiver.key")])
    if hashlib.sha256(data).hexdigest()!=expected:raise SystemExit("Credential digest mismatch; nothing installed")
    if b"client_private_key:" not in data or b"api_connection_string: 10.0.10.212:8001" not in data:
        raise SystemExit("Unexpected credential format; nothing installed")
    DEST.parent.mkdir(parents=True,exist_ok=True)
    if DEST.exists():
        if DEST.read_bytes()==data:print("The same credential is already installed.");return
        raise SystemExit("A different execution credential already exists; no overwrite performed")
    os.chown(DEST.parent,0,999);os.chmod(DEST.parent,0o750)
    temporary=DEST.with_suffix(".new")
    with temporary.open("xb") as f:f.write(data)
    os.chown(temporary,0,999);os.chmod(temporary,0o640);temporary.replace(DEST)
    print("Execution credential installed for the dispatcher.")


def main():
    if os.geteuid()!=0:raise SystemExit("Run with sudo")
    os.umask(0o077)
    parser=argparse.ArgumentParser()
    sub=parser.add_subparsers(dest="action",required=True)
    sub.add_parser("receiver")
    send=sub.add_parser("sender");send.add_argument("--cert",type=Path,required=True)
    get=sub.add_parser("receive");get.add_argument("--cms",type=Path,required=True);get.add_argument("--sha256",required=True)
    args=parser.parse_args()
    if args.action=="receiver":receiver()
    elif args.action=="sender":sender(args.cert)
    else:receive(args.cms,args.sha256)


if __name__=="__main__":main()
