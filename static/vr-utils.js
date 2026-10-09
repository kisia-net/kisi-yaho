export function escape(value) {
  return String(value ?? "").replace(/[&<>"']/g, c => ({"&":"&amp;","<":"&lt;",">":"&gt;",'"':"&quot;","'":"&#39;"}[c]));
}
export function formatTime(value) {
  if (value === null || value === undefined || value === "" || value === 0 || value === "0") return "—";
  let v = value;
  if (typeof v === "number" || /^\d{10,19}$/.test(String(v))) {
    const n = Number(v);
    v = n >= 1e17 ? n / 1e6 : n >= 1e14 ? n / 1000 : n >= 1e11 ? n : n * 1000;
  }
  const d = new Date(v);
  return Number.isNaN(d.getTime()) ? "—" : new Intl.DateTimeFormat("ko-KR", {dateStyle:"short", timeStyle:"medium", hour12:false}).format(d);
}
export function valueAt(row, keys) {
  for (const key of keys) {
    let v = row;
    for (const part of key.split(".")) v = v?.[part];
    if (v !== null && v !== undefined && v !== "") return v;
  }
  return null;
}
export function printable(value) {
  if (value === null || value === undefined || value === "") return "—";
  return typeof value === "object" ? JSON.stringify(value) : String(value);
}
export function pathOf(row) {
  const p = valueAt(row,["OSPath","FullPath","Path","_OSPath"]);
  if (typeof p === "string") return p;
  if (p && typeof p.Path === "string") return p.Path;
  // Only absolute paths can become a collection target.
  if (p?.Components && Array.isArray(p.Components)) return "/" + p.Components.join("/");
  return "";
}
export function bytes(v) {
  if (v === null || v === undefined || !Number.isFinite(Number(v))) return "—";
  const n=Number(v);
  if (n < 1024) return n+" B";
  if (n < 1048576) return (n/1024).toFixed(1)+" KiB";
  return (n/1048576).toFixed(1)+" MiB";
}
export const states = {draft:"검토 중",pending_approval:"승인 대기",queued:"대기",active:"수집 중",submitting:"요청 중",submitted:"서버 접수",finished:"완료",failed:"실패",partial:"일부 완료",rejected:"반려",cancelled:"취소됨",cancel_requested:"취소 요청됨",expired:"만료",submission_unknown:"접수 확인 필요",FINISHED:"완료",RUNNING:"실행 중",WAITING:"대기",ERROR:"실패",CANCELLED:"취소됨",PAUSED:"일시 정지",STOPPED:"정지",1:"정지",2:"실행 중",3:"일시 정지",4:"아카이브"};
export function badge(state) {
  const key=String(state ?? "");
  const tone=["finished","FINISHED"].includes(key)?"good":["failed","ERROR","partial","submission_unknown"].includes(key)?"bad":"wait";
  return `<span class="vr-badge ${tone}">${escape(states[key] || key || "미확인")}</span>`;
}
export function columns(artifact, rows) {
  if (/FileFinder|HashHunter|Yara.Glob|VFS\./.test(artifact)) return [
    ["경로",r=>pathOf(r) || valueAt(r,["Name","Filename"])],
    ["크기",r=>bytes(valueAt(r,["Size","size"]))],
    ["수정 시각",r=>formatTime(valueAt(r,["MTime","Mtime","mtime"]))],
    ["메타데이터 변경",r=>formatTime(valueAt(r,["CTime","Ctime","ctime"]))],
    ["권한",r=>valueAt(r,["Mode.String","Mode"])],
    ["SHA-256 / 일치",r=>valueAt(r,["Hash.SHA256","Hash.sha256","SHA256","Rule","RuleName"])],
  ];
  if (/Pslist/.test(artifact)) return [["PID",r=>valueAt(r,["Pid","PID"])],["상위 PID",r=>valueAt(r,["Ppid","PPID"])],["프로세스",r=>valueAt(r,["Name","Exe","Executable"])],["명령행",r=>valueAt(r,["CommandLine","Cmdline","Command"])],["사용자",r=>valueAt(r,["Username","User","Uid"])],["시작 시각",r=>formatTime(valueAt(r,["CreateTime","StartTime"]))]];
  if (/Netstat/.test(artifact)) return [["프로세스",r=>valueAt(r,["ProcessName","Name","Pid","PID"])],["로컬",r=>valueAt(r,["Laddr","LocalAddress","Laddr.IP"])],["원격",r=>valueAt(r,["Raddr","RemoteAddress","Raddr.IP"])],["상태",r=>valueAt(r,["Status","State"])],["명령행",r=>valueAt(r,["CommandLine","ProcessCommandLine","Cmdline"])]];
  // Unknown/custom artifact fields remain fully accessible, including nested
  // values. The complete original record is always in the detail view/export.
  const keys=[...new Set(rows.flatMap(r=>Object.keys(r)))];
  const primary=keys.filter(k=>!k.startsWith("_") && !["Data","_Accessor","_OSPath"].includes(k)).slice(0,7);
  return (primary.length?primary:keys.slice(0,7)).map(k=>[k,r=>/^(time|timestamp|create_time|last_seen_at)$/i.test(k)?formatTime(r[k]):r[k]]);
}
