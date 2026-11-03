#!/usr/bin/env bash
# =============================================================================
# dashboard-status.sh — health snapshot for the KVM-Sentinel-SOC lab.
#
# Checks, in this order:
#   session     tmux dashboard presence, window/pane count
#   libvirt     vm-honeypot / vm-soc power state, backend-isolated network
#   network     live-fire DNAT rules (needs root, skipped otherwise)
#   controller  approval daemon /health
#   edge        SSH banner on 10.10.0.10:2222 (the trap itself)
#   brain       loki /ready, grafana /api/health, ollama /api/tags
#   docker      compose service state on both guests (needs SSH)
#   ingress     promtail -> loki: are honeypot lines arriving?
#   webhook     controller audit trail (/incidents)
#   resources   free disk, free RAM, load average
#   logs        error-level lines in the last 200 lines of each dashboard log
#   reports     newest AI report age
#   demo        simulator image present on vm-honeypot
#
# Usage:
#   ./scripts/dashboard-status.sh                  one snapshot
#   ./scripts/dashboard-status.sh --watch 5        refresh every 5 s
#   ./scripts/dashboard-status.sh --compact        one line per section
#   ./scripts/dashboard-status.sh --json           machine-readable
#   ./scripts/dashboard-status.sh --section brain  only one section
#   ./scripts/dashboard-status.sh --append-log     append one line to status.log
#
# Exit status: 0 when no check FAILs, 1 otherwise. In --watch mode it never
# exits except on SIGINT/SIGTERM.
# =============================================================================
set -Eeuo pipefail
IFS=$'\n\t'

SCRIPT_DIR="$(cd -- "$(dirname -- "${BASH_SOURCE[0]}")" && pwd -P)"
REPO_ROOT="$(cd -- "$SCRIPT_DIR/.." && pwd -P)"
SELF="$SCRIPT_DIR/$(basename -- "${BASH_SOURCE[0]}")"

# --------------------------------------------------------------------------- #
# configuration (kept in sync with tmux-dashboard.sh; both read ./.env)
# --------------------------------------------------------------------------- #
init_config() {
  SESSION="${DASH_SESSION:-kvm-sentinel}"
  LOG_DIR="${DASH_LOG_DIR:-$REPO_ROOT/logs/tmux-dashboard}"
  CTRL_HOST="${DASH_CTRL_HOST:-192.168.122.1}"
  CTRL_PORT="${DASH_CTRL_PORT:-5000}"
  CTRL_URL="http://$CTRL_HOST:$CTRL_PORT"
  VM1_SSH_HOST="${DASH_VM1_HOST:-10.10.0.10}"
  VM1_SSH_PORT="${DASH_VM1_PORT:-22}"
  VM1_SSH_USER="${DASH_VM1_USER:-soc}"
  VM1_PASSWORD="${DASH_VM1_PASSWORD:-}"
  VM1_COMPOSE_DIR="${DASH_VM1_COMPOSE_DIR:-/opt/honeypot}"
  VM2_SSH_HOST="${DASH_VM2_HOST:-192.168.122.20}"
  VM2_SSH_PORT="${DASH_VM2_PORT:-22}"
  VM2_SSH_USER="${DASH_VM2_USER:-soc}"
  VM2_PASSWORD="${DASH_VM2_PASSWORD:-}"
  VM2_COMPOSE_DIR="${DASH_VM2_COMPOSE_DIR:-/opt/soc}"
  SSH_KEY="${DASH_SSH_KEY:-}"
  LOKI_URL="${DASH_LOKI_URL:-http://192.168.122.20:3100}"
  GRAFANA_URL="${DASH_GRAFANA_URL:-http://192.168.122.20:3000}"
  OLLAMA_URL="${DASH_OLLAMA_URL:-http://192.168.122.20:11434}"
  TRAP_ADDR="${DASH_TRAP_ADDR:-10.10.0.10:2222}"
  TRAP_HOST="${TRAP_ADDR%:*}"
  TRAP_PORT="${TRAP_ADDR##*:}"

  if [[ -n ${NO_COLOR:-} ]]; then
    C_RESET=""; C_BOLD=""; C_INFO=""; C_OK=""; C_WARN=""; C_ERR=""; C_SKIP=""
  else
    C_RESET=$'\033[0m'; C_BOLD=$'\033[1m'; C_INFO=$'\033[1;34m'
    C_OK=$'\033[1;32m'; C_WARN=$'\033[1;33m'; C_ERR=$'\033[1;31m'; C_SKIP=$'\033[1;90m'
  fi
}

ts() { date -u '+%Y-%m-%dT%H:%M:%SZ'; }
have() { command -v "$1" >/dev/null 2>&1; }

load_env() {
  local file="$REPO_ROOT/.env" line key value
  [[ -r "$file" ]] || return 0
  while IFS= read -r line || [[ -n "$line" ]]; do
    [[ "$line" =~ ^[[:space:]]*(#|$) ]] && continue
    if [[ "$line" =~ ^[[:space:]]*(export[[:space:]]+)?([A-Za-z_][A-Za-z0-9_]*)=(.*)$ ]]; then
      key="${BASH_REMATCH[2]}"; value="${BASH_REMATCH[3]}"
      value="${value%\"}"; value="${value#\"}"; value="${value%\'}"; value="${value#\'}"
      if [[ -z ${!key+x} ]]; then printf -v "$key" '%s' "$value"; export "$key"; fi
    fi
  done <"$file"
}

# --------------------------------------------------------------------------- #
# row bookkeeping
# --------------------------------------------------------------------------- #
ROWS=()
OKS=0
WARNS=0
FAILS=0

add_row() { # section state name detail
  ROWS+=("$1"$'\t'"$2"$'\t'"$3"$'\t'"$4")
  case "$2" in
    OK) OKS=$((OKS + 1)) ;;
    WARN) WARNS=$((WARNS + 1)) ;;
    FAIL) FAILS=$((FAILS + 1)) ;;
  esac
}

state_color() {
  case "$1" in
    OK) printf '%s' "$C_OK" ;;
    WARN) printf '%s' "$C_WARN" ;;
    FAIL) printf '%s' "$C_ERR" ;;
    *) printf '%s' "$C_SKIP" ;;
  esac
}

# --------------------------------------------------------------------------- #
# probes
# --------------------------------------------------------------------------- #
tcp_open() {
  timeout 3 bash -c 'exec 3<>/dev/tcp/"$1"/"$2"' _ "$1" "$2" 2>/dev/null
}

tcp_banner() {
  timeout 5 bash -c '
    exec 3<>/dev/tcp/"$1"/"$2" || exit 1
    IFS= read -r -t 3 line <&3 || exit 1
    printf "%s" "$line"
  ' _ "$1" "$2" 2>/dev/null
}

proc_starttime() {
  [[ -r "/proc/$1/stat" ]] || return 1
  sed 's/^.*) //' "/proc/$1/stat" | awk '{print $20}'
}

build_ssh() {
  local node="$1" host port user password
  case "$node" in
    vm1) host="$VM1_SSH_HOST"; port="$VM1_SSH_PORT"; user="$VM1_SSH_USER"; password="$VM1_PASSWORD" ;;
    vm2) host="$VM2_SSH_HOST"; port="$VM2_SSH_PORT"; user="$VM2_SSH_USER"; password="$VM2_PASSWORD" ;;
    *) return 1 ;;
  esac
  local -a opts=(-o ConnectTimeout=5 -o ServerAliveInterval=15 -o StrictHostKeyChecking=accept-new
                 -o LogLevel=ERROR)
  if [[ -n "$SSH_KEY" ]]; then
    opts+=(-i "$SSH_KEY")
  fi
  if [[ -n "$password" ]] && have sshpass; then
    SSH_ARGV=(sshpass -p "$password" ssh "${opts[@]}" -p "$port" "$user@$host")
  else
    SSH_ARGV=(ssh "${opts[@]}" -o BatchMode=yes -p "$port" "$user@$host")
  fi
}

ssh_reachable() {
  case "$1" in
    vm1) tcp_open "$VM1_SSH_HOST" "$VM1_SSH_PORT" ;;
    vm2) tcp_open "$VM2_SSH_HOST" "$VM2_SSH_PORT" ;;
    *) return 1 ;;
  esac
}

remote_compose() {
  local node="$1" dir sub
  local IFS=' '
  shift
  if [[ "$node" == vm1 ]]; then dir="$VM1_COMPOSE_DIR"; else dir="$VM2_COMPOSE_DIR"; fi
  sub="docker compose $*"
  printf 'cd %q && { sudo -n %s 2>/dev/null || %s; }' "$dir" "$sub" "$sub"
}

net_active() {
  # || true: with pipefail a missing network would otherwise abort the script.
  virsh -c qemu:///system net-info "$1" 2>/dev/null \
    | awk -F': *' '/^Active:/{print $2}' || true
}

# --------------------------------------------------------------------------- #
# checks
# --------------------------------------------------------------------------- #
check_session() {
  if ! have tmux; then
    add_row session SKIP session "tmux not installed"
    return
  fi
  if tmux has-session -t "=$SESSION" 2>/dev/null; then
    local windows panes
    windows="$(tmux list-windows -t "=$SESSION" -F x | wc -l | tr -d ' ')"
    panes="$(tmux list-panes -s -t "=$SESSION" -F x | wc -l | tr -d ' ')"
    add_row session OK session "$windows windows / $panes panes"
  else
    add_row session WARN session "not running (./scripts/tmux-dashboard.sh)"
  fi
}

check_libvirt() {
  if ! have virsh; then
    add_row libvirt SKIP virsh "virsh not installed"
    return
  fi
  local dom state net
  for dom in vm-honeypot vm-soc; do
    state="$(virsh -c qemu:///system domstate "$dom" 2>/dev/null | tr -d '\r\n' || true)"
    state="${state:-undefined}"
    case "$state" in
      running) add_row libvirt OK "$dom" "running" ;;
      undefined|"") add_row libvirt FAIL "$dom" "not defined (run deploy-lab.sh)" ;;
      *) add_row libvirt FAIL "$dom" "$state" ;;
    esac
  done
  for net in backend-isolated default; do
    state="$(net_active "$net")"
    case "$state" in
      yes) add_row libvirt OK "net:$net" "active" ;;
      "") add_row libvirt FAIL "net:$net" "not defined" ;;
      *) add_row libvirt FAIL "net:$net" "inactive" ;;
    esac
  done
}

check_network() {
  if ! have iptables; then
    add_row network SKIP live-fire "iptables not installed"
    return
  fi
  if [[ ${EUID} -ne 0 ]] && ! sudo -n true 2>/dev/null; then
    add_row network SKIP live-fire "needs root (sudo iptables -t nat -S)"
    return
  fi
  local rules
  rules="$(iptables -t nat -S 2>/dev/null | grep -c -- 'kvm-sentinel-livefire' || true)"
  if ((rules >= 3)); then
    add_row network OK live-fire "$rules DNAT/MASQUERADE rules present"
  elif ((rules > 0)); then
    add_row network WARN live-fire "only $rules rule(s): partial live-fire"
  else
    add_row network WARN live-fire "not published (classroom mode off)"
  fi
}

check_controller() {
  local body detail
  if body="$(curl -fsS --max-time 3 "$CTRL_URL/health" 2>/dev/null)"; then
    detail="$(printf '%s' "$body" | python3 -c 'import sys, json
d = json.load(sys.stdin)
print("uptime={}s pending={} domain_running={} dry_run={}".format(
    d.get("uptime_seconds"), d.get("pending"), d.get("domain_running"), d.get("dry_run")))' 2>/dev/null || echo "unparseable /health")"
    add_row controller OK health "$detail"
  else
    add_row controller FAIL health "no answer on $CTRL_URL/health"
  fi
}

check_edge() {
  local banner
  if banner="$(tcp_banner "$TRAP_HOST" "$TRAP_PORT")" && [[ -n "$banner" ]]; then
    add_row edge OK trap "$TRAP_ADDR -> ${banner:0:44}"
  else
    add_row edge FAIL trap "$TRAP_ADDR unreachable (honeypot down?)"
  fi
}

check_brain() {
  local code detail
  code="$(curl -s -o /dev/null -w '%{http_code}' --max-time 3 "$LOKI_URL/ready" 2>/dev/null || true)"
  code="${code:-000}"
  if [[ "$code" == "200" ]]; then
    add_row brain OK loki "/ready 200"
  else
    add_row brain FAIL loki "/ready returned $code"
  fi

  if detail="$(curl -fsS --max-time 3 "$GRAFANA_URL/api/health" 2>/dev/null \
      | python3 -c 'import sys, json
d = json.load(sys.stdin)
print("database={} version={}".format(d.get("database"), d.get("version")))' 2>/dev/null)"; then
    add_row brain OK grafana "$detail"
  else
    add_row brain FAIL grafana "no answer on $GRAFANA_URL/api/health"
  fi

  if detail="$(curl -fsS --max-time 5 "$OLLAMA_URL/api/tags" 2>/dev/null \
      | python3 -c 'import sys, json
d = json.load(sys.stdin)
m = d.get("models") or []
print("{} model(s): {}".format(len(m), ", ".join(x.get("name", "?") for x in m[:3])))' 2>/dev/null)"; then
    add_row brain OK ollama "$detail"
  else
    add_row brain FAIL ollama "no answer on $OLLAMA_URL/api/tags"
  fi
}

check_docker() {
  local node out
  for node in vm1 vm2; do
    if ! ssh_reachable "$node"; then
      add_row docker SKIP "$node" "ssh unreachable"
      continue
    fi
    build_ssh "$node"
    if ! out="$(timeout 25 "${SSH_ARGV[@]}" "$(remote_compose "$node" ps --format json)" 2>/dev/null)"; then
      add_row docker FAIL "$node" "compose ps failed (stack down?)"
      continue
    fi
    local detail
    detail="$(printf '%s\n' "$out" | python3 -c 'import sys, json
rows = []
for line in sys.stdin:
    line = line.strip()
    if not line:
        continue
    try:
        rows.append(json.loads(line))
    except ValueError:
        pass
running = sum(1 for r in rows if (r.get("State") or "").lower() == "running")
healthy = sum(1 for r in rows if "healthy" in (r.get("Status") or ""))
print("{} {} {}".format(len(rows), running, healthy))' 2>/dev/null || echo "0 0 0")"
    local total running healthy
    IFS=' ' read -r total running healthy <<<"$detail"
    if ((total == 0)); then
      add_row docker WARN "$node" "no services reported"
    elif ((running == total)); then
      add_row docker OK "$node" "$running/$total running, $healthy healthy"
    else
      add_row docker WARN "$node" "$running/$total running, $healthy healthy"
    fi
  done
}

check_ingress() {
  local start out detail
  start="$(date -u -d '5 minutes ago' +%s)000000000"
  if out="$(curl -fsS --max-time 6 -G "$LOKI_URL/loki/api/v1/query_range" \
      --data-urlencode 'query={job="ssh-honeypot"}' \
      --data-urlencode "start=$start" \
      --data-urlencode 'limit=5' 2>/dev/null)"; then
    detail="$(printf '%s' "$out" | python3 -c 'import sys, json
d = json.load(sys.stdin)
res = (d.get("data") or {}).get("result") or []
n = sum(len(s.get("values") or []) for s in res)
last = ""
for s in res:
    vals = s.get("values") or []
    if vals:
        last = vals[0][1][:90]
        break
print("{} {} {}".format(n, len(res), last.replace("\t", " ")))' 2>/dev/null || echo "0 0 -")"
    local lines streams last
    IFS=' ' read -r lines streams last <<<"$detail"
    if ((lines > 0)); then
      add_row ingress OK promtail-loki "$lines line(s) / $streams stream(s): ${last:0:60}"
    else
      add_row ingress WARN promtail-loki "no honeypot lines in the last 5 min"
    fi
  else
    add_row ingress FAIL promtail-loki "loki query failed ($LOKI_URL)"
  fi
}

check_webhook() {
  local body detail
  if body="$(curl -fsS --max-time 3 "$CTRL_URL/incidents" 2>/dev/null)"; then
    detail="$(printf '%s' "$body" | python3 -c 'import sys, json
d = json.load(sys.stdin)
items = d.get("incidents") or []
last = items[-1] if items else {}
print("{} decision(s); last={} {} {}".format(
    len(items), last.get("decision", "none"), last.get("attacker_ip", ""), last.get("decided_at", "")))' 2>/dev/null || echo "unparseable /incidents")"
    add_row webhook OK audit "$detail"
  else
    add_row webhook FAIL audit "no answer on $CTRL_URL/incidents"
  fi
}

check_resources() {
  local avail_kb pct avail_gib mem_mib load
  avail_kb="$(df -Pk "$REPO_ROOT" | awk 'NR==2 {print $4}')"
  pct="$(df -Pk "$REPO_ROOT" | awk 'NR==2 {print $5}' | tr -d '%')"
  avail_gib=$((avail_kb / 1024 / 1024))
  if ((avail_gib < 5)); then
    add_row resources FAIL disk "${avail_gib} GiB free (${pct}% used)"
  elif ((avail_gib < 12)); then
    add_row resources WARN disk "${avail_gib} GiB free (${pct}% used)"
  else
    add_row resources OK disk "${avail_gib} GiB free (${pct}% used)"
  fi

  mem_mib="$(awk '/^MemAvailable:/ {printf "%d", $2 / 1024}' /proc/meminfo)"
  if ((mem_mib < 1024)); then
    add_row resources FAIL ram "${mem_mib} MiB available"
  elif ((mem_mib < 2560)); then
    add_row resources WARN ram "${mem_mib} MiB available"
  else
    add_row resources OK ram "${mem_mib} MiB available"
  fi

  load="$(awk '{print $1}' /proc/loadavg)"
  add_row resources OK load "1-minute load $load"
}

check_logs() {
  local f n total=0 files=0 worst=""
  shopt -s nullglob
  for f in "$LOG_DIR"/*.log; do
    [[ -f "$f" ]] || continue
    files=$((files + 1))
    n="$(tail -n 200 -- "$f" 2>/dev/null | grep -cEi 'error|critical|traceback|panic|fatal' || true)"
    if ((n > 0)); then
      total=$((total + n))
      [[ -z "$worst" ]] && worst="$(basename -- "$f"): $n"
    fi
  done
  shopt -u nullglob
  if ((files == 0)); then
    add_row logs WARN recent-errors "no dashboard logs yet (start the dashboard)"
  elif ((total > 0)); then
    add_row logs WARN recent-errors "$total match(es) in last 200 lines (first: $worst)"
  else
    add_row logs OK recent-errors "clean across $files log file(s)"
  fi
}

check_reports() {
  local dir="$REPO_ROOT/vm2-soc/reports" newest epoch now age_h
  if [[ ! -d "$dir" ]]; then
    add_row reports SKIP reports "no vm2-soc/reports directory"
    return
  fi
  newest="$(find "$dir" -maxdepth 1 -type f \( -name '*.md' -o -name '*.json' \) -printf '%T@ %p\n' 2>/dev/null | sort -rn | head -1 || true)"
  if [[ -z "$newest" ]]; then
    add_row reports WARN reports "no AI report generated yet"
    return
  fi
  epoch="${newest%%.*}"
  now="$(date +%s)"
  age_h=$(((now - epoch) / 3600))
  add_row reports OK reports "newest $(basename -- "${newest#* }"), ${age_h}h old"
}

check_demo() {
  if ! ssh_reachable vm1; then
    add_row demo SKIP simulator "vm1 unreachable"
    return
  fi
  build_ssh vm1
  local out
  out="$(timeout 20 "${SSH_ARGV[@]}" \
    'sudo -n docker image inspect kvm-sentinel/simulator:1.0.0 >/dev/null 2>&1 && echo present || echo absent' 2>/dev/null || echo unknown)"
  case "$out" in
    present) add_row demo OK simulator "image built (manual run only)" ;;
    absent) add_row demo WARN simulator "image not built yet" ;;
    *) add_row demo SKIP simulator "cannot query docker" ;;
  esac
}

run_section() {
  case "$1" in
    session) check_session ;;
    libvirt) check_libvirt ;;
    network) check_network ;;
    controller) check_controller ;;
    edge) check_edge ;;
    brain) check_brain ;;
    docker) check_docker ;;
    ingress) check_ingress ;;
    webhook) check_webhook ;;
    resources) check_resources ;;
    logs) check_logs ;;
    reports) check_reports ;;
    demo) check_demo ;;
    all)
      check_session; check_libvirt; check_network; check_controller
      check_edge; check_brain; check_docker; check_ingress
      check_webhook; check_resources; check_logs; check_reports; check_demo
      ;;
    *) printf 'unknown section: %s\n' "$1" >&2; exit 2 ;;
  esac
}

# --------------------------------------------------------------------------- #
# rendering
# --------------------------------------------------------------------------- #
render_table() {
  local row section state name detail current=""
  if ((${#ROWS[@]} == 0)); then
    printf 'no checks ran\n'
    return
  fi
  for row in "${ROWS[@]}"; do
    IFS=$'\t' read -r section state name detail <<<"$row"
    if [[ "$section" != "$current" ]]; then
      printf '\n%s%s%s\n' "$C_BOLD" "${section^^}" "$C_RESET"
      current="$section"
    fi
    printf '  %s%-4s%s %-24s %s\n' "$(state_color "$state")" "$state" "$C_RESET" "$name" "$detail"
  done
  printf '\n%sSummary%s %d OK, %d WARN, %d FAIL  (%s)\n' \
    "$C_BOLD" "$C_RESET" "$OKS" "$WARNS" "$FAILS" "$(ts)"
}

render_compact() {
  local row section state name detail
  local -A worst=() detail_for=() count=()
  local -a order=()
  for row in "${ROWS[@]}"; do
    IFS=$'\t' read -r section state name detail <<<"$row"
    if [[ -z ${worst[$section]+x} ]]; then
      order+=("$section")
      worst[$section]="$state"
      detail_for[$section]="$name: $detail"
      count[$section]=0
    fi
    count[$section]=$((count[$section] + 1))
    # Rank OK < SKIP < WARN < FAIL; the compact line shows the worst check.
    case "$state" in
      FAIL)
        if [[ ${worst[$section]} != "FAIL" ]]; then
          worst[$section]="FAIL"; detail_for[$section]="$name: $detail"
        fi
        ;;
      WARN)
        if [[ ${worst[$section]} != "FAIL" && ${worst[$section]} != "WARN" ]]; then
          worst[$section]="WARN"; detail_for[$section]="$name: $detail"
        fi
        ;;
      SKIP)
        if [[ ${worst[$section]} == "OK" ]]; then
          worst[$section]="SKIP"; detail_for[$section]="$name: $detail"
        fi
        ;;
    esac
  done
  local key
  for key in "${order[@]}"; do
    printf '%s%-4s%s %-12s %s\n' "$(state_color "${worst[$key]}")" "${worst[$key]}" "$C_RESET" \
      "$key" "${detail_for[$key]}"
  done
  printf '%s%d OK / %d WARN / %d FAIL%s\n' "$C_BOLD" "$OKS" "$WARNS" "$FAILS" "$C_RESET"
}

render_json() {
  printf '%s\n' "${ROWS[@]}" | python3 -c 'import sys, json, datetime
rows = []
for line in sys.stdin:
    line = line.rstrip("\n")
    if not line:
        continue
    parts = line.split("\t", 3)
    while len(parts) < 4:
        parts.append("")
    rows.append({"section": parts[0], "state": parts[1], "name": parts[2], "detail": parts[3]})
payload = {
    "generated_at": datetime.datetime.now(datetime.timezone.utc).strftime("%Y-%m-%dT%H:%M:%SZ"),
    "summary": {"ok": int(sys.argv[1]), "warn": int(sys.argv[2]), "fail": int(sys.argv[3])},
    "checks": rows,
}
json.dump(payload, sys.stdout, indent=2)
print()' "$OKS" "$WARNS" "$FAILS"
}

append_log() {
  local worst="OK" first_fail=""
  if ((FAILS > 0)); then
    worst="FAIL"
    local row section state name detail
    for row in "${ROWS[@]}"; do
      IFS=$'\t' read -r section state name detail <<<"$row"
      if [[ "$state" == "FAIL" ]]; then first_fail="$section/$name: $detail"; break; fi
    done
  elif ((WARNS > 0)); then
    worst="WARN"
  fi
  printf '%s\t%s\tok=%d\twarn=%d\tfail=%d\t%s\n' \
    "$(ts)" "$worst" "$OKS" "$WARNS" "$FAILS" "$first_fail" >>"$LOG_DIR/status.log"
}

# --------------------------------------------------------------------------- #
# main
# --------------------------------------------------------------------------- #
SECTION="all"
WATCH=0
WATCH_INTERVAL=5
COMPACT=0
JSON=0
APPEND_LOG=0
CLEAR=1

usage() {
  sed -n '3,26p' "$SELF" | sed 's/^# \{0,1\}//'
}

parse_args() {
  while (($#)); do
    case "$1" in
      --section) SECTION="${2:?--section needs a name}"; shift 2 ;;
      --watch)
        WATCH=1; shift
        if [[ "${1:-}" =~ ^[0-9]+$ ]]; then WATCH_INTERVAL="$1"; shift; fi
        ;;
      --compact) COMPACT=1; shift ;;
      --json) JSON=1; shift ;;
      --append-log) APPEND_LOG=1; shift ;;
      --no-clear) CLEAR=0; shift ;;
      --no-color) export NO_COLOR=1; shift ;;
      --help|-h) usage; exit 0 ;;
      *) printf 'unknown option: %s\n' "$1" >&2; exit 2 ;;
    esac
  done
}

cycle() {
  ROWS=(); OKS=0; WARNS=0; FAILS=0
  run_section "$SECTION"
}

main() {
  parse_args "$@"
  load_env
  init_config

  if ((WATCH)); then
    trap 'exit 0' INT TERM
    while :; do
      cycle
      if ((CLEAR)); then clear; fi
      if ((JSON)); then render_json; elif ((COMPACT)); then render_compact; else render_table; fi
      if ((APPEND_LOG)); then append_log; fi
      sleep "$WATCH_INTERVAL"
    done
  fi

  cycle
  if ((JSON)); then render_json; elif ((COMPACT)); then render_compact; else render_table; fi
  if ((APPEND_LOG)); then append_log; fi
  if ((FAILS > 0)); then exit 1; fi
  exit 0
}

main "$@"
