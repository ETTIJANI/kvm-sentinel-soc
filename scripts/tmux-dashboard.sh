#!/usr/bin/env bash
# =============================================================================
# tmux-dashboard.sh — single-command operations console for KVM-Sentinel-SOC.
#
# WHAT IT DOES
#   * validates the host tooling and the lab layout
#   * optionally starts the libvirt networks and domains
#   * bootstraps both Docker Compose stacks over SSH
#   * builds one tmux session with one window per functional area
#   * streams every long-running process to ./logs/tmux-dashboard/ while keeping
#     the live console visible in its pane
#   * reattaches instead of duplicating when the session already exists
#
# LAYOUT (session: kvm-sentinel)
#   core         controller console + controller health
#   edge         honeypot logs, promtail logs, live trap probe
#   brain        agents, loki, grafana, ollama logs (2x2)
#   infra        libvirt state, live-fire rules, host resources
#   integrations promtail->loki ingress probe, controller incidents
#   logs         merged tail of every dashboard log, error-only tail
#   health       full dashboard-status.sh watch
#   shell        interactive shell (transcript via pipe-pane)
#   dashboard    compact status + live pane map
#
# USAGE
#   ./scripts/tmux-dashboard.sh                 create or attach
#   ./scripts/tmux-dashboard.sh --status        health/status snapshot
#   ./scripts/tmux-dashboard.sh --logs          focus the logs window
#   ./scripts/tmux-dashboard.sh --stop          stop the dashboard
#   ./scripts/tmux-dashboard.sh --restart       stop, then create
#   ./scripts/tmux-dashboard.sh --no-attach     build without attaching
#   ./scripts/tmux-dashboard.sh --skip-stacks   do not run compose up
#   ./scripts/tmux-dashboard.sh --start-vms     start libvirt domains first
#   ./scripts/tmux-dashboard.sh --help
#
# CONFIGURATION
#   Environment first, then ./.env (the environment wins). See .env.example.
#
# LOGS
#   logs/tmux-dashboard/<component>.log     stdout+stderr of each component
#   logs/tmux-dashboard/bootstrap.log       compose up output
#   logs/tmux-dashboard/status.log          one line per health cycle
#   logs/tmux-dashboard/shell-session.log   interactive shell transcript
#   logs/tmux-dashboard/run/<session>/pids/ PID + start time, used by --stop
#
# The dashboard never generates attacks: the simulator stays a manual command,
# printed as a hint in the shell window.
# =============================================================================
set -Eeuo pipefail
IFS=$'\n\t'

SCRIPT_DIR="$(cd -- "$(dirname -- "${BASH_SOURCE[0]}")" && pwd -P)"
REPO_ROOT="$(cd -- "$SCRIPT_DIR/.." && pwd -P)"
SELF="$SCRIPT_DIR/$(basename -- "${BASH_SOURCE[0]}")"
STATUS_SCRIPT="$SCRIPT_DIR/dashboard-status.sh"
STOP_SCRIPT="$SCRIPT_DIR/tmux-dashboard-stop.sh"

# --------------------------------------------------------------------------- #
# configuration (environment > .env > defaults)
# --------------------------------------------------------------------------- #
init_config() {
  SESSION="${DASH_SESSION:-kvm-sentinel}"
  LOG_DIR="${DASH_LOG_DIR:-$REPO_ROOT/logs/tmux-dashboard}"
  RUN_DIR="${DASH_RUN_DIR:-$LOG_DIR/run/$SESSION}"
  PID_DIR="$RUN_DIR/pids"

  CTRL_HOST="${DASH_CTRL_HOST:-192.168.122.1}"
  CTRL_PORT="${DASH_CTRL_PORT:-5000}"
  CTRL_URL="http://$CTRL_HOST:$CTRL_PORT"
  CTRL_AUDIT="${DASH_CTRL_AUDIT:-$REPO_ROOT/host/controller/state/incidents.jsonl}"

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

  READY_TIMEOUT="${DASH_READY_TIMEOUT:-180}"
  STACK_TIMEOUT="${DASH_STACK_TIMEOUT:-900}"

  if [[ -n ${NO_COLOR:-} ]]; then
    C_RESET=""; C_BOLD=""; C_INFO=""; C_OK=""; C_WARN=""; C_ERR=""
  else
    C_RESET=$'\033[0m'; C_BOLD=$'\033[1m'; C_INFO=$'\033[1;34m'
    C_OK=$'\033[1;32m'; C_WARN=$'\033[1;33m'; C_ERR=$'\033[1;31m'
  fi
}

# --------------------------------------------------------------------------- #
# small helpers
# --------------------------------------------------------------------------- #
ts() { date -u '+%Y-%m-%dT%H:%M:%SZ'; }
info() { printf '%s[%s] INFO%s %s\n' "$C_INFO" "$(ts)" "$C_RESET" "$*"; }
ok() { printf '%s[%s]  OK %s %s\n' "$C_OK" "$(ts)" "$C_RESET" "$*"; }
warn() { printf '%s[%s] WARN%s %s\n' "$C_WARN" "$(ts)" "$C_RESET" "$*" >&2; }
die() { printf '%s[%s] FAIL%s %s\n' "$C_ERR" "$(ts)" "$C_RESET" "$*" >&2; exit 1; }
have() { command -v "$1" >/dev/null 2>&1; }

# Load .env without executing it; existing environment variables win.
load_env() {
  local file="$REPO_ROOT/.env" line key value
  [[ -r "$file" ]] || return 0
  while IFS= read -r line || [[ -n "$line" ]]; do
    [[ "$line" =~ ^[[:space:]]*(#|$) ]] && continue
    if [[ "$line" =~ ^[[:space:]]*(export[[:space:]]+)?([A-Za-z_][A-Za-z0-9_]*)=(.*)$ ]]; then
      key="${BASH_REMATCH[2]}"
      value="${BASH_REMATCH[3]}"
      value="${value%\"}"; value="${value#\"}"
      value="${value%\'}"; value="${value#\'}"
      if [[ -z ${!key+x} ]]; then
        printf -v "$key" '%s' "$value"
        export "$key"
      fi
    fi
  done <"$file"
}

proc_starttime() {
  local pid="$1"
  [[ -r "/proc/$pid/stat" ]] || return 1
  sed 's/^.*) //' "/proc/$pid/stat" | awk '{print $20}'
}

tcp_open() {
  local host="$1" port="$2"
  timeout 3 bash -c 'exec 3<>/dev/tcp/"$1"/"$2"' _ "$host" "$port" 2>/dev/null
}

wait_tcp() {
  local host="$1" port="$2" limit="$3" label="$4" waited=0
  until tcp_open "$host" "$port"; do
    ((waited >= limit)) && return 1
    sleep 2
    waited=$((waited + 2))
  done
  info "$label reachable on $host:$port after ${waited}s"
}

wait_http() {
  local url="$1" limit="$2" label="$3" waited=0
  until curl -fsS --max-time 3 "$url" >/dev/null 2>&1; do
    ((waited >= limit)) && return 1
    sleep 2
    waited=$((waited + 2))
  done
  info "$label ready at $url after ${waited}s"
}

usage() {
  sed -n '3,42p' "$SELF" | sed 's/^# \{0,1\}//'
}

# --------------------------------------------------------------------------- #
# ssh helpers — one place to add a future remote node
# --------------------------------------------------------------------------- #
# build_ssh <vm1|vm2> fills SSH_ARGV with the full command prefix. Password auth
# is only used when sshpass is installed; otherwise key auth is required and
# BatchMode makes the failure fast and visible instead of hanging on a prompt.
build_ssh() {
  local node="$1" host port user password
  case "$node" in
    vm1) host="$VM1_SSH_HOST"; port="$VM1_SSH_PORT"; user="$VM1_SSH_USER"; password="$VM1_PASSWORD" ;;
    vm2) host="$VM2_SSH_HOST"; port="$VM2_SSH_PORT"; user="$VM2_SSH_USER"; password="$VM2_PASSWORD" ;;
    *) die "unknown ssh node: $node" ;;
  esac
  local -a opts=(-o ConnectTimeout=6 -o ServerAliveInterval=15 -o ServerAliveCountMax=3
                 -o StrictHostKeyChecking=accept-new -o LogLevel=ERROR)
  if [[ -n "$SSH_KEY" ]]; then
    opts+=(-i "$SSH_KEY")
  fi
  if [[ -n "$password" ]] && have sshpass; then
    SSH_ARGV=(sshpass -p "$password" ssh "${opts[@]}" -p "$port" "$user@$host")
  else
    SSH_ARGV=(ssh "${opts[@]}" -o BatchMode=yes -p "$port" "$user@$host")
  fi
}

# remote_compose <node> <compose args...> prints a single remote shell command.
# sudo -n first (the guest user has NOPASSWD sudo), plain docker as fallback for
# hosts where the operator is in the docker group instead.
remote_compose() {
  local node="$1" dir sub
  local IFS=' '
  shift
  if [[ "$node" == vm1 ]]; then dir="$VM1_COMPOSE_DIR"; else dir="$VM2_COMPOSE_DIR"; fi
  sub="docker compose $*"
  printf 'cd %q && { sudo -n %s 2>/dev/null || %s; }' "$dir" "$sub" "$sub"
}

ssh_reachable() {
  local node="$1"
  case "$node" in
    vm1) tcp_open "$VM1_SSH_HOST" "$VM1_SSH_PORT" ;;
    vm2) tcp_open "$VM2_SSH_HOST" "$VM2_SSH_PORT" ;;
    *) return 1 ;;
  esac
}

ssh_probe() {
  local node="$1"
  build_ssh "$node"
  timeout 8 "${SSH_ARGV[@]}" true >/dev/null 2>&1
}

# --------------------------------------------------------------------------- #
# component registry
# --------------------------------------------------------------------------- #
# component_cmd <name> fills CMD with the argv of a long-running component.
# Every component is launched through --_run, which tees stdout+stderr to its
# log and records a PID+start-time pair for the stop script.
component_cmd() {
  local name="$1"
  CMD=()
  case "$name" in
    controller)
      CMD=("$PYTHON_BIN" "$REPO_ROOT/host/controller/approval_daemon.py"
           --host "$CTRL_HOST" --port "$CTRL_PORT" --audit-log "$CTRL_AUDIT")
      ;;
    controller-missing)
      CMD=("$BASH" -c "$CONTROLLER_MISSING_MSG")
      ;;
    vm1-honeypot)
      build_ssh vm1
      CMD=("${SSH_ARGV[@]}" "$(remote_compose vm1 logs -f --tail=200 ssh-honeypot)")
      ;;
    vm1-promtail)
      build_ssh vm1
      CMD=("${SSH_ARGV[@]}" "$(remote_compose vm1 logs -f --tail=100 promtail)")
      ;;
    vm2-agents)
      build_ssh vm2
      CMD=("${SSH_ARGV[@]}" "$(remote_compose vm2 logs -f --tail=200 agents)")
      ;;
    vm2-loki)
      build_ssh vm2
      CMD=("${SSH_ARGV[@]}" "$(remote_compose vm2 logs -f --tail=100 loki)")
      ;;
    vm2-grafana)
      build_ssh vm2
      CMD=("${SSH_ARGV[@]}" "$(remote_compose vm2 logs -f --tail=100 grafana)")
      ;;
    vm2-ollama)
      build_ssh vm2
      CMD=("${SSH_ARGV[@]}" "$(remote_compose vm2 logs -f --tail=100 ollama)")
      ;;
    *) die "unknown component: $name" ;;
  esac
}

# --------------------------------------------------------------------------- #
# tmux builders
# --------------------------------------------------------------------------- #
window_options() {
  local name="$1"
  # remain-on-exit and the border are window options: apply them to every window
  # explicitly, otherwise only the session's current window would inherit them.
  tmux set-option -w -t "$SESSION:$name" remain-on-exit on
  tmux set-option -w -t "$SESSION:$name" pane-border-status top
  tmux set-option -w -t "$SESSION:$name" pane-border-format ' #{pane_index} #{@dash_name} '
}

new_window() {
  local name="$1"
  tmux new-window -d -n "$name" -c "$REPO_ROOT"
  window_options "$name"
  tmux select-pane -t "=$SESSION:$name.0" -T "$name"
  tmux set-option -p -t "$SESSION:$name.0" @dash_name "$name"
}

split_pane() {
  local window="$1" from="$2" direction="$3" size="$4"
  tmux split-window -t "=$SESSION:$window.$from" "$direction" -l "$size" -c "$REPO_ROOT"
}

# pane_run <window> <index> <title> <component> <logfile>
pane_run() {
  local window="$1" index="$2" title="$3" component="$4" logfile="$5"
  local target="=$SESSION:$window.$index"
  tmux select-pane -t "$target" -T "$title"
  tmux set-option -p -t "$SESSION:$window.$index" @dash_name "$title"
  component_cmd "$component"
  local -a words=(exec "$BASH" "$SELF" --_run "$component" "$logfile" -- "${CMD[@]}")
  tmux send-keys -t "$target" "$(printf '%q ' "${words[@]}")" C-m
}

# pane_watch <window> <index> <title> <command string>
# Viewers are intentionally not tee'd into a log: they read the logs already
# written by pane_run, and writing a log viewer's output into the log set would
# create a feedback loop.
pane_watch() {
  local window="$1" index="$2" title="$3" command="$4"
  local target="=$SESSION:$window.$index"
  tmux select-pane -t "$target" -T "$title"
  tmux set-option -p -t "$SESSION:$window.$index" @dash_name "$title"
  tmux send-keys -t "$target" "$command" C-m
}

# status_cmd <section> <interval> [extra flags...] -> command string
status_cmd() {
  local section="$1" interval="$2"
  shift 2
  printf '%q ' "$BASH" "$STATUS_SCRIPT" --section "$section" --watch "$interval" "$@"
}

log_files() {
  local -a files=()
  local name
  for name in controller honeypot promtail agents loki grafana ollama bootstrap; do
    files+=("$LOG_DIR/$name.log")
  done
  printf '%s\n' "${files[@]}"
}

# --------------------------------------------------------------------------- #
# preflight / bootstrap
# --------------------------------------------------------------------------- #
preflight() {
  local missing=()
  local bin
  for bin in tmux curl python3 virsh; do
    have "$bin" || missing+=("$bin")
  done
  if ((${#missing[@]})); then
    die "missing required commands: ${missing[*]}"
  fi
  [[ -f "$REPO_ROOT/host/controller/approval_daemon.py" ]] \
    || die "host/controller/approval_daemon.py not found under $REPO_ROOT"
  [[ -x "$STATUS_SCRIPT" ]] || die "$STATUS_SCRIPT is not executable (chmod +x)"
  [[ -x "$STOP_SCRIPT" ]] || warn "$STOP_SCRIPT is not executable; --stop will not work"
  have ssh || warn "ssh not found: remote panes will be unavailable"
  have sshpass || warn "sshpass not found: password auth disabled, SSH keys required for remote panes"
  [[ -f "$REPO_ROOT/.env" ]] || warn "no .env found (cp .env.example .env to configure)"

  mkdir -p "$LOG_DIR" "$PID_DIR"
  local name
  for name in controller honeypot promtail agents loki grafana ollama bootstrap status shell-session; do
    touch "$LOG_DIR/$name.log"
  done
  chmod 0700 "$RUN_DIR" 2>/dev/null || true
}

detect_python() {
  if [[ -x "$REPO_ROOT/host/controller/.venv/bin/python" ]]; then
    PYTHON_BIN="$REPO_ROOT/host/controller/.venv/bin/python"
  elif [[ -x "$REPO_ROOT/.venv/bin/python" ]]; then
    PYTHON_BIN="$REPO_ROOT/.venv/bin/python"
  elif python3 -c 'import flask, rich' >/dev/null 2>&1; then
    PYTHON_BIN="python3"
  else
    PYTHON_BIN=""
  fi

  CONTROLLER_MISSING_MSG="$(cat <<EOF
printf '\\n[controller] Flask/Rich are not importable by python3.\\n' >&2
printf 'Create the venv, then restart the dashboard:\\n' >&2
printf '  python3 -m venv .venv\\n' >&2
printf '  .venv/bin/pip install -r host/controller/requirements.txt\\n' >&2
printf 'This pane stays open so the failure is visible.\\n\\n' >&2
exec sleep 86400
EOF
)"
}

start_vms_if_requested() {
  ((START_VMS)) || return 0
  local dom state
  if ! sudo -n true 2>/dev/null; then
    warn "--start-vms needs passwordless sudo; skipping (start the lab manually)"
    return 0
  fi
  if ! virsh -c qemu:///system net-info default 2>/dev/null | grep -q '^Active:.*yes'; then
    sudo -n virsh net-start default >/dev/null 2>&1 || warn "could not start the default network"
  fi
  for dom in vm-honeypot vm-soc; do
    state="$(virsh -c qemu:///system domstate "$dom" 2>/dev/null || echo missing)"
    case "$state" in
      running) ok "$dom already running" ;;
      missing) warn "$dom is not defined; run host/provisioning/deploy-lab.sh" ;;
      *)
        if sudo -n virsh start "$dom" >/dev/null 2>&1; then
          ok "$dom started"
        else
          warn "could not start $dom (needs root)"
        fi
        ;;
    esac
  done
  wait_tcp "$VM2_SSH_HOST" "$VM2_SSH_PORT" "$READY_TIMEOUT" "vm-soc ssh" \
    || warn "vm-soc ssh not reachable after ${READY_TIMEOUT}s"
}

bootstrap_stacks() {
  if ((SKIP_STACKS)); then
    warn "--skip-stacks: not starting Docker stacks"
    return 0
  fi
  local node vm2_stack_ok=0
  for node in vm1 vm2; do
    if ! ssh_reachable "$node"; then
      warn "$node is unreachable: stack not started (panes will show the error)"
      continue
    fi
    if ! ssh_probe "$node"; then
      warn "$node SSH authentication failed: stack not started (set DASH_SSH_KEY or DASH_VM*_PASSWORD)"
      continue
    fi
    info "starting the $node compose stack (timeout ${STACK_TIMEOUT}s)"
    build_ssh "$node"
    local command
    command="$(remote_compose "$node" up -d)"
    if timeout "$STACK_TIMEOUT" "${SSH_ARGV[@]}" "$command" >>"$LOG_DIR/bootstrap.log" 2>&1; then
      ok "$node compose stack is up"
      if [[ "$node" == vm2 ]]; then
        vm2_stack_ok=1
      fi
    else
      warn "$node compose up failed; see $LOG_DIR/bootstrap.log"
    fi
  done
  # Loki must be ready before the agents pane is useful; compose already gates
  # on it, this is the dashboard-side confirmation. Skip the wait entirely when
  # vm-soc is unreachable or its stack failed: there is nothing to wait for.
  if ((vm2_stack_ok)) && ssh_probe vm2; then
    if wait_http "$LOKI_URL/ready" "$READY_TIMEOUT" "loki"; then
      ok "loki /ready"
    else
      warn "loki not ready after ${READY_TIMEOUT}s (is vm-soc running?)"
    fi
  else
    warn "vm-soc stack did not start: skipping the Loki readiness wait"
  fi
}

# --------------------------------------------------------------------------- #
# session construction
# --------------------------------------------------------------------------- #
build_session() {
  tmux new-session -d -s "$SESSION" -n core -c "$REPO_ROOT"
  tmux set-option -s mouse on
  tmux set-option -g history-limit 50000
  tmux set-option -t "$SESSION" destroy-unattached off
  window_options core
  tmux set-option -t "$SESSION" status-left '[#{session_name}] '
  tmux set-option -t "$SESSION" status-right '%H:%M '
  tmux set-option -t "$SESSION" window-status-current-format '#[bold]#I:#W#{?window_zoomed_flag, Z,}'
  tmux select-pane -t "=$SESSION:core.0" -T controller

  # ---- core: the human-in-the-loop controller and its liveness -------------
  split_pane core 0 -h 34%
  if ((SKIP_CONTROLLER)); then
    pane_run core 0 controller-skipped controller-missing "$LOG_DIR/controller.log"
  elif [[ -n "$PYTHON_BIN" ]]; then
    pane_run core 0 controller controller "$LOG_DIR/controller.log"
  else
    pane_run core 0 controller-missing controller-missing "$LOG_DIR/controller.log"
  fi
  pane_watch core 1 controller-health "$(status_cmd controller 5)"

  # ---- edge: the trap tier --------------------------------------------------
  new_window edge
  split_pane edge 0 -v 45%
  split_pane edge 1 -v 50%
  tmux select-layout -t "=$SESSION:edge" even-vertical
  pane_run edge 0 honeypot-logs vm1-honeypot "$LOG_DIR/honeypot.log"
  pane_run edge 1 promtail-logs vm1-promtail "$LOG_DIR/promtail.log"
  pane_watch edge 2 trap-probe "$(status_cmd edge 10)"

  # ---- brain: observability + AI pipeline (2x2) -----------------------------
  new_window brain
  split_pane brain 0 -h 50%
  split_pane brain 1 -v 50%
  split_pane brain 0 -v 50%
  tmux select-layout -t "=$SESSION:brain" tiled
  pane_run brain 0 agents-logs vm2-agents "$LOG_DIR/agents.log"
  pane_run brain 1 loki-logs vm2-loki "$LOG_DIR/loki.log"
  pane_run brain 2 grafana-logs vm2-grafana "$LOG_DIR/grafana.log"
  pane_run brain 3 ollama-logs vm2-ollama "$LOG_DIR/ollama.log"

  # ---- infra: hypervisor, firewall, host pressure ---------------------------
  new_window infra
  split_pane infra 0 -h 34%
  split_pane infra 1 -h 50%
  tmux select-layout -t "=$SESSION:infra" even-horizontal
  pane_watch infra 0 libvirt-state "$(status_cmd libvirt 5)"
  pane_watch infra 1 live-fire "$(status_cmd network 5)"
  pane_watch infra 2 host-resources "$(status_cmd resources 5)"

  # ---- integrations: the two bridges that can silently break ----------------
  new_window integrations
  split_pane integrations 0 -h 50%
  tmux select-layout -t "=$SESSION:integrations" even-horizontal
  pane_watch integrations 0 loki-ingress "$(status_cmd ingress 15)"
  pane_watch integrations 1 incidents "$(status_cmd webhook 5)"

  # ---- logs: merged stream + error-only stream ------------------------------
  new_window logs
  split_pane logs 0 -h 60%
  local -a files=()
  local line
  while IFS= read -r line; do files+=("$line"); done < <(log_files)
  pane_watch logs 0 all-logs "$(printf '%q ' tail -F "${files[@]}")"
  pane_watch logs 1 errors "tail -F $(printf '%q ' "${files[@]}") | grep --line-buffered -Ei 'error|critical|traceback|panic|fatal'"

  # ---- health: the full status table ----------------------------------------
  new_window health
  pane_watch health 0 status "$(status_cmd all 5 --append-log)"

  # ---- shell: manual debugging, transcript preserved ------------------------
  new_window shell
  local shell_hint
  shell_hint="printf '%s\\n' '' 'KVM-Sentinel-SOC shell — repo root. Useful commands:' '  ./scripts/dashboard-status.sh --no-color            full health snapshot' '  ./scripts/tmux-dashboard.sh --logs                  jump to the logs window' '  sudo ./host/provisioning/enable-live-fire.sh status' '  ssh soc@192.168.122.20 sudo docker compose -f /opt/soc/docker-compose.yml ps' '  ssh soc@10.10.0.10 sudo docker compose -f /opt/honeypot/docker-compose.yml ps' '  ssh soc@10.10.0.10 sudo docker compose -f /opt/honeypot/docker-compose.yml run --rm simulator' '' 'The simulator line is manual: it is never run automatically.' ''"
  pane_watch shell 0 shell "cd $(printf '%q' "$REPO_ROOT") && clear && $shell_hint; exec bash -i"
  # pipe-pane preserves everything typed in this shell; the other panes already
  # write through --_run, so a second tee would duplicate their output.
  tmux pipe-pane -t "=$SESSION:shell.0" "cat >> $(printf '%q' "$LOG_DIR/shell-session.log")"

  # ---- dashboard: compact overview + live pane map --------------------------
  new_window dashboard
  split_pane dashboard 0 -h 38%
  pane_watch dashboard 0 overview "$(status_cmd all 5 --compact)"
  pane_watch dashboard 1 pane-map \
    "while :; do clear; printf 'session: $SESSION\n\n'; tmux list-panes -s -t '$SESSION' -F '#{window_index}.#{pane_index} #{@dash_name} (#{pane_current_command})'; sleep 2; done"

  tmux select-window -t "=$SESSION:dashboard"
}

print_summary() {
  local windows panes
  windows="$(tmux list-windows -t "=$SESSION" -F '  #{window_index}: #{window_name}' | paste -sd ' ' -)"
  panes="$(tmux list-panes -s -t "=$SESSION" -F x | wc -l | tr -d ' ')"
  printf '\n%sKVM-Sentinel-SOC dashboard%s\n' "$C_BOLD" "$C_RESET"
  printf '  session : %s\n' "$SESSION"
  printf '  windows : %s\n' "$windows"
  printf '  panes   : %s\n' "$panes"
  printf '  logs    : %s\n' "$LOG_DIR"
  printf '  attach  : tmux attach -t %s\n' "$SESSION"
  printf '  status  : %s --status\n' "$SELF"
  printf '  stop    : %s --stop\n\n' "$SELF"
}

attach_session() {
  if ((NO_ATTACH)); then
    info "--no-attach: session built, not attaching"
    return 0
  fi
  if [[ ! -t 1 && -z ${TMUX:-} ]]; then
    info "stdout is not a tty: attach manually with 'tmux attach -t $SESSION'"
    return 0
  fi
  if [[ -n "${TMUX:-}" ]]; then
    tmux switch-client -t "=$SESSION"
  else
    tmux attach-session -t "=$SESSION"
  fi
}

# --------------------------------------------------------------------------- #
# internal runner: one pane, one component, one log, one pidfile
# --------------------------------------------------------------------------- #
run_component() {
  local name="$1" logfile="$2"
  shift 2
  [[ "${1:-}" == "--" ]] && shift
  (($#)) || die "run_component: no command given for $name"

  mkdir -p "$(dirname "$logfile")" "$PID_DIR"
  local starttime
  starttime="$(proc_starttime $$)" || starttime=0
  printf '%s %s\n' "$$" "$starttime" >"$PID_DIR/$name.pid"

  printf '\n===== %s | %s | start =====\n' "$(ts)" "$name" >>"$logfile"
  # Process substitution keeps this shell as the component (exec below), so the
  # recorded PID and the signal target are the real process, not tee. The pane
  # still shows live output because tee writes to the inherited tty.
  local shown
  shown="$(printf '%q ' "$@")"
  exec > >(tee -a "$logfile") 2>&1
  printf '[%s] %s: %s\n' "$(date -u '+%H:%M:%SZ')" "$name" "$shown"
  exec "$@"
}

# --------------------------------------------------------------------------- #
# main
# --------------------------------------------------------------------------- #
MODE="create"
NO_ATTACH=0
SKIP_STACKS=0
SKIP_CONTROLLER=0
START_VMS=0
PASSTHRU=()
RUN_NAME=""
RUN_LOG=""
RUN_CMD=()

parse_args() {
  if [[ "${1:-}" == "--_run" ]]; then
    shift
    RUN_NAME="${1:?--_run needs a component name}"
    RUN_LOG="${2:?--_run needs a log path}"
    shift 2
    [[ "${1:-}" == "--" ]] && shift
    RUN_CMD=("$@")
    MODE="run"
    return 0
  fi
  while (($#)); do
    case "$1" in
      --status) MODE="status"; shift; PASSTHRU=("$@"); break ;;
      --logs) MODE="logs"; shift ;;
      --stop) MODE="stop"; shift; PASSTHRU=("$@"); break ;;
      --restart) MODE="restart"; shift ;;
      --no-attach) NO_ATTACH=1; shift ;;
      --skip-stacks) SKIP_STACKS=1; shift ;;
      --skip-controller) SKIP_CONTROLLER=1; shift ;;
      --start-vms) START_VMS=1; shift ;;
      --help|-h) usage; exit 0 ;;
      *) die "unknown option: $1 (try --help)" ;;
    esac
  done
}

main() {
  parse_args "$@"
  load_env
  init_config
  detect_python

  if [[ "$MODE" == "run" ]]; then
    run_component "$RUN_NAME" "$RUN_LOG" -- "${RUN_CMD[@]}"
    return 0
  fi

  case "$MODE" in
    status)
      exec "$BASH" "$STATUS_SCRIPT" "${PASSTHRU[@]+"${PASSTHRU[@]}"}"
      ;;
    stop)
      exec "$BASH" "$STOP_SCRIPT" "${PASSTHRU[@]+"${PASSTHRU[@]}"}"
      ;;
    logs)
      if tmux has-session -t "=$SESSION" 2>/dev/null; then
        tmux select-window -t "=$SESSION:logs"
        attach_session
        return 0
      fi
      printf 'dashboard is not running; log directory: %s\n' "$LOG_DIR"
      return 0
      ;;
    restart)
      "$BASH" "$STOP_SCRIPT" --quiet || true
      MODE="create"
      ;;
  esac

  preflight

  if tmux has-session -t "=$SESSION" 2>/dev/null; then
    info "session '$SESSION' already exists: attaching instead of duplicating"
    print_summary
    attach_session
    return 0
  fi

  start_vms_if_requested
  bootstrap_stacks
  build_session
  print_summary
  attach_session
}

main "$@"
