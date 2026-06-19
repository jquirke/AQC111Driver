#!/bin/sh
set -u

LOG_FILE="${LOG_FILE:-$PWD/baseline-vlan0.log}"
PARENT_IF="${PARENT_IF:-en9}"
PARENT_ADDR="${PARENT_ADDR:-169.254.245.127}"
PARENT_NETMASK="${PARENT_NETMASK:-255.255.0.0}"
VLAN_IF="${VLAN_IF:-vlan0}"
VLAN_TAG="${VLAN_TAG:-1234}"
VLAN_ADDR="${VLAN_ADDR:-169.254.113.129}"
VLAN_NETMASK="${VLAN_NETMASK:-255.255.0.0}"
TARGET_ADDR="${TARGET_ADDR:-169.254.50.52}"
TARGET_MAC="${TARGET_MAC:-58:ef:68:e2:8e:95}"
WAIT_SECONDS="${WAIT_SECONDS:-20}"
PING_COUNT="${PING_COUNT:-4}"

timestamp() {
  date '+%Y-%m-%d %H:%M:%S %z'
}

log() {
  printf '%s %s\n' "$(timestamp)" "$*" | tee -a "$LOG_FILE"
}

run() {
  log "+ $*"
  tmp="${TMPDIR:-/tmp}/baseline-vlan0.$$.out"
  "$@" >"$tmp" 2>&1
  status=$?
  tee -a "$LOG_FILE" <"$tmp"
  rm -f "$tmp"
  log "exit=$status"
  return "$status"
}

run_required() {
  run "$@"
  status=$?
  if [ "$status" -ne 0 ]; then
    log "ERROR: command failed with exit status $status: $*"
    exit "$status"
  fi
}

run_optional() {
  run "$@"
  return 0
}

wait_for_parent() {
  elapsed=0
  while [ "$elapsed" -le "$WAIT_SECONDS" ]; do
    if ifconfig "$PARENT_IF" >/dev/null 2>&1; then
      status=$(ifconfig "$PARENT_IF" | awk '/status:/{print $2; exit}')
      return 0
      log "$PARENT_IF exists but status is '${status:-unknown}'; waiting"
    else
      log "$PARENT_IF does not exist yet; waiting"
    fi
    sleep 1
    elapsed=$((elapsed + 1))
  done

  log "ERROR: $PARENT_IF did not become active within ${WAIT_SECONDS}s"
  return 1
}

if [ "$(id -u)" -ne 0 ]; then
  log "ERROR: run this script with sudo"
  log "Example: sudo $0"
  exit 1
fi

log "Starting deterministic adapter baseline"
log "Log file: $LOG_FILE"
log "Parent: $PARENT_IF $PARENT_ADDR/$PARENT_NETMASK"
log "VLAN: $VLAN_IF tag $VLAN_TAG $VLAN_ADDR/$VLAN_NETMASK"
log "Target: $TARGET_ADDR at $TARGET_MAC"

if ! wait_for_parent; then
  exit 1
fi

run_required ifconfig "$PARENT_IF"
run_required ifconfig "$PARENT_IF" inet "$PARENT_ADDR" netmask "$PARENT_NETMASK"
run_required ifconfig "$PARENT_IF" up

if ifconfig "$VLAN_IF" >/dev/null 2>&1; then
  log "$VLAN_IF already exists; destroying before recreation"
  run_required ifconfig "$VLAN_IF" destroy
fi

run_required ifconfig "$VLAN_IF" create
run_required ifconfig "$VLAN_IF" vlan "$VLAN_TAG" vlandev "$PARENT_IF"
run_required ifconfig "$VLAN_IF" inet "$VLAN_ADDR" netmask "$VLAN_NETMASK"
run_required ifconfig "$VLAN_IF" up

log "Clearing stale target route and ARP entries"
run_optional arp -d "$TARGET_ADDR" ifscope "$VLAN_IF"
run_optional arp -d "$TARGET_ADDR"
run_optional route -n delete -host "$TARGET_ADDR"

log "Installing deterministic target route and scoped ARP"
run route -n add -host "$TARGET_ADDR" -interface "$VLAN_IF"
route_status=$?
if [ "$route_status" -ne 0 ]; then
  run_required route -n change -host "$TARGET_ADDR" -interface "$VLAN_IF"
fi
run_required arp -s "$TARGET_ADDR" "$TARGET_MAC" temp ifscope "$VLAN_IF"

log "Final baseline state"
run_required ifconfig "$PARENT_IF"
run_required ifconfig "$VLAN_IF"
run_required route -n get "$TARGET_ADDR"
run_required arp -an -i "$VLAN_IF"
run_required netstat -rn -f inet

log "Verification ping"
run ping -b "$VLAN_IF" -S "$VLAN_ADDR" -c "$PING_COUNT" "$TARGET_ADDR"
ping_status=$?

if [ "$ping_status" -ne 0 ]; then
  log "ERROR: baseline configured, but ping failed with exit status $ping_status"
  exit "$ping_status"
fi

log "Deterministic adapter baseline completed successfully"
