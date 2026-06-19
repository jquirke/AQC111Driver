#!/bin/sh
set -u

LOG_FILE="${LOG_FILE:-$PWD/setup-vlan1234.log}"
PARENT_IF="${PARENT_IF:-en9}"
VLAN_IF="${VLAN_IF:-vlan0}"
VLAN_TAG="${VLAN_TAG:-1234}"
VLAN_ADDR="${VLAN_ADDR:-172.16.123.20}"
VLAN_NETMASK="${VLAN_NETMASK:-255.255.255.0}"
TARGET_ADDR="${TARGET_ADDR:-172.16.123.10}"
TARGET_MAC="${TARGET_MAC:-}"
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
  tmp="${TMPDIR:-/tmp}/setup-vlan1234.$$.out"
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
      log "$PARENT_IF exists"
      return 0
    fi
    log "$PARENT_IF does not exist yet; waiting"
    sleep 1
    elapsed=$((elapsed + 1))
  done

  log "ERROR: $PARENT_IF did not appear within ${WAIT_SECONDS}s"
  return 1
}

delete_ipv4_addrs() {
  iface="$1"
  if ! ifconfig "$iface" >/dev/null 2>&1; then
    return 0
  fi

  addrs=$(ifconfig "$iface" | awk '/^[[:space:]]*inet / { print $2 }')
  for addr in $addrs; do
    run_optional ifconfig "$iface" inet "$addr" delete
  done
}

if [ "$(id -u)" -ne 0 ]; then
  log "ERROR: run this script with sudo"
  log "Example: sudo $0"
  exit 1
fi

log "Starting deterministic VLAN test setup"
log "Log file: $LOG_FILE"
log "Parent: $PARENT_IF with no IPv4 address"
log "VLAN: $VLAN_IF tag $VLAN_TAG $VLAN_ADDR/$VLAN_NETMASK"
log "Target: $TARGET_ADDR"

if ! wait_for_parent; then
  exit 1
fi

run_required ifconfig "$PARENT_IF" up

if ifconfig "$VLAN_IF" >/dev/null 2>&1; then
  log "$VLAN_IF already exists; destroying before recreation"
  run_required ifconfig "$VLAN_IF" destroy
fi

log "Clearing IPv4 addresses from parent to avoid route ambiguity"
delete_ipv4_addrs "$PARENT_IF"

log "Clearing stale target route and ARP entries"
run_optional arp -d "$TARGET_ADDR" ifscope "$VLAN_IF"
run_optional arp -d "$TARGET_ADDR" ifscope "$PARENT_IF"
run_optional arp -d "$TARGET_ADDR"
run_optional route -n delete -host "$TARGET_ADDR"

run_required ifconfig "$VLAN_IF" create
run_required ifconfig "$VLAN_IF" vlan "$VLAN_TAG" vlandev "$PARENT_IF"
run_required ifconfig "$VLAN_IF" inet "$VLAN_ADDR" netmask "$VLAN_NETMASK"
run_required ifconfig "$VLAN_IF" up

if [ -n "$TARGET_MAC" ]; then
  log "Installing optional scoped ARP override: $TARGET_ADDR -> $TARGET_MAC"
  run_required arp -s "$TARGET_ADDR" "$TARGET_MAC" temp ifscope "$VLAN_IF"
else
  log "No TARGET_MAC supplied; using normal ARP on $VLAN_IF"
fi

log "Final VLAN test state"
run_required ifconfig "$PARENT_IF"
run_required ifconfig "$VLAN_IF"
run_required route -n get "$TARGET_ADDR"
run_optional arp -an -i "$VLAN_IF"
run_required netstat -rn -f inet

log "Verification ping"
run ping -b "$VLAN_IF" -S "$VLAN_ADDR" -c "$PING_COUNT" "$TARGET_ADDR"
ping_status=$?

if [ "$ping_status" -ne 0 ]; then
  log "ERROR: VLAN setup completed, but ping failed with exit status $ping_status"
  exit "$ping_status"
fi

log "Deterministic VLAN test setup completed successfully"
