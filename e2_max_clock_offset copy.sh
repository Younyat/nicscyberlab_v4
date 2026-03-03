#!/usr/bin/env bash
set -euo pipefail

# ============================================================
# CONFIG
# ============================================================
OPENRC="./admin-openrc.sh"
SSH_KEY="${SSH_KEY:-$HOME/.ssh/my_key}"
SSH_USERS=("ubuntu" "debian")
SAMPLES="${SAMPLES:-5}"
SSH_TIMEOUT="${SSH_TIMEOUT:-4}"

FILTER_STATUS="${FILTER_STATUS:-ACTIVE}"   # "", ACTIVE, SHUTOFF, etc.

# Preferir IPs de esta subred/prefijo
PREFERRED_IP_PREFIX="${PREFERRED_IP_PREFIX:-10.0.2.}"

# ============================================================
# HELPERS
# ============================================================
die() { echo "[ERROR] $*" >&2; exit 1; }

need_cmd() {
  command -v "$1" >/dev/null 2>&1 || die "Falta comando: $1"
}

ns_now() {
  date +%s%N
}

extract_preferred_ipv4() {
  local addrs="$1"
  local pref="$2"

  # 1) Preferida: primera IPv4 que coincida con prefijo, ej 10.0.2.
  local ip_pref
  ip_pref="$(echo "$addrs" | grep -Eo "(${pref//./\\.})([0-9]{1,3})" | head -n 1 || true)"
  if [[ -n "$ip_pref" ]]; then
    echo "$ip_pref"
    return 0
  fi

  # 2) Fallback: primera IPv4 cualquiera
  echo "$addrs" | grep -Eo '([0-9]{1,3}\.){3}[0-9]{1,3}' | head -n 1 || true
}

ssh_remote_ns() {
  local user="$1"
  local ip="$2"
  ssh -i "$SSH_KEY" \
      -o BatchMode=yes \
      -o ConnectTimeout="$SSH_TIMEOUT" \
      -o StrictHostKeyChecking=no \
      -o UserKnownHostsFile=/dev/null \
      "$user@$ip" 'date +%s%N' 2>/dev/null || return 1
}

measure_offset_for_ip() {
  local ip="$1"

  local chosen_user=""
  local remote_ns=""
  for u in "${SSH_USERS[@]}"; do
    if remote_ns="$(ssh_remote_ns "$u" "$ip")"; then
      chosen_user="$u"
      break
    fi
  done

  if [[ -z "$chosen_user" ]]; then
    echo "FAIL"
    return 0
  fi

  local best_rtt_ns=""
  local best_offset_ns=""
  local i
  for ((i=1; i<=SAMPLES; i++)); do
    local t1 t3 t2
    t1="$(ns_now)"
    if ! t2="$(ssh_remote_ns "$chosen_user" "$ip")"; then
      continue
    fi
    t3="$(ns_now)"

    local rtt_ns=$(( t3 - t1 ))
    local mid_ns=$(( (t1 + t3) / 2 ))
    local off_ns=$(( t2 - mid_ns ))

    if [[ -z "${best_rtt_ns}" || "$rtt_ns" -lt "$best_rtt_ns" ]]; then
      best_rtt_ns="$rtt_ns"
      best_offset_ns="$off_ns"
    fi
  done

  if [[ -z "${best_rtt_ns}" || -z "${best_offset_ns}" ]]; then
    echo "FAIL"
    return 0
  fi

  local best_rtt_ms best_offset_ms best_abs_offset_ms
  best_rtt_ms="$(awk -v ns="$best_rtt_ns" 'BEGIN{printf "%.3f", ns/1000000.0}')"
  best_offset_ms="$(awk -v ns="$best_offset_ns" 'BEGIN{printf "%.3f", ns/1000000.0}')"
  best_abs_offset_ms="$(awk -v ns="$best_offset_ns" 'BEGIN{v=ns/1000000.0; if(v<0) v=-v; printf "%.3f", v}')"

  echo "OK $chosen_user $best_rtt_ms $best_offset_ms $best_abs_offset_ms"
}

# ============================================================
# MAIN
# ============================================================
need_cmd openstack
need_cmd ssh
need_cmd awk
need_cmd grep
need_cmd date

[[ -f "$OPENRC" ]] || die "No encuentro $OPENRC"
[[ -f "$SSH_KEY" ]] || die "No encuentro SSH_KEY=$SSH_KEY"

# shellcheck disable=SC1090
source "$OPENRC"

echo "[INFO] OpenStack auth check..."
openstack token issue >/dev/null 2>&1 || die "No puedo autenticar contra OpenStack. Revisa admin-openrc.sh"

echo "[INFO] Listando servidores..."
if [[ -n "$FILTER_STATUS" ]]; then
  mapfile -t SERVER_LINES < <(openstack server list --status "$FILTER_STATUS" -f value -c ID -c Name)
else
  mapfile -t SERVER_LINES < <(openstack server list -f value -c ID -c Name)
fi

if [[ "${#SERVER_LINES[@]}" -eq 0 ]]; then
  die "No hay servidores (o ninguno con status=$FILTER_STATUS)."
fi

printf "\n%-36s  %-24s  %-15s  %-8s  %-10s  %-12s  %-12s\n" \
  "VM_ID" "NAME" "IP" "USER" "RTT_ms" "OFFSET_ms" "ABS_ms"
printf "%s\n" "-------------------------------------------------------------------------------------------------------------------------------"

max_abs_ms="0.000"
max_vm_id=""
max_vm_name=""
max_vm_ip=""

for line in "${SERVER_LINES[@]}"; do
  vm_id="$(echo "$line" | awk '{print $1}')"
  vm_name="$(echo "$line" | awk '{$1=""; sub(/^ /,""); print}')"

  addrs="$(openstack server show "$vm_id" -f value -c addresses 2>/dev/null || true)"
  ip="$(extract_preferred_ipv4 "$addrs" "$PREFERRED_IP_PREFIX")"

  if [[ -z "$ip" ]]; then
    printf "%-36s  %-24s  %-15s  %-8s  %-10s  %-12s  %-12s\n" \
      "$vm_id" "$(echo "$vm_name" | cut -c1-24)" "N/A" "N/A" "N/A" "N/A" "N/A"
    continue
  fi

  res="$(measure_offset_for_ip "$ip")"
  if [[ "$res" == "FAIL" ]]; then
    printf "%-36s  %-24s  %-15s  %-8s  %-10s  %-12s  %-12s\n" \
      "$vm_id" "$(echo "$vm_name" | cut -c1-24)" "$ip" "FAIL" "N/A" "N/A" "N/A"
    continue
  fi

  user="$(echo "$res" | awk '{print $2}')"
  rtt_ms="$(echo "$res" | awk '{print $3}')"
  offset_ms="$(echo "$res" | awk '{print $4}')"
  abs_ms="$(echo "$res" | awk '{print $5}')"

  printf "%-36s  %-24s  %-15s  %-8s  %-10s  %-12s  %-12s\n" \
    "$vm_id" "$(echo "$vm_name" | cut -c1-24)" "$ip" "$user" "$rtt_ms" "$offset_ms" "$abs_ms"

  is_gt="$(awk -v a="$abs_ms" -v b="$max_abs_ms" 'BEGIN{print (a>b)?1:0}')"
  if [[ "$is_gt" == "1" ]]; then
    max_abs_ms="$abs_ms"
    max_vm_id="$vm_id"
    max_vm_name="$vm_name"
    max_vm_ip="$ip"
  fi
done

echo
echo "[RESULT] E2 max clock offset/skew (ms) = $max_abs_ms"
if [[ -n "$max_vm_id" ]]; then
  echo "[RESULT] Worst node: $max_vm_name | $max_vm_id | $max_vm_ip"
fi