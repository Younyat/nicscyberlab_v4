#DO_FIX_TIME=1 SSH_KEY="$HOME/.ssh/my_key" bash e2_max_clock_offset.sh


#!/usr/bin/env bash
set -euo pipefail

OPENRC="./admin-openrc.sh"
SSH_KEY="${SSH_KEY:-$HOME/.ssh/my_key}"
SSH_USERS=("ubuntu" "debian")
SSH_TIMEOUT="${SSH_TIMEOUT:-6}"
FILTER_STATUS="${FILTER_STATUS:-ACTIVE}"
PREFERRED_IP_PREFIX="${PREFERRED_IP_PREFIX:-10.0.2.}"

# 0 = solo medir; 1 = si falta chrony, instalarlo en remoto y luego medir
DO_FIX_TIME="${DO_FIX_TIME:-0}"

die(){ echo "[ERROR] $*" >&2; exit 1; }
need_cmd(){ command -v "$1" >/dev/null 2>&1 || die "Falta comando: $1"; }

extract_preferred_ipv4() {
  local addrs="$1" pref="$2"
  local ip_pref
  ip_pref="$(echo "$addrs" | grep -Eo "(${pref//./\\.})([0-9]{1,3})" | head -n 1 || true)"
  [[ -n "$ip_pref" ]] && { echo "$ip_pref"; return 0; }
  echo "$addrs" | grep -Eo '([0-9]{1,3}\.){3}[0-9]{1,3}' | head -n 1 || true
}

ssh_run() {
  local user="$1" ip="$2" cmd="$3"
  ssh -i "$SSH_KEY" \
    -o BatchMode=yes \
    -o ConnectTimeout="$SSH_TIMEOUT" \
    -o StrictHostKeyChecking=no \
    -o UserKnownHostsFile=/dev/null \
    "$user@$ip" "$cmd"
}

pick_ssh_user() {
  local ip="$1"
  for u in "${SSH_USERS[@]}"; do
    if ssh_run "$u" "$ip" "true" >/dev/null 2>&1; then
      echo "$u"; return 0
    fi
  done
  echo ""
}

ensure_chrony() {
  local user="$1" ip="$2"
  # devuelve 0 si chronyc existe al final, 1 si no
  if ssh_run "$user" "$ip" "command -v chronyc >/dev/null 2>&1" >/dev/null 2>&1; then
    return 0
  fi
  [[ "$DO_FIX_TIME" == "1" ]] || return 1

  # Instala chrony si el usuario tiene sudo sin password
  # Si pide password, fallará y devolvemos 1.
  local cmd='
set -e
sudo -n true >/dev/null 2>&1 || exit 10
sudo apt-get update -y
sudo apt-get install -y chrony
sudo systemctl enable --now chrony
command -v chronyc >/dev/null 2>&1
'
  if ssh_run "$user" "$ip" "$cmd" >/dev/null 2>&1; then
    return 0
  fi
  return 1
}

# Devuelve: "OK <user> <offset_ms_signed> <abs_ms>" o "FAIL <reason>"
measure_offset_chrony() {
  local ip="$1"
  local user
  user="$(pick_ssh_user "$ip")"
  [[ -n "$user" ]] || { echo "FAIL ssh"; return 0; }

  if ! ensure_chrony "$user" "$ip"; then
    echo "FAIL no_chrony_or_no_sudo"
    return 0
  fi

  # Extrae la línea System time
  local line
  line="$(ssh_run "$user" "$ip" "chronyc tracking 2>/dev/null | grep -E '^System time'" 2>/dev/null || true)"
  [[ -n "$line" ]] || { echo "FAIL no_system_time"; return 0; }

  # Formato típico:
  # System time     : 0.000018718 seconds slow of NTP time
  local sec sign
  sec="$(echo "$line" | awk '{print $4}')"
  sign="+"
  echo "$line" | tr '[:upper:]' '[:lower:]' | grep -q "slow" && sign="-"

  local offset_ms abs_ms
  offset_ms="$(awk -v s="$sec" -v sign="$sign" 'BEGIN{
    v = s*1000.0;
    if(sign=="-") v = -v;
    printf "%.3f", v
  }')"
  abs_ms="$(awk -v v="$offset_ms" 'BEGIN{a=v; if(a<0) a=-a; printf "%.3f", a}')"

  echo "OK $user $offset_ms $abs_ms"
}

need_cmd openstack
need_cmd ssh
need_cmd awk
need_cmd grep

[[ -f "$OPENRC" ]] || die "No encuentro $OPENRC"
[[ -f "$SSH_KEY" ]] || die "No encuentro SSH_KEY=$SSH_KEY"
# shellcheck disable=SC1090
source "$OPENRC"

echo "[INFO] OpenStack auth check..."
openstack token issue >/dev/null 2>&1 || die "No puedo autenticar contra OpenStack."

echo "[INFO] Listando servidores..."
if [[ -n "$FILTER_STATUS" ]]; then
  mapfile -t SERVER_LINES < <(openstack server list --status "$FILTER_STATUS" -f value -c ID -c Name)
else
  mapfile -t SERVER_LINES < <(openstack server list -f value -c ID -c Name)
fi
[[ "${#SERVER_LINES[@]}" -gt 0 ]] || die "No hay servidores."

printf "\n%-36s  %-24s  %-15s  %-8s  %-14s  %-12s  %-22s\n" \
  "VM_ID" "NAME" "IP" "USER" "OFFSET_ms" "ABS_ms" "STATUS"
printf "%s\n" "---------------------------------------------------------------------------------------------------------------"

max_abs_ms="0.000"
max_vm_id=""
max_vm_name=""
max_vm_ip=""
ok_count=0
fail_count=0

for line in "${SERVER_LINES[@]}"; do
  vm_id="$(echo "$line" | awk '{print $1}')"
  vm_name="$(echo "$line" | awk '{$1=""; sub(/^ /,""); print}')"
  addrs="$(openstack server show "$vm_id" -f value -c addresses 2>/dev/null || true)"
  ip="$(extract_preferred_ipv4 "$addrs" "$PREFERRED_IP_PREFIX")"
  [[ -n "$ip" ]] || continue

  res="$(measure_offset_chrony "$ip")"
  if [[ "$res" == FAIL* ]]; then
    reason="$(echo "$res" | awk '{print $2}')"
    printf "%-36s  %-24s  %-15s  %-8s  %-14s  %-12s  %-22s\n" \
      "$vm_id" "$(echo "$vm_name" | cut -c1-24)" "$ip" "FAIL" "N/A" "N/A" "$reason"
    fail_count=$((fail_count+1))
    continue
  fi

  user="$(echo "$res" | awk '{print $2}')"
  off_ms="$(echo "$res" | awk '{print $3}')"
  abs_ms="$(echo "$res" | awk '{print $4}')"

  printf "%-36s  %-24s  %-15s  %-8s  %-14s  %-12s  %-22s\n" \
    "$vm_id" "$(echo "$vm_name" | cut -c1-24)" "$ip" "$user" "$off_ms" "$abs_ms" "ok"

  ok_count=$((ok_count+1))

  is_gt="$(awk -v a="$abs_ms" -v b="$max_abs_ms" 'BEGIN{print (a>b)?1:0}')"
  if [[ "$is_gt" == "1" ]]; then
    max_abs_ms="$abs_ms"
    max_vm_id="$vm_id"
    max_vm_name="$vm_name"
    max_vm_ip="$ip"
  fi
done

echo
echo "[RESULT] Nodes OK=$ok_count FAIL=$fail_count"
if [[ "$ok_count" -eq 0 ]]; then
  echo "[RESULT] E2 max clock offset/skew (ms) = N/A (no nodes measured)"
else
  echo "[RESULT] E2 max clock offset/skew (ms) = $max_abs_ms"
  echo "[RESULT] Worst node: $max_vm_name | $max_vm_id | $max_vm_ip"
fi