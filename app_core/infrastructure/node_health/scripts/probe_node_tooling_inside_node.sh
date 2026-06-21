#!/usr/bin/env bash
set -u

kv() {
  printf 'KV\t%s\t%s\n' "$1" "$2"
}

section_begin() {
  printf 'SECTION\t%s\tBEGIN\n' "$1"
}

section_end() {
  printf 'SECTION\t%s\tEND\n' "$1"
}

service_state() {
  local service="$1"
  systemctl is-active "$service" 2>/dev/null || echo "not_installed"
}

pkg_installed() {
  local package="$1"
  dpkg-query -W -f='${Status}\n' "$package" 2>/dev/null | grep -q "install ok installed"
}

pkg_version() {
  local package="$1"
  dpkg-query -W -f='${Version}\n' "$package" 2>/dev/null | head -n 1
}

command_version() {
  local cmd="$1"
  shift
  if ! command -v "$cmd" >/dev/null 2>&1; then
    return 1
  fi
  "$cmd" "$@" 2>/dev/null | head -n 1
}

tool_version() {
  local tool="$1"
  case "$tool" in
    suricata)
      command_version suricata --version || pkg_version suricata || echo "not_available"
      ;;
    wazuh-agent)
      pkg_version wazuh-agent || echo "not_available"
      ;;
    wazuh-manager)
      pkg_version wazuh-manager || echo "not_available"
      ;;
    nmap)
      command_version nmap --version || pkg_version nmap || echo "not_available"
      ;;
    mbpoll)
      command_version mbpoll -h || pkg_version mbpoll || echo "not_available"
      ;;
    zeek)
      command_version zeek --version || pkg_version zeek || echo "not_available"
      ;;
    snort)
      command_version snort -V || pkg_version snort || echo "not_available"
      ;;
    caldera)
      if [[ -d /opt/caldera/.git ]]; then
        git -C /opt/caldera rev-parse --short HEAD 2>/dev/null | awk '{print "git_commit " $0}'
      elif [[ -f /opt/caldera/server.py ]]; then
        echo "/opt/caldera present"
      else
        pkg_version caldera || echo "not_available"
      fi
      ;;
    caldera-agent)
      if [[ -f /etc/systemd/system/caldera-agent.service || -f /usr/local/bin/sandcat ]]; then
        echo "service_or_binary_present"
      else
        pkg_version caldera-agent || echo "not_available"
      fi
      ;;
    *)
      echo "not_available"
      ;;
  esac
}

tool_presence() {
  local tool="$1"
  case "$tool" in
    suricata)
      pkg_installed suricata && echo "installed" || echo "not_installed"
      ;;
    wazuh-agent)
      pkg_installed wazuh-agent && echo "installed" || echo "not_installed"
      ;;
    wazuh-manager)
      pkg_installed wazuh-manager && echo "installed" || echo "not_installed"
      ;;
    zeek)
      pkg_installed zeek && echo "installed" || echo "not_installed"
      ;;
    snort)
      pkg_installed snort && echo "installed" || echo "not_installed"
      ;;
    nmap|mbpoll)
      command -v "$tool" >/dev/null 2>&1 && echo "installed" || echo "not_installed"
      ;;
    caldera)
      if [[ -d /opt/caldera || -f /etc/systemd/system/caldera.service ]]; then
        echo "installed"
      else
        pkg_installed caldera && echo "installed" || echo "not_installed"
      fi
      ;;
    caldera-agent)
      if [[ -f /etc/systemd/system/caldera-agent.service || -f /usr/local/bin/sandcat ]]; then
        echo "installed"
      else
        pkg_installed caldera-agent && echo "installed" || echo "not_installed"
      fi
      ;;
    *)
      echo "unknown"
      ;;
  esac
}

suricata_rule_files() {
  local yaml="/etc/suricata/suricata.yaml"
  if [[ ! -r "$yaml" ]]; then
    return 0
  fi
  awk '
    /^rule-files:[[:space:]]*$/ { in_rules = 1; next }
    in_rules && /^[^[:space:]-]/ { in_rules = 0 }
    in_rules && /^[[:space:]]*-[[:space:]]*/ {
      line = $0
      sub(/^[[:space:]]*-[[:space:]]*/, "", line)
      print line
    }
  ' "$yaml" 2>/dev/null
}

suricata_custom_signatures() {
  local file
  for file in /var/lib/suricata/rules/nics*.rules; do
    [[ -r "$file" ]] || continue
    awk -v file="$(basename "$file")" '
      /^[[:space:]]*#/ { next }
      /alert[[:space:]]/ {
        sid = "unknown"
        msg = "unknown"
        if (match($0, /sid:[0-9]+/)) {
          sid = substr($0, RSTART + 4, RLENGTH - 4)
        }
        if (match($0, /msg:"[^"]+"/)) {
          msg = substr($0, RSTART + 5, RLENGTH - 6)
        }
        printf "%s | sid=%s | msg=%s\n", file, sid, msg
      }
    ' "$file" 2>/dev/null
  done
}

suricata_rule_inventory() {
  local dir="/var/lib/suricata/rules"
  if [[ ! -d "$dir" ]]; then
    return 0
  fi
  find "$dir" -maxdepth 1 -type f 2>/dev/null | sort | while read -r path; do
    printf '%s | %s\n' "$path" "$(stat -c 'size=%s bytes mtime=%y' "$path" 2>/dev/null)"
  done
}

emit_file_contents() {
  local file
  for file in "$@"; do
    [[ -r "$file" ]] || continue
    printf 'FILE\t%s\n' "$file"
    sed -n '1,240p' "$file" 2>/dev/null || true
    printf 'FILE_END\t%s\n' "$file"
  done
}

wazuh_fim_paths() {
  local conf="/var/ossec/etc/ossec.conf"
  if [[ ! -r "$conf" ]]; then
    return 0
  fi
  grep -n '<directories' "$conf" 2>/dev/null || true
}

wazuh_local_rules() {
  local dir="/var/ossec/etc/rules"
  if [[ ! -d "$dir" ]]; then
    return 0
  fi
  find "$dir" -maxdepth 1 -type f 2>/dev/null | sort | while read -r path; do
    printf '%s\n' "$(basename "$path")"
  done
}

wazuh_local_decoders() {
  local dir="/var/ossec/etc/decoders"
  if [[ ! -d "$dir" ]]; then
    return 0
  fi
  find "$dir" -maxdepth 1 -type f 2>/dev/null | sort | while read -r path; do
    printf '%s\n' "$(basename "$path")"
  done
}

wazuh_rule_inventory() {
  local dir
  for dir in /var/ossec/etc/rules /var/ossec/etc/decoders; do
    [[ -d "$dir" ]] || continue
    find "$dir" -maxdepth 1 -type f 2>/dev/null | sort | while read -r path; do
      printf '%s | %s\n' "$path" "$(stat -c 'size=%s bytes mtime=%y' "$path" 2>/dev/null)"
    done
  done
}

kv date_utc "$(date -u +"%Y-%m-%dT%H:%M:%SZ" 2>/dev/null || echo not_available)"

section_begin tool_presence
for tool in suricata wazuh-agent wazuh-manager zeek snort nmap mbpoll caldera caldera-agent; do
  printf '%s=%s\n' "$tool" "$(tool_presence "$tool")"
done
section_end tool_presence

section_begin tool_status
for tool in suricata wazuh-agent wazuh-manager zeek snort openplc docker; do
  printf '%s=%s\n' "$tool" "$(service_state "$tool")"
done
for tool in nmap mbpoll caldera caldera-agent; do
  if command -v "$tool" >/dev/null 2>&1; then
    printf '%s=%s\n' "$tool" "installed"
  else
    printf '%s=%s\n' "$tool" "not_installed"
  fi
done
section_end tool_status

section_begin tool_versions
for tool in suricata wazuh-agent wazuh-manager zeek snort nmap mbpoll caldera caldera-agent; do
  printf '%s=%s\n' "$tool" "$(tool_version "$tool")"
done
section_end tool_versions

section_begin suricata_rule_files
suricata_rule_files
section_end suricata_rule_files

section_begin suricata_custom_signatures
suricata_custom_signatures
section_end suricata_custom_signatures

section_begin suricata_rule_inventory
suricata_rule_inventory
section_end suricata_rule_inventory

section_begin suricata_rule_contents
emit_file_contents /var/lib/suricata/rules/nics*.rules
section_end suricata_rule_contents

section_begin wazuh_fim_paths
wazuh_fim_paths
section_end wazuh_fim_paths

section_begin wazuh_local_rules
wazuh_local_rules
section_end wazuh_local_rules

section_begin wazuh_local_decoders
wazuh_local_decoders
section_end wazuh_local_decoders

section_begin wazuh_rule_inventory
wazuh_rule_inventory
section_end wazuh_rule_inventory

section_begin wazuh_rule_contents
emit_file_contents /var/ossec/etc/rules/*.xml /var/ossec/etc/rules/*.conf /var/ossec/etc/decoders/*.xml /var/ossec/etc/decoders/*.conf
section_end wazuh_rule_contents
