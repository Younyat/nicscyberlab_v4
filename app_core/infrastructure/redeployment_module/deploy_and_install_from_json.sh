#!/usr/bin/env bash
set -euo pipefail

trap 'echo "[ERROR] Failed at line ${LINENO}" >&2' ERR

# ============================================================
# deploy_and_install_from_json.sh
#
# Usage:
#   bash deploy_and_install_from_json.sh <scenario_json> [tools_json_dir_or_file]
#
# Examples:
#   bash deploy_and_install_from_json.sh scenario_file.json
#   bash deploy_and_install_from_json.sh scenario_file.json tools-installer-tmp
#   bash deploy_and_install_from_json.sh scenario_file.json victim_33_tools.json
#
# What it does:
#   1. Deploy scenario from scenario JSON
#   2. Ignore properties.ip from scenario JSON
#   3. Read tools JSON files
#   4. Install tools only for matching deployed instances
#   5. Update each tools JSON with real OpenStack data
#   6. Print final summary
# ============================================================

SCENARIO_JSON_INPUT="${1:-}"
TOOLS_JSON_SOURCE="${2:-}"

if [[ -z "$SCENARIO_JSON_INPUT" ]]; then
    echo "Usage: $0 <scenario_json> [tools_json_dir_or_file]"
    exit 1
fi

for bin in jq openstack bash; do
    if ! command -v "$bin" >/dev/null 2>&1; then
        echo "ERROR: Missing dependency: $bin"
        exit 1
    fi
done

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"

find_repo_root() {
    local dir="$1"
    while [[ "$dir" != "/" ]]; do
        if [[ -f "$dir/admin-openrc.sh" && -f "$dir/scenario/main_generator_inicial_openstack.sh" ]]; then
            echo "$dir"
            return 0
        fi
        dir="$(dirname "$dir")"
    done
    return 1
}

REPO_ROOT="$(find_repo_root "$SCRIPT_DIR")" || {
    echo "ERROR: Could not find project root"
    exit 1
}

ADMIN_OPENRC="$REPO_ROOT/admin-openrc.sh"
GENERATOR_SCRIPT="$REPO_ROOT/scenario/main_generator_inicial_openstack.sh"
TF_OUT_DIR="$REPO_ROOT/tf_out"
TOOLS_SCRIPTS_DIR="$REPO_ROOT/tools-installer/scripts"
LOGS_DIR="$REPO_ROOT/tools-installer/logs"

if [[ -d "$SCRIPT_DIR/tools-installer-tmp" ]]; then
    DEFAULT_TOOLS_DIR="$SCRIPT_DIR/tools-installer-tmp"
else
    DEFAULT_TOOLS_DIR="$REPO_ROOT/tools-installer-tmp"
fi

mkdir -p "$TF_OUT_DIR" "$LOGS_DIR"

if [[ ! -f "$ADMIN_OPENRC" ]]; then
    echo "ERROR: admin-openrc.sh not found: $ADMIN_OPENRC"
    exit 1
fi

if [[ ! -f "$GENERATOR_SCRIPT" ]]; then
    echo "ERROR: scenario generator not found: $GENERATOR_SCRIPT"
    exit 1
fi

resolve_path() {
    local input="$1"

    if [[ -f "$input" || -d "$input" ]]; then
        echo "$(cd "$(dirname "$input")" && pwd)/$(basename "$input")"
        return 0
    fi

    if [[ -f "$SCRIPT_DIR/$input" || -d "$SCRIPT_DIR/$input" ]]; then
        echo "$SCRIPT_DIR/$input"
        return 0
    fi

    if [[ -f "$REPO_ROOT/scenario/$input" ]]; then
        echo "$REPO_ROOT/scenario/$input"
        return 0
    fi

    if [[ -f "$REPO_ROOT/$input" || -d "$REPO_ROOT/$input" ]]; then
        echo "$REPO_ROOT/$input"
        return 0
    fi

    return 1
}

SCENARIO_JSON="$(resolve_path "$SCENARIO_JSON_INPUT")" || {
    echo "ERROR: Scenario JSON not found: $SCENARIO_JSON_INPUT"
    exit 1
}

if [[ -n "$TOOLS_JSON_SOURCE" ]]; then
    TOOLS_SOURCE_RESOLVED="$(resolve_path "$TOOLS_JSON_SOURCE")" || {
        echo "ERROR: Tools path not found: $TOOLS_JSON_SOURCE"
        exit 1
    }
else
    if [[ -d "$DEFAULT_TOOLS_DIR" || -f "$DEFAULT_TOOLS_DIR" ]]; then
        TOOLS_SOURCE_RESOLVED="$DEFAULT_TOOLS_DIR"
    else
        echo "ERROR: No default tools source found"
        echo "Checked: $DEFAULT_TOOLS_DIR"
        exit 1
    fi
fi

TMP_DIR="$(mktemp -d)"
trap 'rm -rf "$TMP_DIR"' EXIT

CLEAN_SCENARIO_JSON="$TMP_DIR/scenario_clean.json"
DEPLOYED_NAMES_FILE="$TMP_DIR/deployed_names.txt"
TOOLS_FILES_LIST="$TMP_DIR/tools_files.txt"

echo "===================================================="
echo " DEPLOY AND INSTALL"
echo "===================================================="
echo "Project root   : $REPO_ROOT"
echo "Scenario JSON  : $SCENARIO_JSON"
echo "Tools source   : $TOOLS_SOURCE_RESOLVED"
echo

NODE_COUNT="$(jq -r '.nodes | length' "$SCENARIO_JSON" 2>/dev/null || echo 0)"
if [[ "$NODE_COUNT" -eq 0 ]]; then
    echo "ERROR: No nodes found in scenario JSON"
    exit 1
fi

jq -r '.nodes[].name' "$SCENARIO_JSON" > "$DEPLOYED_NAMES_FILE"

jq '
  .nodes |= map(
    if has("properties") and (.properties | type == "object")
    then .properties |= del(.ip)
    else .
    end
  )
' "$SCENARIO_JSON" > "$CLEAN_SCENARIO_JSON"

echo "Scenario nodes: $NODE_COUNT"
echo "Clean scenario created"
echo

# shellcheck disable=SC1090
source "$ADMIN_OPENRC"
echo "OpenStack credentials loaded"
echo

chmod +x "$GENERATOR_SCRIPT"

echo "===================================================="
echo " STEP 1 - DEPLOY SCENARIO"
echo "===================================================="
echo

bash "$GENERATOR_SCRIPT" "$CLEAN_SCENARIO_JSON" "$TF_OUT_DIR"

echo
echo "Scenario deployment finished"
echo

sleep 5

get_instance_info_json() {
    local instance_name="$1"
    openstack server show "$instance_name" -f json 2>/dev/null || true
}

get_instance_image_name() {
    local raw="$1"
    echo "$raw" | jq -r '.image // .image_name // "unknown"'
}

detect_ssh_user_from_image() {
    local image_name="$1"
    local low
    low="$(echo "$image_name" | tr '[:upper:]' '[:lower:]')"

    if [[ "$low" == *ubuntu* ]]; then
        echo "ubuntu"
    elif [[ "$low" == *kali* ]]; then
        echo "kali"
    else
        echo "debian"
    fi
}

extract_ips_from_addresses() {
    local raw="$1"
    local addresses
    local ip_private="N/A"
    local ip_floating="N/A"

    addresses="$(echo "$raw" | jq -r '.addresses // empty')"

    if [[ -n "$addresses" ]]; then
        mapfile -t IPS < <(grep -Eo '([0-9]{1,3}\.){3}[0-9]{1,3}' <<< "$addresses" || true)
        if [[ "${#IPS[@]}" -ge 1 ]]; then
            ip_private="${IPS[0]}"
        fi
        if [[ "${#IPS[@]}" -ge 2 ]]; then
            ip_floating="${IPS[1]}"
        fi
    fi

    echo "${ip_private}|${ip_floating}"
}

is_name_in_deployed_scenario() {
    local target="$1"
    grep -Fxq "$target" "$DEPLOYED_NAMES_FILE"
}

collect_tools_files() {
    local source_path="$1"
    : > "$TOOLS_FILES_LIST"

    if [[ -f "$source_path" ]]; then
        echo "$source_path" >> "$TOOLS_FILES_LIST"
        return 0
    fi

    if [[ -d "$source_path" ]]; then
        find "$source_path" -maxdepth 1 -type f -name '*_tools.json' | sort > "$TOOLS_FILES_LIST"
        return 0
    fi

    return 1
}

collect_tools_files "$TOOLS_SOURCE_RESOLVED"

TOOLS_FILES_COUNT="$(wc -l < "$TOOLS_FILES_LIST" | tr -d ' ')"

echo "===================================================="
echo " STEP 2 - INSTALL TOOLS"
echo "===================================================="
echo "Tools JSON files found: $TOOLS_FILES_COUNT"
echo

if [[ "$TOOLS_FILES_COUNT" -eq 0 ]]; then
    echo "No tools JSON files found"
    echo
else
    while IFS= read -r TOOL_JSON_FILE; do
        [[ -n "$TOOL_JSON_FILE" ]] || continue

        INSTANCE_NAME="$(jq -r '.name // empty' "$TOOL_JSON_FILE")"
        if [[ -z "$INSTANCE_NAME" ]]; then
            echo "Skip file without instance name: $TOOL_JSON_FILE"
            echo
            continue
        fi

        if ! is_name_in_deployed_scenario "$INSTANCE_NAME"; then
            echo "Skip tools file. Instance not in deployed scenario: $INSTANCE_NAME"
            echo
            continue
        fi

        RAW_INFO="$(get_instance_info_json "$INSTANCE_NAME")"
        if [[ -z "$RAW_INFO" ]]; then
            echo "Instance not found in OpenStack: $INSTANCE_NAME"
            echo
            continue
        fi

        INSTANCE_ID="$(echo "$RAW_INFO" | jq -r '.id // "N/A"')"
        INSTANCE_STATUS="$(echo "$RAW_INFO" | jq -r '.status // "N/A"')"
        IMAGE_NAME="$(get_instance_image_name "$RAW_INFO")"
        SSH_USER="$(detect_ssh_user_from_image "$IMAGE_NAME")"

        IPS_DATA="$(extract_ips_from_addresses "$RAW_INFO")"
        IP_PRIVATE="${IPS_DATA%%|*}"
        IP_FLOATING="${IPS_DATA##*|}"

        if [[ "$IP_FLOATING" != "N/A" ]]; then
            TARGET_IP="$IP_FLOATING"
        else
            TARGET_IP="$IP_PRIVATE"
        fi

        echo "----------------------------------------------------"
        echo "Instance: $INSTANCE_NAME"
        echo "ID      : $INSTANCE_ID"
        echo "Status  : $INSTANCE_STATUS"
        echo "User    : $SSH_USER"
        echo "IP      : $TARGET_IP"
        echo "File    : $TOOL_JSON_FILE"
        echo "----------------------------------------------------"

        jq \
          --arg id "$INSTANCE_ID" \
          --arg ip "$TARGET_IP" \
          --arg ip_private "$IP_PRIVATE" \
          --arg ip_floating "$IP_FLOATING" \
          --arg status "$INSTANCE_STATUS" \
          '
          .id = $id
          | .ip = $ip
          | .ip_private = $ip_private
          | .ip_floating = $ip_floating
          | .status = $status
          ' "$TOOL_JSON_FILE" > "${TOOL_JSON_FILE}.tmp" && mv "${TOOL_JSON_FILE}.tmp" "$TOOL_JSON_FILE"

        mapfile -t TOOLS < <(jq -r '.tools | keys[]?' "$TOOL_JSON_FILE")

        if [[ "${#TOOLS[@]}" -eq 0 ]]; then
            echo "No tools in JSON"
            echo
            continue
        fi

        for TOOL in "${TOOLS[@]}"; do
            CURRENT_STATUS="$(jq -r ".tools.\"$TOOL\"" "$TOOL_JSON_FILE")"

            if [[ "$CURRENT_STATUS" == "installed" ]]; then
                echo "[SKIPPED] $TOOL already installed"
                continue
            fi

            SCRIPT_PATH="$TOOLS_SCRIPTS_DIR/install_${TOOL}.sh"
            LOG_FILE="$LOGS_DIR/${INSTANCE_NAME// /_}_${TOOL}.log"

            if [[ ! -f "$SCRIPT_PATH" ]]; then
                echo "[ERROR] Install script not found: $SCRIPT_PATH"
                jq ".tools.\"$TOOL\" = \"error\"" "$TOOL_JSON_FILE" > "${TOOL_JSON_FILE}.tmp" && mv "${TOOL_JSON_FILE}.tmp" "$TOOL_JSON_FILE"
                continue
            fi

            chmod +x "$SCRIPT_PATH"
            echo "[INSTALLING] $TOOL ..."

            if bash "$SCRIPT_PATH" "$TARGET_IP" "$SSH_USER" >"$LOG_FILE" 2>&1; then
                echo "[SUCCESS] $TOOL installed"
                jq ".tools.\"$TOOL\" = \"installed\"" "$TOOL_JSON_FILE" > "${TOOL_JSON_FILE}.tmp" && mv "${TOOL_JSON_FILE}.tmp" "$TOOL_JSON_FILE"
            else
                echo "[ERROR] $TOOL failed. Log: $LOG_FILE"
                jq ".tools.\"$TOOL\" = \"error\"" "$TOOL_JSON_FILE" > "${TOOL_JSON_FILE}.tmp" && mv "${TOOL_JSON_FILE}.tmp" "$TOOL_JSON_FILE"
            fi
        done

        echo
    done < "$TOOLS_FILES_LIST"
fi

echo "===================================================="
echo " FINAL SUMMARY"
echo "===================================================="
echo

while IFS= read -r INSTANCE_NAME; do
    [[ -n "$INSTANCE_NAME" ]] || continue

    RAW_INFO="$(get_instance_info_json "$INSTANCE_NAME")"

    if [[ -z "$RAW_INFO" ]]; then
        echo "Instance: $INSTANCE_NAME"
        echo "  Status: NOT FOUND"
        echo
        continue
    fi

    INSTANCE_ID="$(echo "$RAW_INFO" | jq -r '.id // "N/A"')"
    INSTANCE_STATUS="$(echo "$RAW_INFO" | jq -r '.status // "N/A"')"
    IMAGE_NAME="$(get_instance_image_name "$RAW_INFO")"

    IPS_DATA="$(extract_ips_from_addresses "$RAW_INFO")"
    IP_PRIVATE="${IPS_DATA%%|*}"
    IP_FLOATING="${IPS_DATA##*|}"

    echo "Instance    : $INSTANCE_NAME"
    echo "ID          : $INSTANCE_ID"
    echo "Status      : $INSTANCE_STATUS"
    echo "Image       : $IMAGE_NAME"
    echo "IP private  : $IP_PRIVATE"
    echo "IP floating : $IP_FLOATING"

    MATCHED_TOOL_FILE=""
    while IFS= read -r TOOL_JSON_FILE; do
        [[ -n "$TOOL_JSON_FILE" ]] || continue
        TOOL_INSTANCE_NAME="$(jq -r '.name // empty' "$TOOL_JSON_FILE")"
        if [[ "$TOOL_INSTANCE_NAME" == "$INSTANCE_NAME" ]]; then
            MATCHED_TOOL_FILE="$TOOL_JSON_FILE"
            break
        fi
    done < "$TOOLS_FILES_LIST"

    if [[ -n "$MATCHED_TOOL_FILE" ]]; then
        echo "Tools       :"
        TOOLS_OUTPUT="$(jq -r '
          (.tools // {})
          | to_entries[]
          | "  - \(.key): \(.value)"
        ' "$MATCHED_TOOL_FILE")"

        if [[ -z "$TOOLS_OUTPUT" ]]; then
            echo "  - None"
        else
            echo "$TOOLS_OUTPUT"
        fi
    else
        echo "Tools       :"
        echo "  - No tools JSON matched"
    fi

    echo
done < "$DEPLOYED_NAMES_FILE"

echo "===================================================="
echo " DONE"
echo "===================================================="