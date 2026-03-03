#!/usr/bin/env bash
set -euo pipefail

# ==============================================================================
# Script: analyze_disk_tsk.sh (Professional Version with Auto-Extraction)
# ==============================================================================

if [[ $# -lt 2 ]]; then
    echo "Usage: $0 <CASEASE_DIR> <DISK_RAW_ABS_PATH> [OUT_DIR_ABS]"
    exit 1
fi

CASE_DIR="$1"
DISK="$2"

# [ADDED] Optional OUT dir (for backend compatibility). If not provided, keep your default.
OUT_ARG="${3:-}"

# 1) File Validations
[[ -d "$CASE_DIR" ]] || { echo "ERROR: CASE_DIR does not exist"; exit 1; }
[[ -f "$DISK" ]] || { echo "ERROR: Disk file not found"; exit 1; }

# Keep your original default OUT, but allow override if arg3 exists
OUT="$CASE_DIR/analysis/disk/tsk"
if [[ -n "$OUT_ARG" ]]; then
    OUT="$OUT_ARG"
fi
mkdir -p "$OUT"

echo "[*] Starting TSK Forensic Analysis (Sleuth Kit)"
echo "[*] Image: $DISK"
echo "[*] Destination: $OUT"
echo "---------------------------------------------------"

# 2) Identify partitions with mmls
echo "[*] Analyzing partition table (mmls)..."
mmls "$DISK" > "$OUT/mmls.txt" 2>/dev/null || true

# Extract Offset candidates by removing leading zeros
# ORIGINAL (kept):
CANDIDATES=$(awk '$0 ~ /^[[:space:]]*[0-9]+:/ { s=$3; if (s ~ /^[0-9]+$/) print s }' "$OUT/mmls.txt" | sed 's/^0*//' | sort -n | uniq)

# [ADDED] More robust candidates parser (typical mmls: slot: start end length desc => start is $2).
# If the original produced nothing, fall back to this.
if [[ -z "${CANDIDATES:-}" ]]; then
    CANDIDATES=$(awk '
      /^[[:space:]]*[0-9]+:/ {
        s=$2;
        if (s ~ /^[0-9]+$/) print s
      }' "$OUT/mmls.txt" | sed 's/^0*//' | sort -n | uniq)
fi

# [ADDED] Safety fallback: at least try offset 0
if [[ -z "${CANDIDATES:-}" ]]; then
    CANDIDATES="0"
fi

# 3) Partition Analysis Loop
FOUND_FS=0
for off in $CANDIDATES; do
    [[ -z "$off" ]] && off=0

    # Check if Sleuth Kit recognizes a File System at this offset
    FS_INFO=$(fsstat -o "$off" "$DISK" 2>/dev/null | grep "File System Type:" || true)

    if [[ -n "$FS_INFO" ]]; then
        FOUND_FS=$((FOUND_FS + 1))
        FS_TYPE=$(echo "$FS_INFO" | cut -d: -f2 | xargs)

        PART_OUT="$OUT/partition_offset_$off"
        mkdir -p "$PART_OUT"

        echo "[+] Partition detected ($FS_TYPE) at offset $off"
        echo "    -> Extracting metadata to $PART_OUT..."

        # Save FS details
        fsstat -o "$off" "$DISK" > "$PART_OUT/fsstat.txt" 2>/dev/null || true

        # Generate Bodyfile (mactime input format)
        # Using -m to define the virtual mount point in the report
        fls -r -m "/offset_$off" -o "$off" "$DISK" > "$PART_OUT/bodyfile.txt" 2> "$PART_OUT/fls.err" || true

        # Generate Timeline if bodyfile is not empty
        if [[ -s "$PART_OUT/bodyfile.txt" ]]; then
            mactime -b "$PART_OUT/bodyfile.txt" -d -y > "$PART_OUT/timeline.csv" 2>/dev/null || true
            echo "    -> [OK] Timeline generated successfully."

            # --- NEW SECTION: AUTOMATIC EVIDENCE EXTRACTION ---
            # If Ext4, attempt to recover critical files using inodes
            if [[ "$FS_TYPE" == *"Ext4"* ]]; then
                echo "    -> [EXTRACT] Recovering critical Linux files..."
                RECOVERY_DIR="$PART_OUT/recovered_evidence"
                mkdir -p "$RECOVERY_DIR"

                # Look for specific inodes in the newly generated bodyfile
                # Format: MD5|name|inode|mode_as_string|UID|GID|size|atime|mtime|ctime|crtime

                # 1. Recover auth.log
                AUTH_INODE=$(grep "var/log/auth.log" "$PART_OUT/bodyfile.txt" | cut -d'|' -f3 | head -n 1 || true)
                # [ADDED] More exact match fallback
                if [[ -z "${AUTH_INODE:-}" ]]; then
                    AUTH_INODE=$(grep "|/var/log/auth.log|" "$PART_OUT/bodyfile.txt" | cut -d'|' -f3 | head -n 1 || true)
                fi
                if [[ -n "${AUTH_INODE:-}" ]]; then
                    icat -o "$off" "$DISK" "$AUTH_INODE" > "$RECOVERY_DIR/auth.log" 2>/dev/null || true
                    echo "       [+] auth.log recovered."
                fi

                # 2. Recover .bash_history for user ubuntu (UID 1000)
                BASH_INODE=$(grep "home/ubuntu/.bash_history" "$PART_OUT/bodyfile.txt" | cut -d'|' -f3 | head -n 1 || true)
                # [ADDED] More exact match fallback
                if [[ -z "${BASH_INODE:-}" ]]; then
                    BASH_INODE=$(grep "|/home/ubuntu/.bash_history|" "$PART_OUT/bodyfile.txt" | cut -d'|' -f3 | head -n 1 || true)
                fi
                if [[ -n "${BASH_INODE:-}" ]]; then
                    icat -o "$off" "$DISK" "$BASH_INODE" > "$RECOVERY_DIR/bash_history_ubuntu" 2>/dev/null || true
                    echo "       [+] .bash_history (ubuntu) recovered."
                fi

                # 3. Recover /etc/passwd to verify users
                PASSWD_INODE=$(grep "etc/passwd" "$PART_OUT/bodyfile.txt" | cut -d'|' -f3 | head -n 1 || true)
                # [ADDED] More exact match fallback
                if [[ -z "${PASSWD_INODE:-}" ]]; then
                    PASSWD_INODE=$(grep "|/etc/passwd|" "$PART_OUT/bodyfile.txt" | cut -d'|' -f3 | head -n 1 || true)
                fi
                if [[ -n "${PASSWD_INODE:-}" ]]; then
                    icat -o "$off" "$DISK" "$PASSWD_INODE" > "$RECOVERY_DIR/passwd" 2>/dev/null || true
                    echo "       [+] /etc/passwd recovered."
                fi
            fi
            # -------------------------------------------------------
        else
            echo "    -> [!] Could not extract files (possible unsupported or empty FS)."
        fi
    fi
done

if [[ $FOUND_FS -eq 0 ]]; then
    echo "[!] No compatible file systems were detected."
fi

# 4) Global Strings Extraction
echo "---------------------------------------------------"
echo "[*] Extracting text strings (strings) from disk..."
strings -a -n 8 "$DISK" | head -n 20000 > "$OUT/strings_head.txt" 2>/dev/null || true

echo "[*] Analysis complete."
echo "$OUT"