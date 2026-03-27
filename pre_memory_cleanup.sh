# ============================================================
# Remote cleanup for low free space on /
# - Does NOT remove the remote dump file
# - Does NOT remove its parent directory
# - Does NOT remove /tmp/LiME
# ============================================================

REMOTE_DUMP="$(readlink -f "$REMOTE_DUMP" 2>/dev/null || echo "$REMOTE_DUMP")"
REMOTE_DUMP_DIR="$(dirname "$REMOTE_DUMP")"

echo "[INFO] Disk usage before cleanup:"
df -h / || true

# APT cache and package lists
sudo apt-get clean || true
sudo rm -rf /var/lib/apt/lists/* || true
sudo rm -rf /var/cache/apt/archives/* || true

# Journal cleanup
sudo journalctl --vacuum-size=50M || true

# Old rotated logs
sudo find /var/log -type f -name "*.gz" -delete || true
sudo find /var/log -type f -name "*.1" -delete || true

# Optional: truncate large current logs safely
sudo find /var/log -type f -size +20M -exec truncate -s 0 {} \; 2>/dev/null || true

# Safe cleanup of /tmp
if [[ -d /tmp ]]; then
  for p in /tmp/* /tmp/.[!.]* /tmp/..?*; do
    [[ -e "$p" ]] || continue

    if [[ "$p" == "/tmp/LiME" || "$p" == "/tmp/LiME/"* ]]; then
      continue
    fi

    if [[ "$p" == "$REMOTE_DUMP" ]]; then
      continue
    fi

    if [[ "$REMOTE_DUMP_DIR" == /tmp/* && "$p" == "$REMOTE_DUMP_DIR" ]]; then
      continue
    fi

    sudo rm -rf -- "$p" 2>/dev/null || true
  done
fi

echo "[INFO] Largest directories under /var:"
sudo du -xh /var 2>/dev/null | sort -h | tail -n 20 || true

echo "[INFO] Disk usage after cleanup:"
df -h / || true