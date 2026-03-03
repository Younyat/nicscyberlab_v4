# ============================================================
# Cleanup remoto (seguro)
# - NO borra el dump remoto ($REMOTE_DUMP) ni su directorio padre
# - NO borra /tmp/LiME
# ============================================================

# Normaliza rutas (importante para que las comparaciones funcionen)
REMOTE_DUMP="$(readlink -f "$REMOTE_DUMP" 2>/dev/null || echo "$REMOTE_DUMP")"
REMOTE_DUMP_DIR="$(dirname "$REMOTE_DUMP")"

sudo apt-get clean || true
sudo rm -rf /var/lib/apt/lists/* || true
sudo rm -rf /var/cache/apt/archives/* || true

# Limpieza segura de /tmp:
# borramos hijos directos de /tmp, excepto:
#   - /tmp/LiME
#   - el fichero dump (REMOTE_DUMP)
#   - el directorio que lo contiene (REMOTE_DUMP_DIR) si está dentro de /tmp
if [[ -d /tmp ]]; then
  for p in /tmp/* /tmp/.[!.]* /tmp/..?*; do
    [[ -e "$p" ]] || continue

    # Protecciones
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

df -h / || true