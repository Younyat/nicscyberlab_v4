#!/usr/bin/env bash
set -uo pipefail

# ============================================================
# HOST CLOCK SYNC — NICS CyberLab
# ============================================================
# Root cause fixed here (2026-07-17): this host is a VMware guest with
# BOTH VMware Tools time sync AND chrony/NTP fighting over the clock at
# once. VMware Tools periodically yanks the guest clock towards the
# hypervisor host's own clock, independently of NTP; chrony tries to
# smoothly discipline it via NTP at the same time. The two corrections
# fight, and chrony ends up learning a nonsensical frequency compensation
# trying to track a clock that keeps getting external step-corrections it
# doesn't know about (~222000 ppm observed here vs. a normal few hundred
# ppm at most) -- this is what let a ~10 minute host/VM clock offset
# build up and make causal-reconstruction timestamp ordering ambiguous
# (see forensics/README.md and level_c_orchestrator/README.md).
#
# Idempotent and safe to call every time (Level C calls it automatically
# before every campaign run -- see level_c_orchestrator/service.py
# _phase_sync_node_clocks). Steps 1-2 are one-time structural fixes that
# no-op on every call after the first; step 3 is the actual per-run value
# (forces an immediate correction right before the campaign needs an
# accurate clock, rather than relying on chrony's own polling interval).
#
# Runs as root via the existing NOPASSWD sudoers rule for
# tools-installer/scripts-host/*.sh -- no new sudo privilege was granted
# to add this script.
# ============================================================

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
LOG_DIR="$(dirname "$SCRIPT_DIR")/logs"
LOG_FILE="$LOG_DIR/host_clock_sync.log"
TOOLS_CONF="/etc/vmware-tools/tools.conf"

mkdir -p "$LOG_DIR"
touch "$LOG_FILE"

log_msg() {
    echo "data: [$1] $2"
    echo "$(date '+%Y-%m-%d %H:%M:%S') [HOST-CLOCK] [$1] $2" >> "$LOG_FILE"
}

if [ "$(id -u)" -ne 0 ]; then
    log_msg "ERROR" "Must run as root (invoke via sudo)."
    exit 1
fi

STRUCTURAL_FIX_APPLIED=0
CLOCKSOURCE_FILE="/sys/devices/system/clocksource/clocksource0/current_clocksource"

# 0. TSC is not a reliable clocksource on this VM (observed live: chrony
#    tracking a ~200000 ppm frequency error even right after a clean
#    restart, with no VMware Tools conflict left to explain it — that is
#    the guest's virtualized TSC itself being unstable, not an NTP/VMware
#    Tools fight). Switch to hpet at runtime if available and not already
#    active. This is a live sysfs toggle only (reversible with the same
#    command, no reboot, no bootloader change) — NOT persisted across
#    reboot by this script; see tools-installer/README.md for the GRUB
#    step if it needs to survive a reboot too.
if [ -f "$CLOCKSOURCE_FILE" ]; then
    CURRENT_CS="$(cat "$CLOCKSOURCE_FILE" 2>/dev/null || echo unknown)"
    AVAILABLE_CS="$(cat "$(dirname "$CLOCKSOURCE_FILE")/available_clocksource" 2>/dev/null || echo "")"
    if [ "$CURRENT_CS" = "hpet" ]; then
        log_msg "INFO" "Clocksource already hpet."
    elif echo "$AVAILABLE_CS" | grep -qw hpet; then
        if echo hpet > "$CLOCKSOURCE_FILE" 2>/dev/null; then
            log_msg "FIX" "Switched clocksource from $CURRENT_CS to hpet (runtime only, not persisted across reboot)."
            STRUCTURAL_FIX_APPLIED=1
        else
            log_msg "WARN" "Could not switch clocksource to hpet at runtime."
        fi
    else
        log_msg "WARN" "hpet not in available clocksources ($AVAILABLE_CS) — leaving $CURRENT_CS."
    fi
fi

# 0.5. Persist the hpet clocksource choice across reboots too (the sysfs
#      write above only affects the current, already-running kernel). Only
#      touches GRUB_CMDLINE_LINUX_DEFAULT, appends clocksource=hpet if not
#      already present, and regenerates grub.cfg -- does NOT reboot.
GRUB_DEFAULTS="/etc/default/grub"
if [ -f "$GRUB_DEFAULTS" ]; then
    if grep -q 'clocksource=hpet' "$GRUB_DEFAULTS" 2>/dev/null; then
        log_msg "INFO" "GRUB_CMDLINE_LINUX_DEFAULT already has clocksource=hpet."
    else
        if grep -q '^GRUB_CMDLINE_LINUX_DEFAULT=' "$GRUB_DEFAULTS"; then
            sed -i -E 's/^GRUB_CMDLINE_LINUX_DEFAULT="([^"]*)"/GRUB_CMDLINE_LINUX_DEFAULT="\1 clocksource=hpet"/' "$GRUB_DEFAULTS"
        else
            echo 'GRUB_CMDLINE_LINUX_DEFAULT="clocksource=hpet"' >> "$GRUB_DEFAULTS"
        fi
        if command -v update-grub >/dev/null 2>&1 && update-grub >/dev/null 2>&1; then
            log_msg "FIX" "Added clocksource=hpet to $GRUB_DEFAULTS and regenerated grub.cfg (takes effect on next reboot; the runtime sysfs switch above already applies to the current session)."
            STRUCTURAL_FIX_APPLIED=1
        else
            log_msg "WARN" "Edited $GRUB_DEFAULTS but update-grub failed or is unavailable — next reboot may still boot with the old clocksource."
        fi
    fi
fi

# 1. Persist VMware Tools time sync disabled across reboots (idempotent).
if [ -f "$TOOLS_CONF" ] && grep -q '^\[timesync\]' "$TOOLS_CONF" 2>/dev/null; then
    log_msg "INFO" "VMware Tools [timesync] section already present in $TOOLS_CONF — leaving as-is."
else
    {
        echo ""
        echo "[timesync]"
        echo "disabled = \"TRUE\""
    } >> "$TOOLS_CONF"
    log_msg "FIX" "Persisted [timesync] disabled=TRUE to $TOOLS_CONF so chrony is the sole clock authority, even after reboot."
    STRUCTURAL_FIX_APPLIED=1
fi

# 2. Disable the live VMware Tools time-sync toggle too (runtime, in case
#    vmtoolsd doesn't reread tools.conf until its own restart).
if command -v vmware-toolbox-cmd >/dev/null 2>&1; then
    CURRENT_TS_STATUS="$(vmware-toolbox-cmd timesync status 2>/dev/null || echo unknown)"
    if [ "$CURRENT_TS_STATUS" = "Disabled" ]; then
        log_msg "INFO" "VMware Tools timesync already Disabled (runtime)."
    else
        vmware-toolbox-cmd timesync disable >/dev/null 2>&1 \
            && log_msg "FIX" "Disabled VMware Tools timesync (runtime, was: $CURRENT_TS_STATUS)." \
            || log_msg "WARN" "Could not toggle VMware Tools timesync at runtime (non-fatal, tools.conf change above still applies after next vmtoolsd restart)."
    fi
fi

# 3. Force an immediate correction now. chrony's own `makestep` config
#    directive only auto-steps within the first few updates after chronyd
#    starts, not indefinitely, so a long-uptime drift needs an explicit
#    nudge here rather than waiting for chrony to notice on its own.
if command -v chronyc >/dev/null 2>&1; then
    STEP_OUT="$(chronyc makestep 2>&1)"
    log_msg "INFO" "chronyc makestep: $STEP_OUT"
else
    log_msg "ERROR" "chronyc not found — cannot step the clock."
    exit 1
fi

# 4. Only on the first-ever structural fix: restart chrony so it discards
#    the frequency-compensation state it learned while fighting VMware
#    Tools, instead of slowly re-converging from a wildly wrong baseline.
#    Not done on routine per-campaign calls -- a healthy chrony doesn't
#    need restarting every time, and restarting briefly interrupts its
#    own tracking.
if [ "$STRUCTURAL_FIX_APPLIED" -eq 1 ]; then
    if systemctl restart chrony >/dev/null 2>&1; then
        log_msg "FIX" "Restarted chrony to discard the frequency-compensation state learned while VMware Tools was still fighting it."
    else
        log_msg "WARN" "Could not restart chrony (non-fatal — makestep above already corrected the current offset)."
    fi
fi

log_msg "DONE" "Host clock sync complete."
exit 0
