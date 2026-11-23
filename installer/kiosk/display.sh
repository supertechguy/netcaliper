#!/bin/sh
# SPDX-License-Identifier: GPL-3.0-only
# Display control for the kiosk session (runs as ncal-kiosk inside cage).
#
#   kiosk-display rotate               rotate portrait outputs (KIOSK_TRANSFORM, default 270)
#   kiosk-display dim   [--if-battery] dim the backlight to KIOSK_DIM_LEVEL (remembers brightness)
#   kiosk-display blank [--if-battery] power the backlight off
#   kiosk-display wake                 backlight on + restore brightness
#
# Blanking uses the backlight, not output power-off: cage has no output-power protocol, and
# disabling the output would drop VNC viewers (wayvnc captures that output). With the backlight
# off the panel is dark, the GPU idles on a static page, and remote input can still wake it.
set -u
CMD="${1:-}"
GATE="${2:-}"
STATE="${XDG_RUNTIME_DIR:-/tmp}/ncal-brightness"

on_ac() {
	for ps in /sys/class/power_supply/*; do
		[ -r "$ps/type" ] && [ -r "$ps/online" ] || continue
		case "$(cat "$ps/type")" in Mains | USB*) [ "$(cat "$ps/online")" = 1 ] && return 0 ;; esac
	done
	# No mains supply reported at all (desktop/dev host): treat as AC.
	ls /sys/class/power_supply/*/type >/dev/null 2>&1 || return 0
	grep -qx Battery /sys/class/power_supply/*/type 2>/dev/null || return 0
	return 1
}

backlights() { ls -d /sys/class/backlight/* 2>/dev/null; }

save_brightness() {
	[ -f "$STATE" ] && return 0 # keep the original level across dim -> blank
	for b in $(backlights); do echo "$b $(cat "$b/brightness")"; done >"$STATE"
}

[ "$GATE" = --if-battery ] && on_ac && exit 0

case "$CMD" in
rotate)
	command -v wlr-randr >/dev/null 2>&1 || exit 0
	wlr-randr | awk '
		/^[^ ]/ { out = $1 }
		/current/ { split($1, wh, "x"); if (wh[2] + 0 > wh[1] + 0) print out }
	' | while read -r output; do
		[ -n "${KIOSK_OUTPUT:-}" ] && [ "$output" != "$KIOSK_OUTPUT" ] && continue
		wlr-randr --output "$output" --transform "${KIOSK_TRANSFORM:-270}" || true
	done
	;;
dim)
	save_brightness
	for b in $(backlights); do
		lvl="${KIOSK_DIM_LEVEL:-1}"
		[ "$lvl" -lt "$(cat "$b/brightness")" ] && echo "$lvl" >"$b/brightness"
	done
	;;
blank)
	save_brightness
	for b in $(backlights); do
		if [ -w "$b/bl_power" ]; then echo 4 >"$b/bl_power"; else echo 0 >"$b/brightness"; fi
	done
	;;
wake)
	for b in $(backlights); do [ -w "$b/bl_power" ] && echo 0 >"$b/bl_power"; done
	if [ -f "$STATE" ]; then
		while read -r b lvl; do [ -w "$b/brightness" ] && echo "$lvl" >"$b/brightness"; done <"$STATE"
		rm -f "$STATE"
	fi
	;;
*)
	sed -n '3,8p' "$0" | sed 's/^# \{0,1\}//' >&2
	exit 2
	;;
esac
exit 0
