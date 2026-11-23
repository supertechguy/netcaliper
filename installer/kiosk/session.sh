#!/bin/sh
# SPDX-License-Identifier: GPL-3.0-only
# Runs inside cage as ncal-kiosk: rotate portrait panels, wait for core, then Chromium.
# Settings come from /etc/netcaliper/kiosk.env (written by the installer, per platform).
set -u
URL="${KIOSK_URL:-http://127.0.0.1:8080/}"

DISPLAY_CTL="$(dirname "$0")/kiosk-display"

"$DISPLAY_CTL" wake # a previous session may have died while blanked
"$DISPLAY_CTL" rotate

# Remote view/control (opt-in: install.sh --vnc). Listens in the root namespace only, so it is
# reachable from the management network but never from a network under test (test netns).
VNC_CONF=/etc/netcaliper/wayvnc/config
if [ "${KIOSK_VNC:-0}" = 1 ] && [ -r "$VNC_CONF" ] && command -v wayvnc >/dev/null 2>&1; then
	(while :; do
		wayvnc --config="$VNC_CONF" || true
		sleep 2
	done) &
fi

# Wait (up to 90 s) for core; Chromium's own error page is uglier than a black screen.
i=0
while [ $i -lt 90 ] && ! curl -fsS -o /dev/null --max-time 2 "${URL%/}/api/v1/health"; do
	i=$((i + 1))
	sleep 1
done

# Power saving: dim, then blank the backlight after inactivity (any key, trackball or VNC input
# wakes it). Optional shorter timeouts on battery. 0 disables. The UI mirrors KIOSK_BLANK_S so the
# input that wakes the screen doesn't also trigger an action. Started only now (core is up,
# Chromium next) so its clock and the page's start together.
BLANK="${KIOSK_BLANK_S:-600}"
DIM="${KIOSK_DIM_S:-$((BLANK - 60))}"
if [ "$BLANK" -gt 0 ] && command -v swayidle >/dev/null 2>&1; then
	set -- -w
	[ "$DIM" -gt 0 ] && [ "$DIM" -lt "$BLANK" ] &&
		set -- "$@" timeout "$DIM" "$DISPLAY_CTL dim" resume "$DISPLAY_CTL wake"
	set -- "$@" timeout "$BLANK" "$DISPLAY_CTL blank" resume "$DISPLAY_CTL wake"
	BB="${KIOSK_BLANK_S_BATTERY:-0}"
	if [ "$BB" -gt 0 ] && [ "$BB" -lt "$BLANK" ]; then
		BD="${KIOSK_DIM_S_BATTERY:-$((BB - 30))}"
		[ "$BD" -gt 0 ] && [ "$BD" -lt "$BB" ] &&
			set -- "$@" timeout "$BD" "$DISPLAY_CTL dim --if-battery" resume "$DISPLAY_CTL wake"
		set -- "$@" timeout "$BB" "$DISPLAY_CTL blank --if-battery" resume "$DISPLAY_CTL wake"
	fi
	(while :; do
		swayidle "$@" || true
		sleep 2
	done) &
fi

for b in chromium chromium-browser; do
	command -v "$b" >/dev/null 2>&1 && BROWSER="$b" && break
done
[ -n "${BROWSER:-}" ] || { echo "kiosk: no chromium found" >&2; exit 1; }

# Fresh profile each start: no restore bubbles, no stale state.
PROFILE="${HOME:-/var/lib/ncal-kiosk}/chromium"
rm -rf "$PROFILE"
# shellcheck disable=SC2086  # KIOSK_CHROMIUM_FLAGS is a deliberately word-split flag list
exec "$BROWSER" \
	--kiosk --ozone-platform=wayland \
	--user-data-dir="$PROFILE" \
	--no-first-run --noerrdialogs --disable-infobars --disable-session-crashed-bubble \
	--disable-translate --disable-features=Translate,MediaRouter,HardwareMediaKeyHandling \
	--password-store=basic --disable-component-update --check-for-update-interval=31536000 \
	--disable-pinch --overscroll-history-navigation=0 \
	${KIOSK_CHROMIUM_FLAGS:-} \
	"$URL"
