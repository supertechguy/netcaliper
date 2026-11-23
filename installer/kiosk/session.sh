#!/bin/sh
# SPDX-License-Identifier: GPL-3.0-only
# Runs inside cage as ncal-kiosk: rotate portrait panels, wait for core, then Chromium.
# Settings come from /etc/netcaliper/kiosk.env (written by the installer, per platform).
set -u
URL="${KIOSK_URL:-http://127.0.0.1:8080/}"
TRANSFORM="${KIOSK_TRANSFORM:-270}"

# Rotate any output whose current mode is portrait (uConsole DSI panel is 720x1280 native).
if command -v wlr-randr >/dev/null 2>&1; then
	wlr-randr | awk '
		/^[^ ]/ { out = $1 }
		/current/ { split($1, wh, "x"); if (wh[2] + 0 > wh[1] + 0) print out }
	' | while read -r output; do
		[ -n "${KIOSK_OUTPUT:-}" ] && [ "$output" != "$KIOSK_OUTPUT" ] && continue
		wlr-randr --output "$output" --transform "$TRANSFORM" || true
	done
fi

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
