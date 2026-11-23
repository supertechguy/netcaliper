#!/usr/bin/env bash
# SPDX-License-Identifier: GPL-3.0-only
# Reverse install.sh. Keeps data (/var/lib/netcaliper) and config (/etc/netcaliper) unless --purge.
# Apt packages are left installed (they're ordinary system tools). The initramfs workaround is
# left in place: removing it would re-break apt on the uConsole image.
#
#   sudo installer/uninstall.sh [--purge]
set -euo pipefail
trap 'printf "\n  ✗ %s failed at line %s: %s\n" "${0##*/}" "$LINENO" "$BASH_COMMAND" >&2' ERR

HERE=$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)
# Running from /opt/netcaliper (which we delete): re-exec from a temporary copy first.
if [[ $HERE == /opt/netcaliper* && -z ${NCAL_UNINSTALL_COPY:-} ]]; then
	tmp=$(mktemp -d)
	cp -a "$HERE/uninstall.sh" "$tmp/" && mkdir -p "$tmp/lib" && cp -a "$HERE/lib/common.sh" "$tmp/lib/"
	NCAL_UNINSTALL_COPY=$tmp exec bash "$tmp/uninstall.sh" "$@"
fi
# shellcheck source=lib/common.sh
. "$HERE/lib/common.sh"

PURGE=0
for a in "$@"; do
	case $a in
	--purge) PURGE=1 ;;
	-h | --help) sed -n '3,7p' "$0" | sed 's/^# \{0,1\}//' && exit 0 ;;
	*) die "unknown option $a" ;;
	esac
done
need_root "$@"

step "Stopping services"
for u in "$KIOSK_UNIT" netcaliper-core netcaliper-agent netcaliper-helper netcaliper-netns; do
	if systemctl list-unit-files -q "$u.service" >/dev/null 2>&1; then
		systemctl disable -q --now "$u" 2>/dev/null || true
	fi
done
# The netns stop deleted the namespace, returning test interfaces to the root namespace.

step "Restoring the desktop"
dm=$(state_get DISABLED_DM || true)
if [[ -n ${dm:-} ]]; then
	systemctl enable -q "$dm" && info "re-enabled $dm (starts at next boot)"
fi
target=$(state_get DEFAULT_TARGET || true)
[[ -n ${target:-} ]] && systemctl set-default -q "$target"

step "Removing files"
for u in "$KIOSK_UNIT" "${UNITS[@]}"; do remove_file "/etc/systemd/system/$u.service"; done
systemctl daemon-reload
remove_file /etc/pam.d/netcaliper-kiosk
remove_file /etc/tmpfiles.d/netcaliper.conf
rm -rf /run/netcaliper
remove_file /etc/modprobe.d/netcaliper-blacklist-dvb.conf
CHANGED=0
remove_file /etc/udev/rules.d/90-netcaliper.rules
[[ $CHANGED == 1 ]] && udevadm control --reload
CHANGED=0
remove_file "$NM_UNMANAGED"
if [[ $CHANGED == 1 ]] && command -v nmcli >/dev/null; then nmcli general reload conf || true; fi
remove_file /usr/local/bin/netcaliper
rm -rf "$PREFIX" && info "removed $PREFIX"

if [[ $PURGE == 1 ]]; then
	step "Purging data, config and users"
	rm -rf "$STATE_DIR" "$ETC" /var/lib/$KIOSK_USER
	id "$KIOSK_USER" >/dev/null 2>&1 && userdel "$KIOSK_USER"
	id "$SVC_USER" >/dev/null 2>&1 && userdel "$SVC_USER"
	getent group "$SVC_USER" >/dev/null && groupdel "$SVC_USER"
	getent group "$KIOSK_USER" >/dev/null && groupdel "$KIOSK_USER"
else
	rm -f "$STATE_FILE"
	info "kept $STATE_DIR and $ETC (use --purge to remove them and the service users)"
fi
[[ -n ${NCAL_UNINSTALL_COPY:-} ]] && rm -rf "$NCAL_UNINSTALL_COPY"
step "Done"
