# SPDX-License-Identifier: GPL-3.0-only
# shellcheck shell=bash disable=SC2034  # constants are used by the sourcing scripts
# Shared helpers for install.sh / uninstall.sh. Every step is check-then-apply.

PREFIX=/opt/netcaliper
ETC=/etc/netcaliper
STATE_DIR=/var/lib/netcaliper
STATE_FILE=$STATE_DIR/.installer-state
NETNS=ncal-test
SVC_USER=netcaliper
KIOSK_USER=ncal-kiosk
UNITS=(netcaliper-netns netcaliper-helper netcaliper-agent netcaliper-core)
KIOSK_UNIT=netcaliper-kiosk
NM_UNMANAGED=/etc/NetworkManager/conf.d/90-netcaliper-unmanaged.conf

if [[ -t 1 ]]; then G=$'\e[92m' D=$'\e[2;32m' Y=$'\e[93m' R=$'\e[91m' N=$'\e[0m'; else G='' D='' Y='' R='' N=''; fi
step() { printf '%s==>%s %s\n' "$G" "$N" "$*"; }
info() { printf '%s    %s%s\n' "$D" "$*" "$N"; }
warn() { printf '%s  ! %s%s\n' "$Y" "$*" "$N" >&2; }
die() {
	printf '%s  ✗ %s%s\n' "$R" "$*" "$N" >&2
	exit 1
}

need_root() { [[ $EUID -eq 0 ]] || die "run as root (sudo $0 $*)"; }

# install_file SRC DEST MODE [OWNER:GROUP] — copy only when content differs. Sets CHANGED=1.
CHANGED=0
install_file() {
	local src=$1 dest=$2 mode=$3 owner=${4:-root:root}
	if [[ -f $dest ]] && cmp -s "$src" "$dest"; then
		chmod "$mode" "$dest"
		chown "$owner" "$dest"
		return 0
	fi
	install -D -m "$mode" -o "${owner%%:*}" -g "${owner##*:}" "$src" "$dest"
	info "updated $dest"
	CHANGED=1
}

# render SRC DEST MODE — substitute @PREFIX@ / @NETNS@, then install_file.
render() {
	local tmp
	tmp=$(mktemp)
	sed -e "s|@PREFIX@|$PREFIX|g" -e "s|@NETNS@|$NETNS|g" "$1" >"$tmp"
	install_file "$tmp" "$2" "$3"
	rm -f "$tmp"
}

remove_file() {
	if [[ -e $1 || -L $1 ]]; then
		rm -f "$1"
		info "removed $1"
		CHANGED=1
	fi
}

state_get() { [[ -f $STATE_FILE ]] && sed -n "s/^$1=//p" "$STATE_FILE" | tail -n1; }
state_set() {
	mkdir -p "$STATE_DIR"
	touch "$STATE_FILE"
	sed -i "/^$1=/d" "$STATE_FILE"
	echo "$1=$2" >>"$STATE_FILE"
}

os_field() { sed -n "s/^$1=//p" /etc/os-release | tr -d '"'; }

# uConsole: keyboard/trackball MCU 1eaf:0024 is always present (device tree doesn't name it).
is_uconsole() {
	local d
	for d in /sys/bus/usb/devices/*; do
		[[ -f $d/idVendor ]] || continue
		[[ $(<"$d/idVendor"):$(<"$d/idProduct") == 1eaf:0024 ]] && return 0
	done
	return 1
}

# Prints the enabled display manager's unit name, or nothing. Always succeeds (safe under set -e).
current_dm() {
	local link
	link=$(readlink -f "${1:-/etc/systemd/system}/display-manager.service" 2>/dev/null) || return 0
	if [[ -n $link && -e $link ]]; then basename "$link" .service; fi
	return 0
}
