#!/usr/bin/env bash
# SPDX-License-Identifier: GPL-3.0-only
# netcaliper installer — idempotent: re-running converges to the same state.
#
#   sudo installer/install.sh              # device (Pi OS / uConsole): services + kiosk
#   sudo installer/install.sh --dev        # x86 dev host: services, no kiosk, no OS tweaks
#   sudo installer/install.sh --no-kiosk   # device without the kiosk
#   sudo installer/install.sh --vnc        # also serve the kiosk screen over VNC (auth + TLS)
#
# Options: --dev --no-kiosk --start-kiosk --vnc --no-vnc --skip-apt --branch NAME --repo URL --help
set -euo pipefail
trap 'printf "\n  ✗ %s failed at line %s: %s\n" "${0##*/}" "$LINENO" "$BASH_COMMAND" >&2' ERR

HERE=$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)
# shellcheck source=lib/common.sh
. "$HERE/lib/common.sh"

ORIG_ARGS=("$@")
DEV=0 KIOSK=1 START_KIOSK=0 SKIP_APT=0 BRANCH=main REPO=https://github.com/supertechguy/netcaliper.git
VNC=""
usage() { sed -n '3,10p' "$0" | sed 's/^# \{0,1\}//'; }
while [[ $# -gt 0 ]]; do
	case $1 in
	--dev) DEV=1 KIOSK=0 ;;
	--no-kiosk) KIOSK=0 ;;
	--start-kiosk) START_KIOSK=1 ;;
	--vnc) VNC=1 ;;
	--no-vnc) VNC=0 ;;
	--skip-apt) SKIP_APT=1 ;;
	--branch) BRANCH=${2:?--branch needs a name} && shift ;;
	--repo) REPO=${2:?--repo needs a URL} && shift ;;
	-h | --help) usage && exit 0 ;;
	*) die "unknown option $1 (see --help)" ;;
	esac
	shift
done
need_root "$@"

# ------------------------------------------------------------------ preflight

step "Preflight"
[[ -f /etc/os-release ]] || die "no /etc/os-release: unsupported OS"
OS_ID=$(os_field ID) OS_CODENAME=$(os_field VERSION_CODENAME) OS_NAME=$(os_field PRETTY_NAME)
ARCH=$(uname -m)
case "$OS_ID:$(os_field ID_LIKE)" in
debian:* | raspbian:* | ubuntu:* | *:*debian*) ;;
*) die "unsupported OS $OS_NAME (Debian, Raspberry Pi OS or Ubuntu required)" ;;
esac
command -v systemctl >/dev/null || die "systemd is required"
UCONSOLE=0
is_uconsole && UCONSOLE=1
[[ -z $VNC ]] && VNC=$(state_get VNC || true) # remembered across re-runs
VNC=${VNC:-0}
[[ $KIOSK == 0 ]] && VNC=0
info "$OS_NAME ($OS_CODENAME, $ARCH)$([[ $UCONSOLE == 1 ]] && echo ', ClockworkPi uConsole')$([[ $DEV == 1 ]] && echo ', dev host')"
if [[ $DEV == 0 && $ARCH != aarch64 && $ARCH != armv7l ]]; then
	warn "not an ARM board: consider --dev"
fi

# Source tree: this checkout if we're in one, else clone.
SRC=$(cd "$HERE/.." && pwd)
if [[ ! -f $SRC/device/pyproject.toml ]]; then
	command -v git >/dev/null || apt-get install -y git
	SRC=$PREFIX/src
	if [[ -d $SRC/.git ]]; then
		git -C "$SRC" fetch --depth 1 origin "$BRANCH" && git -C "$SRC" checkout -q -B "$BRANCH" FETCH_HEAD
	else
		git clone --depth 1 --branch "$BRANCH" "$REPO" "$SRC"
	fi
	exec "$SRC/installer/install.sh" "${ORIG_ARGS[@]}"
fi
info "source $SRC"

# ------------------------------------------------------------------ apt repair (uConsole image)

if [[ $DEV == 0 && -d /etc/initramfs-tools ]] && [[ $(findmnt -no SOURCE / 2>/dev/null) == /dev/root ]]; then
	step "Boot/apt workaround (no initramfs; root is /dev/root)"
	install_file "$SRC/installer/initramfs/root-device-workaround" \
		/etc/initramfs-tools/conf.d/root-device-workaround 0644
fi
if [[ -n $(dpkg --audit 2>/dev/null) ]]; then
	step "Repairing half-configured packages"
	DEBIAN_FRONTEND=noninteractive dpkg --configure -a --force-confold
fi

# ------------------------------------------------------------------ packages

PKGS=(iproute2 iw ethtool wpasupplicant nftables curl python3 python3-venv
	nmap arp-scan tcpdump tshark iperf3 rtl-sdr rtl-433 bluez)
[[ $KIOSK == 1 ]] && PKGS+=(cage chromium wlr-randr kbd fonts-dejavu-core)
[[ $VNC == 1 ]] && PKGS+=(wayvnc openssl)

if [[ $SKIP_APT == 0 ]]; then
	step "Packages"
	export DEBIAN_FRONTEND=noninteractive
	apt-get update -qq
	echo "wireshark-common wireshark-common/install-setuid boolean false" | debconf-set-selections
	echo "iperf3 iperf3/start_daemon boolean false" | debconf-set-selections
	want=()
	for p in "${PKGS[@]}"; do
		if [[ $p == chromium ]] && ! apt-cache show chromium >/dev/null 2>&1; then p=chromium-browser; fi
		if dpkg-query -W -f='${Status}' "$p" 2>/dev/null | grep -q 'install ok installed'; then continue; fi
		if apt-cache show "$p" >/dev/null 2>&1; then want+=("$p"); else warn "package $p not available on $OS_CODENAME"; fi
	done
	if [[ ${#want[@]} -gt 0 ]]; then
		info "installing ${want[*]}"
		apt-get install -y -qq --no-install-recommends "${want[@]}"
	else
		info "all present"
	fi
fi

PYV=$(python3 -c 'import sys; print("%d.%d" % sys.version_info[:2])')
python3 -c 'import sys; sys.exit(sys.version_info < (3, 11))' || die "Python $PYV found; netcaliper needs ≥ 3.11"

# ------------------------------------------------------------------ users

step "Users"
getent group "$SVC_USER" >/dev/null || groupadd --system "$SVC_USER"
if ! id "$SVC_USER" >/dev/null 2>&1; then
	useradd --system --gid "$SVC_USER" --home-dir "$STATE_DIR" --no-create-home --shell /usr/sbin/nologin "$SVC_USER"
	info "created user $SVC_USER"
fi
for g in bluetooth plugdev; do
	getent group "$g" >/dev/null && ! id -nG "$SVC_USER" | grep -qw "$g" && usermod -aG "$g" "$SVC_USER"
done
if [[ $KIOSK == 1 ]] && ! id "$KIOSK_USER" >/dev/null 2>&1; then
	useradd --system --user-group --create-home --home-dir /var/lib/$KIOSK_USER --shell /usr/sbin/nologin "$KIOSK_USER"
	info "created user $KIOSK_USER"
fi
if [[ $KIOSK == 1 ]]; then
	for g in video render input; do
		getent group "$g" >/dev/null && ! id -nG "$KIOSK_USER" | grep -qw "$g" && usermod -aG "$g" "$KIOSK_USER"
	done
fi
# Let the installing user run `netcaliper doctor` / read data without sudo.
if [[ -n ${SUDO_USER:-} && $SUDO_USER != root ]] && ! id -nG "$SUDO_USER" | grep -qw "$SVC_USER"; then
	usermod -aG "$SVC_USER" "$SUDO_USER"
	info "added $SUDO_USER to group $SVC_USER (log in again to take effect)"
fi

# ------------------------------------------------------------------ app

step "Application ($PREFIX)"
SRC_HASH=$(cd "$SRC" && find device/pyproject.toml device/netcaliper -type f \
	-not -path '*/__pycache__/*' -not -name '*.pyc' -print0 | sort -z | xargs -0 sha256sum | sha256sum | cut -c1-16)
if [[ -x $PREFIX/venv/bin/python ]] && ! "$PREFIX/venv/bin/python" -c 'import sys; sys.exit(sys.version_info[:2] != tuple(map(int, "'"$PYV"'".split("."))))'; then
	info "system Python changed: rebuilding venv"
	rm -rf "$PREFIX/venv"
fi
if [[ ! -x $PREFIX/venv/bin/python ]]; then
	python3 -m venv "$PREFIX/venv"
	"$PREFIX/venv/bin/pip" install -q --upgrade pip
fi
APP_CHANGED=0
if [[ $(cat "$PREFIX/.src-hash" 2>/dev/null) != "$SRC_HASH" ]]; then
	BUILD=$(mktemp -d)
	cp -a "$SRC/device" "$BUILD/" # build from a copy: never write into the checkout as root
	"$PREFIX/venv/bin/pip" install -q --no-cache-dir "$BUILD/device"
	rm -rf "$BUILD"
	echo "$SRC_HASH" >"$PREFIX/.src-hash"
	info "installed netcaliper $("$PREFIX/venv/bin/netcaliper" --version 2>/dev/null || echo "($SRC_HASH)")"
	APP_CHANGED=1
else
	info "up to date ($SRC_HASH)"
fi
ln -sfn "$PREFIX/venv/bin/netcaliper" /usr/local/bin/netcaliper
install -d -m 0755 "$PREFIX/libexec"
install_file "$SRC/installer/kiosk/session.sh" "$PREFIX/libexec/kiosk-session" 0755
install_file "$SRC/installer/uninstall.sh" "$PREFIX/uninstall.sh" 0755
install_file "$SRC/installer/lib/common.sh" "$PREFIX/lib/common.sh" 0644

# ------------------------------------------------------------------ config + data

step "Config and data"
# 0751: others may traverse (the kiosk user reaches wayvnc/) but not list; files keep their own modes.
install -d -m 0751 -o root -g "$SVC_USER" "$ETC"
install -d -m 0750 -o root -g "$SVC_USER" "$ETC/nftables"
install -d -m 0750 -o "$SVC_USER" -g "$SVC_USER" "$STATE_DIR"
if [[ ! -f $ETC/netcaliper.toml ]]; then
	install -m 0640 -o root -g "$SVC_USER" "$SRC/installer/config/netcaliper.toml" "$ETC/netcaliper.toml"
	info "created $ETC/netcaliper.toml"
fi
CHANGED=0
install_file "$SRC/installer/nftables/ncal-test.nft" "$ETC/nftables/ncal-test.nft" 0640 "root:$SVC_USER"
NFT_CHANGED=$CHANGED

KENV=$(mktemp)
{
	echo "# Generated by install.sh for this platform; edit freely, re-run install.sh to reset."
	echo "KIOSK_URL=http://127.0.0.1:8080/"
	echo "KIOSK_VNC=$VNC"
	if [[ $UCONSOLE == 1 ]]; then
		echo "KIOSK_TRANSFORM=270"                   # DSI panel is 720x1280 portrait
		echo "WLR_DRM_FORCE_LIBLIFTOFF=1"            # from the ClockworkPi image's labwc env
		echo "XCURSOR_SIZE=48"
	fi
} >"$KENV"
install_file "$KENV" "$ETC/kiosk.env" 0644
rm -f "$KENV"

if [[ $VNC == 1 ]]; then
	step "VNC (remote view + control of the kiosk)"
	VD=$ETC/wayvnc
	install -d -m 0750 -o root -g "$KIOSK_USER" "$VD"
	if [[ ! -f $VD/config ]]; then
		pw=$(openssl rand -base64 24 | tr -d '/+=' | cut -c1-16)
		umask 027
		cat >"$VD/config" <<-CONF
			# wayvnc for the netcaliper kiosk. Change the password here, then:
			#   sudo systemctl restart netcaliper-kiosk
			address=0.0.0.0
			port=5900
			enable_auth=true
			username=netcaliper
			password=$pw
			private_key_file=$VD/tls_key.pem
			certificate_file=$VD/tls_cert.pem
			rsa_private_key_file=$VD/rsa_key.pem
		CONF
		umask 022
		info "generated VNC credentials in $VD/config (user netcaliper; read the password with sudo)"
	fi
	if [[ ! -f $VD/tls_key.pem ]]; then
		openssl req -x509 -newkey ec -pkeyopt ec_paramgen_curve:prime256v1 -sha256 -days 3650 -nodes \
			-keyout "$VD/tls_key.pem" -out "$VD/tls_cert.pem" -subj "/CN=$(hostname)" \
			-addext "subjectAltName=DNS:$(hostname),DNS:$(hostname).local" 2>/dev/null
		info "generated self-signed TLS certificate"
	fi
	if [[ ! -f $VD/rsa_key.pem ]]; then
		openssl genrsa -traditional -out "$VD/rsa_key.pem" 2048 2>/dev/null
	fi
	chown root:"$KIOSK_USER" "$VD"/*
	chmod 0640 "$VD"/*
fi
state_set VNC "$VNC"

# ------------------------------------------------------------------ kernel / udev / NM

step "Kernel modules, udev, NetworkManager"
CHANGED=0
install_file "$SRC/installer/modprobe/netcaliper-blacklist-dvb.conf" /etc/modprobe.d/netcaliper-blacklist-dvb.conf 0644
for m in dvb_usb_rtl28xxu rtl2832_sdr rtl2832; do
	if grep -q "^$m " /proc/modules; then
		if modprobe -r "$m" 2>/dev/null; then info "unloaded $m"; else warn "$m in use: reboot to release the RTL-SDR"; fi
	fi
done
CHANGED=0
install_file "$SRC/installer/udev/90-netcaliper.rules" /etc/udev/rules.d/90-netcaliper.rules 0644
if [[ $CHANGED == 1 ]]; then
	udevadm control --reload
	udevadm trigger --subsystem-match=usb --subsystem-match=tty --action=change
fi
if [[ -d /etc/NetworkManager/conf.d ]]; then
	info "NetworkManager present: the helper keeps test interfaces unmanaged ($NM_UNMANAGED)"
fi

# ------------------------------------------------------------------ services

step "Services"
CHANGED=0
install_file "$SRC/installer/tmpfiles/netcaliper.conf" /etc/tmpfiles.d/netcaliper.conf 0644
systemd-tmpfiles --create /etc/tmpfiles.d/netcaliper.conf
for u in "${UNITS[@]}"; do
	render "$SRC/installer/systemd/$u.service" "/etc/systemd/system/$u.service" 0644
done
UNITS_CHANGED=$CHANGED
systemctl daemon-reload
systemctl enable -q "${UNITS[@]}"
if ! systemctl is-active -q netcaliper-netns; then
	systemctl start netcaliper-netns
elif [[ $NFT_CHANGED == 1 || $UNITS_CHANGED == 1 ]]; then
	systemctl reload netcaliper-netns # re-applies sysctls + ruleset without dropping the namespace
fi
if [[ $APP_CHANGED == 1 || $UNITS_CHANGED == 1 ]]; then
	systemctl restart netcaliper-helper netcaliper-agent netcaliper-core
else
	systemctl start netcaliper-helper netcaliper-agent netcaliper-core
fi

# ------------------------------------------------------------------ kiosk

if [[ $KIOSK == 1 ]]; then
	step "Kiosk"
	install_file "$SRC/installer/pam/netcaliper-kiosk" /etc/pam.d/netcaliper-kiosk 0644
	render "$SRC/installer/systemd/$KIOSK_UNIT.service" "/etc/systemd/system/$KIOSK_UNIT.service" 0644
	systemctl daemon-reload
	systemctl enable -q "$KIOSK_UNIT"
	dm=$(current_dm)
	if [[ -n $dm && $dm != "$KIOSK_UNIT" ]]; then
		state_set DISABLED_DM "$dm"
		systemctl disable -q "$dm"
		info "disabled display manager $dm (uninstall.sh restores it)"
	fi
	if [[ $(systemctl get-default) != graphical.target ]]; then
		state_set DEFAULT_TARGET "$(systemctl get-default)"
		systemctl set-default -q graphical.target
	fi
	if [[ $START_KIOSK == 1 ]]; then
		[[ -n $dm ]] && systemctl stop "$dm" || true
		systemctl restart "$KIOSK_UNIT"
		info "kiosk started on tty1"
	elif ! systemctl is-active -q "$KIOSK_UNIT"; then
		info "kiosk starts at next boot (or now: sudo systemctl start $KIOSK_UNIT — stops the desktop)"
	fi
fi

# ------------------------------------------------------------------ verify

step "Verify"
for _ in $(seq 1 30); do
	curl -fsS -o /dev/null --max-time 2 http://127.0.0.1:8080/api/v1/health && break
	sleep 1
done
if curl -fsS -o /dev/null --max-time 2 http://127.0.0.1:8080/api/v1/health; then
	info "core is up on http://127.0.0.1:8080/"
else
	warn "core did not answer: journalctl -u netcaliper-core"
fi
"$PREFIX/venv/bin/netcaliper" doctor --no-color || true
step "Done"
