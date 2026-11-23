# installer

```sh
git clone https://github.com/supertechguy/netcaliper.git && cd netcaliper
sudo installer/install.sh            # Pi OS / uConsole: services + kiosk (boots into the UI)
sudo installer/install.sh --vnc      # …plus remote view/control over VNC (auth + TLS)
sudo installer/install.sh --dev      # x86 dev host: services only, no kiosk, no OS tweaks
sudo /opt/netcaliper/uninstall.sh    # reverse it (keeps data/config; --purge removes them)
```

Re-running `install.sh` is safe and converges (a no-change run reports nothing as updated).
Other flags: `--no-kiosk`, `--start-kiosk` (switch to the kiosk now instead of at next boot),
`--no-vnc`, `--skip-apt`, `--branch NAME`.

| Path | What |
|---|---|
| `systemd/` | `netcaliper-{netns,helper,agent,core,kiosk}.service` (`@PREFIX@`/`@NETNS@` rendered at install) |
| `nftables/ncal-test.nft` | ruleset loaded **inside** the test netns (default drop in/forward) |
| `kiosk/session.sh` | runs inside cage: rotate portrait panels, optional wayvnc, wait for core, Chromium |
| `plymouth/` | boot splash theme (the image is rendered at install by `netcaliper splash`; the previous theme is restored on uninstall) |
| `pam/`, `tmpfiles/`, `udev/`, `modprobe/` | logind session for the kiosk, `/run/netcaliper`, USB device access, DVB blacklist |
| `initramfs/` | uConsole image apt fix (boots without initramfs; `mkinitramfs` can't resolve `/dev/root`) |
| `config/netcaliper.toml` | default config (never overwritten) |

**Power saving:** the screen dims after 9 min and the backlight turns off after 10 min without input;
any key, trackball movement or VNC input wakes it (the waking key doesn't act). Tune
`KIOSK_DIM_S` / `KIOSK_BLANK_S` (0 = never) and optional `KIOSK_BLANK_S_BATTERY` in
`/etc/netcaliper/kiosk.env`, then `sudo systemctl restart netcaliper-kiosk`. Re-installs keep your values.

**VNC:** connect to `<device>:5900` with a client that supports VeNCrypt or RSA-AES (TigerVNC viewer,
Remmina). User `netcaliper`; the password is generated on the device:
`sudo grep ^password /etc/netcaliper/wayvnc/config`. Change it there, then
`sudo systemctl restart netcaliper-kiosk`. Recovery console on the device: Ctrl+Alt+F2.

Design notes: `docs/ARCHITECTURE.md` §2 and §10, `docs/SECURITY.md`.
