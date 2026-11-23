# SPDX-License-Identifier: GPL-3.0-only
"""Static checks on installer assets: units run real CLI commands, placeholders resolve, and the
installer never hard-codes interface names."""

from __future__ import annotations

import re
import shutil
import subprocess
from pathlib import Path

import pytest

from netcaliper.cli.main import main

INSTALLER = Path(__file__).parents[2] / "installer"
UNITS = sorted((INSTALLER / "systemd").glob("*.service"))


def test_units_reference_real_cli_commands(capsys: pytest.CaptureFixture[str]) -> None:
    assert {u.stem for u in UNITS} >= {
        "netcaliper-netns",
        "netcaliper-helper",
        "netcaliper-agent",
        "netcaliper-core",
        "netcaliper-kiosk",
    }
    for unit in UNITS:
        for m in re.finditer(r"^Exec\w+=[+-]*@PREFIX@/venv/bin/netcaliper (\S+)", unit.read_text(), re.M):
            with pytest.raises(SystemExit) as e:
                main([m.group(1), "--help"])
            assert e.value.code == 0, f"{unit.name}: `netcaliper {m.group(1)}` is not a command"
    capsys.readouterr()


def test_unit_privileges() -> None:
    text = {u.stem: u.read_text() for u in UNITS}
    for name in ("netcaliper-core", "netcaliper-agent"):
        assert "User=netcaliper" in text[name]
        assert "CapabilityBoundingSet=CAP_NET_RAW CAP_NET_ADMIN" in text[name]
        assert "NoNewPrivileges=yes" in text[name]
    assert "NetworkNamespacePath=/run/netns/@NETNS@" in text["netcaliper-agent"]
    assert "User=ncal-kiosk" in text["netcaliper-kiosk"]
    assert re.search(r"^CapabilityBoundingSet=$", text["netcaliper-kiosk"], re.M)
    assert "User=" not in text["netcaliper-helper"]  # root, but sandboxed:
    assert "NoNewPrivileges=yes" in text["netcaliper-helper"]


def test_no_hardcoded_interface_names_in_installer() -> None:
    pat = re.compile(r"\b(eth\d|wlan\d|enp\w+|wlp\w+|enx[0-9a-f]+)\b")
    for f in INSTALLER.rglob("*"):
        if f.is_file() and f.suffix != ".md":
            assert not pat.search(f.read_text()), f"interface name in {f}"


def test_nft_ruleset_is_default_drop() -> None:
    rules = (INSTALLER / "nftables/ncal-test.nft").read_text()
    assert re.search(r"hook input .*policy drop", rules)
    assert re.search(r"hook forward .*policy drop", rules)
    assert "delete table inet netcaliper" in rules  # atomic reload


@pytest.mark.skipif(not shutil.which("shellcheck"), reason="shellcheck not installed")
def test_shellcheck() -> None:
    scripts = ["install.sh", "uninstall.sh", "lib/common.sh", "kiosk/session.sh"]
    r = subprocess.run(
        ["shellcheck", "-x", "-P", str(INSTALLER), *(str(INSTALLER / s) for s in scripts)],
        capture_output=True,
        text=True,
        check=False,
    )
    assert r.returncode == 0, r.stdout


def test_current_dm_is_safe_under_set_e(tmp_path: Path) -> None:
    # Regression: with no display manager enabled, `dm=$(current_dm)` aborted install.sh (set -e).
    lib = INSTALLER / "lib/common.sh"
    script = f'set -euo pipefail; . "{lib}"; dm=$(current_dm "{tmp_path}"); echo "ok:$dm"'
    r = subprocess.run(["bash", "-c", script], capture_output=True, text=True, check=False)
    assert r.returncode == 0 and r.stdout.strip() == "ok:", r.stderr
    (tmp_path / "lightdm.service").write_text("")
    (tmp_path / "display-manager.service").symlink_to(tmp_path / "lightdm.service")
    r = subprocess.run(["bash", "-c", script], capture_output=True, text=True, check=False)
    assert r.stdout.strip() == "ok:lightdm"


def test_merge_env_keeps_user_edits(tmp_path: Path) -> None:
    lib = INSTALLER / "lib/common.sh"
    defaults, target = tmp_path / "defaults", tmp_path / "kiosk.env"
    defaults.write_text("# header\nKIOSK_BLANK_S=600\nKIOSK_DIM_S=540\n#KIOSK_BLANK_S_BATTERY=300\n")

    def run(cmd: str) -> None:
        # Stub out install/chmod/chown so the helpers run unprivileged on plain files.
        stubs = 'install() { cp "$8" "$9"; }; chmod() { :; }; chown() { :; }'
        script = f'set -euo pipefail; . "{lib}"; {stubs}; {cmd}'
        r = subprocess.run(["bash", "-c", script], capture_output=True, text=True, check=False)
        assert r.returncode == 0, r.stderr

    run(f'merge_env "{defaults}" "{target}"')
    assert target.read_text() == defaults.read_text()  # fresh install: defaults verbatim
    target.write_text("KIOSK_BLANK_S=120\n")  # user edit
    run(f'merge_env "{defaults}" "{target}"')
    assert target.read_text() == "KIOSK_BLANK_S=120\nKIOSK_DIM_S=540\n"  # kept + missing key added
    run(f'set_env "{target}" KIOSK_VNC 1')
    run(f'set_env "{target}" KIOSK_VNC 0')
    assert target.read_text().count("KIOSK_VNC") == 1 and "KIOSK_VNC=0" in target.read_text()


def test_boot_splash_png_is_valid_and_rotates() -> None:
    import struct
    import zlib

    from netcaliper.cli.splash import png, render

    w, h, rows = render(0)
    data = png(w, h, rows)
    assert data[:8] == b"\x89PNG\r\n\x1a\n"
    ihdr_w, ihdr_h = struct.unpack("!II", data[16:24])
    assert (ihdr_w, ihdr_h) == (w, h) and w > h  # landscape wordmark
    idat = data[data.index(b"IDAT") + 4 : data.index(b"IEND") - 8]
    raw = zlib.decompress(idat)
    assert len(raw) == h * (1 + 4 * w)
    w90, h90, rows90 = render(90)
    assert (w90, h90) == (h, w)
    # Clockwise: the first row of the rotated image is the original's first column, bottom to top.
    col0 = bytes(b for r in reversed(rows) for b in r[:4])
    assert rows90[0] == col0
    assert png(w, h, rows) == data  # deterministic → installer re-runs stay no-ops


def test_plymouth_theme_and_kiosk_handoff() -> None:
    theme = (INSTALLER / "plymouth/netcaliper.plymouth").read_text()
    assert "ModuleName=script" in theme and "netcaliper.script" in theme
    script = (INSTALLER / "plymouth/netcaliper.script").read_text()
    assert 'Image("splash.png")' in script and "SetDisplayPasswordFunction" in script
    unit = (INSTALLER / "systemd/netcaliper-kiosk.service").read_text()
    # Waiting for plymouth-quit-wait while conflicting with plymouth-quit would stall the kiosk.
    assert "plymouth-quit-wait" not in unit
    assert re.search(r"^Conflicts=.*plymouth-quit\.service", unit, re.M)
    assert "plymouth quit --retain-splash" in unit
    install = (INSTALLER / "install.sh").read_text()
    for f in ("plymouth/netcaliper.plymouth", "plymouth/netcaliper.script"):
        assert f"installer/{f}" in install and (INSTALLER / f).exists()
    assert "PLYMOUTH_THEME" in (INSTALLER / "uninstall.sh").read_text()
