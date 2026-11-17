#!/usr/bin/env python3
"""
How Soon  |  hardware health and security checker  |  by Bradley Williams

Checks drives, memory, board and CPU, power, inputs and outputs, and security
on Linux, Windows and macOS. Every finding gets a "how soon" rating
(Now, Soon, Watch, Fine) and, where it is safe to do so, a fix you can run.

Needs only Python 3.8+. If pywebview is installed it opens in a native
window, otherwise in an app window of Chrome, Edge, Brave or Chromium,
otherwise in your default browser.

    python3 howsoon.py            start the app
    python3 howsoon.py --demo     start with sample data (no scanning)

License: Perpetual Free License. Free to use, share and distribute.
"""

import base64
import ctypes
import datetime as dt
import glob
import http.server
import json
import os
import platform
import re
import secrets
import shlex
import shutil
import socket
import socketserver
import struct
import subprocess
import sys
import tempfile
import threading
import time
import traceback
import urllib.parse
import webbrowser

APP_NAME = "How Soon"
APP_VERSION = "1.0.0"

OS = {"linux": "linux", "win32": "windows", "darwin": "mac"}.get(sys.platform, "linux")
if sys.platform.startswith("linux"):
    OS = "linux"

URGENCY_ORDER = {"now": 0, "soon": 1, "watch": 2, "fine": 3, "info": 4}
WHEN_DEFAULT = {
    "now": "Today",
    "soon": "Within a few weeks",
    "watch": "Check again next month",
    "fine": "Nothing to do",
    "info": "For reference",
}
AREAS = [
    ("drives", "Drives"),
    ("memory", "Memory"),
    ("board", "Board and CPU"),
    ("power", "Power"),
    ("io", "Inputs and outputs"),
    ("security", "Security"),
    ("system", "System"),
]

HOME = os.path.expanduser("~")


# ------------------------------------------------------------------------------
#  Paths and small helpers
# ------------------------------------------------------------------------------
def data_dir():
    if OS == "windows":
        base = os.environ.get("LOCALAPPDATA") or os.path.join(HOME, "AppData", "Local")
        d = os.path.join(base, "HowSoon")
    elif OS == "mac":
        d = os.path.join(HOME, "Library", "Application Support", "HowSoon")
    else:
        base = os.environ.get("XDG_DATA_HOME") or os.path.join(HOME, ".local", "share")
        d = os.path.join(base, "howsoon")
    os.makedirs(os.path.join(d, "logs"), exist_ok=True)
    return d


NO_WINDOW = 0x08000000 if OS == "windows" else 0


def run(cmd, timeout=30, env=None, input_text=None, shell=False):
    """Run a command, never raise. Returns (returncode, stdout+stderr text)."""
    try:
        e = None
        if env:
            e = dict(os.environ)
            e.update(env)
        p = subprocess.run(
            cmd, capture_output=True, text=True, timeout=timeout, env=e,
            input=input_text, shell=shell, creationflags=NO_WINDOW,
            encoding="utf-8", errors="replace",
        )
        return p.returncode, (p.stdout or "") + (p.stderr or "")
    except FileNotFoundError:
        return 127, ""
    except subprocess.TimeoutExpired:
        return 124, ""
    except Exception as ex:  # noqa
        return 1, str(ex)


def run_out(cmd, timeout=30, **kw):
    rc, out = run(cmd, timeout=timeout, **kw)
    return out if rc == 0 else ""


def which(name):
    p = shutil.which(name)
    if p:
        return p
    extra = []
    if OS == "mac":
        extra = ["/opt/homebrew/bin", "/opt/homebrew/sbin", "/usr/local/bin", "/usr/local/sbin", "/usr/sbin", "/sbin"]
    elif OS == "linux":
        extra = ["/usr/sbin", "/sbin", "/usr/local/sbin"]
    elif OS == "windows":
        pf = os.environ.get("ProgramFiles", r"C:\Program Files")
        extra = [os.path.join(pf, "smartmontools", "bin")]
    for d in extra:
        for cand in (os.path.join(d, name), os.path.join(d, name + ".exe")):
            if os.path.isfile(cand) and os.access(cand, os.X_OK):
                return cand
    return None


def read(path, default=""):
    try:
        with open(path, "r", encoding="utf-8", errors="replace") as f:
            return f.read()
    except Exception:
        return default


def read_int(path, default=None):
    try:
        return int(read(path).strip())
    except Exception:
        return default


def fmt_bytes(n):
    if n is None:
        return "unknown"
    n = float(n)
    for unit in ("B", "KB", "MB", "GB", "TB"):
        if abs(n) < 1024 or unit == "TB":
            if unit in ("B", "KB"):
                return "%d %s" % (n, unit)
            return ("%.1f %s" % (n, unit)).replace(".0 ", " ")
        n /= 1024.0
    return "%.1f TB" % n


def fmt_int(n):
    try:
        return "{:,}".format(int(n))
    except Exception:
        return str(n)


def fmt_duration(seconds):
    seconds = int(seconds or 0)
    d, rem = divmod(seconds, 86400)
    h, rem = divmod(rem, 3600)
    m = rem // 60
    if d:
        return "%dd %dh" % (d, h)
    if h:
        return "%dh %dm" % (h, m)
    return "%dm" % m


def is_admin():
    try:
        if OS == "windows":
            return bool(ctypes.windll.shell32.IsUserAnAdmin())
        return os.geteuid() == 0
    except Exception:
        return False


def self_cmd():
    """argv prefix that starts this program again (script or frozen binary)."""
    if getattr(sys, "frozen", False):
        return [sys.executable]
    return [sys.executable, os.path.abspath(__file__)]


def finding(area, fid, urgency, title, detail="", when=None, metrics=None, fixes=None):
    return {
        "area": area,
        "id": fid,
        "urgency": urgency,
        "title": title,
        "detail": detail,
        "when": when or WHEN_DEFAULT[urgency],
        "metrics": metrics or [],
        "fixes": fixes or [],
    }


def m(label, value):
    return {"label": label, "value": value}


# ------------------------------------------------------------------------------
#  History (for trends: disk fill rate, reallocated growth, battery wear)
# ------------------------------------------------------------------------------
def history_path():
    return os.path.join(data_dir(), "history.json")


def load_history():
    try:
        with open(history_path(), "r", encoding="utf-8") as f:
            h = json.load(f)
            return h if isinstance(h, list) else []
    except Exception:
        return []


def save_history(snapshot):
    h = load_history()
    h.append(snapshot)
    h = h[-300:]
    try:
        tmp = history_path() + ".tmp"
        with open(tmp, "w", encoding="utf-8") as f:
            json.dump(h, f)
        os.replace(tmp, history_path())
    except Exception:
        pass


def oldest_matching(history, key_fn, min_age_days=1.0):
    """Oldest snapshot value at least min_age_days old, as (age_days, value)."""
    now = time.time()
    for snap in history:
        age = (now - snap.get("t", now)) / 86400.0
        if age < min_age_days:
            continue
        try:
            v = key_fn(snap)
        except Exception:
            v = None
        if v is not None:
            return age, v
    return None, None


# ------------------------------------------------------------------------------
#  SMART (shared by all platforms when smartctl is available)
# ------------------------------------------------------------------------------
def smart_scan_devices():
    exe = which("smartctl")
    if not exe:
        return []
    out = run_out([exe, "--scan-open", "-j"], timeout=30)
    devs = []
    try:
        for d in json.loads(out).get("devices", []):
            devs.append({"name": d.get("name"), "type": d.get("type")})
    except Exception:
        pass
    if not devs and OS == "linux":
        for p in sorted(glob.glob("/sys/block/*")):
            n = os.path.basename(p)
            if re.match(r"^(sd[a-z]+|nvme\d+n\d+|hd[a-z]+|vd[a-z]+)$", n):
                devs.append({"name": "/dev/" + n, "type": None})
    return devs


def smart_read_all():
    exe = which("smartctl")
    if not exe:
        return {"available": False, "disks": []}
    disks = []
    for d in smart_scan_devices():
        cmd = [exe, "-a", "-j", d["name"]]
        if d.get("type"):
            cmd[1:1] = ["-d", d["type"]]
        rc, out = run(cmd, timeout=45)
        try:
            j = json.loads(out)
        except Exception:
            continue
        j["_dev"] = d["name"]
        disks.append(j)
    return {"available": True, "disks": disks}


def parse_smart(j):
    """Turn smartctl JSON into a compact dict."""
    s = {
        "dev": j.get("_dev"),
        "model": j.get("model_name") or j.get("model_family") or "",
        "serial": j.get("serial_number") or "",
        "capacity": (j.get("user_capacity") or {}).get("bytes"),
        "rotation": j.get("rotation_rate"),
        "protocol": (j.get("device") or {}).get("protocol", ""),
        "passed": (j.get("smart_status") or {}).get("passed"),
        "poh": (j.get("power_on_time") or {}).get("hours"),
        "temp": (j.get("temperature") or {}).get("current"),
        "attrs": {},
        "failing_now": [],
        "failed_past": [],
        "nvme": None,
        "life_left": None,
        "last_test": None,
        "messages": [],
    }
    for msg in (j.get("smartctl") or {}).get("messages", []) or []:
        if msg.get("severity") == "error":
            s["messages"].append(msg.get("string", ""))
    table = ((j.get("ata_smart_attributes") or {}).get("table")) or []
    for a in table:
        aid = a.get("id")
        raw = (a.get("raw") or {}).get("value")
        s["attrs"][aid] = {
            "name": a.get("name"),
            "value": a.get("value"),
            "worst": a.get("worst"),
            "thresh": a.get("thresh"),
            "raw": raw,
            "raw_str": (a.get("raw") or {}).get("string"),
        }
        wf = (a.get("when_failed") or "").strip()
        if wf == "now":
            s["failing_now"].append(a.get("name"))
        elif wf == "past":
            s["failed_past"].append(a.get("name"))
    for lid in (231, 202, 177, 233, 169):
        if lid in s["attrs"] and s["attrs"][lid]["value"] is not None:
            s["life_left"] = s["attrs"][lid]["value"]
            break
    nv = j.get("nvme_smart_health_information_log")
    if nv:
        s["nvme"] = nv
        if nv.get("percentage_used") is not None:
            s["life_left"] = max(0, 100 - int(nv.get("percentage_used")))
        if s["poh"] is None:
            s["poh"] = nv.get("power_on_hours")
        if s["temp"] is None:
            s["temp"] = nv.get("temperature")
    tests = ((j.get("ata_smart_self_test_log") or {}).get("standard") or {}).get("table") or []
    if tests:
        t = tests[0]
        s["last_test"] = {
            "type": (t.get("type") or {}).get("string", ""),
            "status": (t.get("status") or {}).get("string", ""),
            "passed": (t.get("status") or {}).get("passed"),
            "hours": t.get("lifetime_hours"),
        }
    return s


def smart_findings(sm, history, ctx):
    """Findings for one disk from parsed SMART data."""
    out = []
    name = sm["model"] or sm["dev"]
    key = sm["serial"] or sm["dev"]
    hdd = (sm["rotation"] or 0) > 0
    a = sm["attrs"]

    def raw(aid):
        v = a.get(aid, {}).get("raw")
        return int(v) if isinstance(v, (int, float)) else 0

    realloc = raw(5)
    pending = raw(197)
    offline = raw(198)
    reported = raw(187)
    crc = raw(199)
    metrics = []
    if sm["poh"] is not None:
        metrics.append(m("Power-on hours", fmt_int(sm["poh"])))
    if sm["temp"] is not None:
        metrics.append(m("Temperature", "%s°C" % sm["temp"]))
    if 5 in a:
        metrics.append(m("Reallocated sectors", fmt_int(realloc)))
    if 197 in a:
        metrics.append(m("Pending sectors", fmt_int(pending)))
    if sm["life_left"] is not None and not hdd:
        metrics.append(m("Life left", "%d%%" % sm["life_left"]))

    fixes_test = ["smart_short", "smart_long"]

    if sm["passed"] is False or sm["failing_now"]:
        out.append(finding(
            "drives", "smart_fail_" + key, "now",
            "%s says it is failing" % name,
            "The drive's own health check failed%s. Back up anything you care about today and replace the drive."
            % ((" (" + ", ".join(sm["failing_now"]) + ")") if sm["failing_now"] else ""),
            when="Back up today", metrics=metrics,
        ))
        return out

    if pending or offline or reported:
        out.append(finding(
            "drives", "smart_bad_" + key, "now",
            "%s has unreadable sectors" % name,
            "%s pending, %s uncorrectable and %s reported read errors. Data in those spots may already be lost. "
            "Back up now, then run a long self-test to see if the drive remaps them."
            % (fmt_int(pending), fmt_int(offline), fmt_int(reported)),
            when="Back up today", metrics=metrics, fixes=fixes_test,
        ))

    if realloc:
        age, old = oldest_matching(history, lambda s: s["disks"][key]["realloc"])
        grew = old is not None and realloc > old
        if grew:
            urg = "soon"
            detail = ("Reallocated sectors went from %s to %s in the last %d days. A count that keeps climbing "
                      "means the surface is wearing out. Plan a replacement." % (fmt_int(old), fmt_int(realloc), round(age)))
            when = "Replace within weeks"
        elif realloc >= 50:
            urg = "soon"
            detail = "%s sectors have already been swapped for spares. That is a lot. Plan a replacement." % fmt_int(realloc)
            when = "Replace within weeks"
        else:
            urg = "watch"
            detail = ("%s bad spot%s already swapped for a spare. A few is normal wear. If this number grows "
                      "between scans, the drive is on its way out." % (fmt_int(realloc), "" if realloc == 1 else "s"))
            when = "Rescan monthly"
        out.append(finding("drives", "smart_realloc_" + key, urg, "%s has reallocated sectors" % name,
                           detail, when=when, metrics=metrics, fixes=fixes_test))

    if not hdd and sm["life_left"] is not None:
        left = sm["life_left"]
        used = 100 - left
        est = ""
        if used > 0 and sm["poh"]:
            rem_hours = sm["poh"] * left / float(used)
            age, old_poh = oldest_matching(history, lambda s: s["disks"][key]["poh"], min_age_days=7)
            per_day = 8.0
            note = " at about 8 hours a day"
            if old_poh is not None and age:
                per_day = max(0.5, (sm["poh"] - old_poh) / age)
                note = " at your current %.0f hours a day" % per_day
            years = rem_hours / per_day / 365.0
            est = " At this rate that is roughly %s more%s." % (
                ("%.0f years" % years) if years >= 2 else ("%.0f months" % max(1, years * 12)), note)
        if left <= 0:
            urg, when = "now", "Replace now"
        elif left <= 10:
            urg, when = "soon", "Replace within weeks"
        elif left <= 30:
            urg, when = "watch", "Plan ahead"
        else:
            urg, when = "fine", "Years left"
        out.append(finding("drives", "ssd_life_" + key, urg, "%s has %d%% of its write life left" % (name, left),
                           "Flash cells wear out with writes." + est, when=when, metrics=metrics))

    nv = sm.get("nvme") or {}
    if nv:
        spare, thr = nv.get("available_spare"), nv.get("available_spare_threshold")
        if spare is not None and thr is not None and spare <= thr:
            out.append(finding("drives", "nvme_spare_" + key, "now", "%s is out of spare blocks" % name,
                               "Available spare is %s%%, at or under the %s%% threshold. Back up and replace." % (spare, thr),
                               when="Back up today", metrics=metrics))
        if nv.get("media_errors"):
            out.append(finding("drives", "nvme_media_" + key, "soon", "%s has logged media errors" % name,
                               "%s media errors so far. Back up and keep an eye on this number." % fmt_int(nv["media_errors"]),
                               metrics=metrics, fixes=fixes_test))
        if nv.get("critical_warning"):
            out.append(finding("drives", "nvme_crit_" + key, "now", "%s raised a critical warning" % name,
                               "The drive's critical warning flag is set (code %s)." % nv["critical_warning"],
                               when="Back up today", metrics=metrics))

    t = sm["temp"]
    if t is not None:
        hot = 60 if hdd else 70
        if t >= hot:
            out.append(finding("drives", "smart_hot_" + key, "soon", "%s is running hot at %s°C" % (name, t),
                               "Heat shortens drive life. Clear the vents, keep the machine off soft surfaces and check the fan.",
                               metrics=metrics))
    if sm["failed_past"]:
        names = ", ".join(x.replace("_", " ") for x in sm["failed_past"])
        out.append(finding("drives", "smart_past_" + key, "watch", "%s went out of range in the past" % name,
                           "These attributes crossed their limit at some point: %s. If it was temperature, keep the vents clear." % names,
                           metrics=metrics))
    if crc:
        out.append(finding("drives", "smart_crc_" + key, "watch", "%s has cable errors" % name,
                           "%s CRC errors between the drive and the board. On a desktop, reseat or replace the SATA cable." % fmt_int(crc),
                           metrics=metrics))
    if hdd and sm["poh"] and sm["poh"] > 35000:
        out.append(finding("drives", "smart_old_" + key, "watch", "%s is getting old" % name,
                           "%s power-on hours, about %.1f years of running time. Hard drives often start failing past this point."
                           % (fmt_int(sm["poh"]), sm["poh"] / 8760.0), metrics=metrics))
    lt = sm.get("last_test")
    if lt and lt.get("passed") is False:
        out.append(finding("drives", "smart_test_" + key, "now", "%s failed its last self-test" % name,
                           "%s: %s. Back up and replace the drive." % (lt["type"], lt["status"]),
                           when="Back up today", metrics=metrics))

    if not out:
        test_note = ""
        if lt:
            test_note = " Last self-test: %s, %s." % (lt["type"].lower(), lt["status"].lower().rstrip("."))
        out.append(finding("drives", "smart_ok_" + key, "fine", "%s looks healthy" % name,
                           "SMART health passed with no bad or pending sectors." + test_note, metrics=metrics,
                           fixes=fixes_test))
    return out


def disk_snapshot(sm):
    return {
        "realloc": (sm["attrs"].get(5) or {}).get("raw") or 0,
        "poh": sm["poh"],
        "life": sm["life_left"],
    }


def space_findings(volumes, history):
    out = []
    for v in volumes:
        size, free = v.get("size") or 0, v.get("free") or 0
        if size < 1 << 30:
            continue
        pct_free = free * 100.0 / size
        label = v.get("label") or v.get("mount")
        key = v.get("mount")
        metrics = [m("Free", fmt_bytes(free)), m("Size", fmt_bytes(size)), m("Used", "%d%%" % round(100 - pct_free))]
        days_left = None
        age, old_free = oldest_matching(history, lambda s: s["volumes"][key], min_age_days=2)
        if old_free is not None and age and old_free > free:
            rate = (old_free - free) / age
            if rate > 50 * 1024 * 1024:
                days_left = free / rate
                metrics.append(m("Filling", "%s a day" % fmt_bytes(rate)))
        fix = ["clean_caches"]
        if pct_free < 5 or (days_left is not None and days_left < 7):
            urg = "now"
        elif pct_free < 10 or (days_left is not None and days_left < 30):
            urg = "soon"
        elif pct_free < 20:
            urg = "watch"
        else:
            urg = "fine"
        when = WHEN_DEFAULT[urg]
        if days_left is not None and days_left < 365:
            when = "Full in about %d days" % max(1, round(days_left))
        if urg == "fine":
            title = "%s has %s free" % (label, fmt_bytes(free))
            detail = "%d%% free." % round(pct_free)
            fix = []
        else:
            title = "%s is %d%% full" % (label, round(100 - pct_free))
            detail = ("Only %s left. Programs slow down and updates fail when a disk runs out of room."
                      % fmt_bytes(free))
        out.append(finding("drives", "space_" + re.sub(r"\W", "_", key), urg, title, detail, when=when,
                           metrics=metrics, fixes=fix))
    return out


# ------------------------------------------------------------------------------
#  Linux
# ------------------------------------------------------------------------------
REAL_FS = {"ext2", "ext3", "ext4", "xfs", "btrfs", "f2fs", "zfs", "vfat", "exfat", "ntfs", "ntfs3", "fuseblk", "jfs", "reiserfs", "bcachefs"}

RISKY_PORTS = {
    21: "FTP", 23: "Telnet", 25: "SMTP", 69: "TFTP", 110: "POP3", 111: "RPC", 135: "RPC",
    137: "NetBIOS", 139: "NetBIOS", 445: "SMB file sharing", 512: "rexec", 513: "rlogin", 514: "rsh",
    1433: "SQL Server", 2375: "Docker API without TLS", 3306: "MySQL", 3389: "Remote Desktop",
    5432: "PostgreSQL", 5900: "VNC", 5901: "VNC", 6379: "Redis", 9200: "Elasticsearch",
    11211: "Memcached", 27017: "MongoDB",
}


def linux_os_release():
    d = {}
    for line in read("/etc/os-release").splitlines():
        if "=" in line:
            k, v = line.split("=", 1)
            d[k] = v.strip().strip('"')
    return d


def linux_pkg_manager():
    for pm in ("apt-get", "dnf", "pacman", "zypper"):
        if which(pm):
            return pm
    return None


def linux_root_disk():
    src = run_out(["findmnt", "-no", "SOURCE", "/"]).strip()
    if not src:
        return None, False
    src = re.sub(r"\[.*\]$", "", src)
    out = run_out(["lsblk", "-J", "-s", "-o", "NAME,TYPE,ROTA", src])
    disk, crypt = None, False
    try:
        def walk(nodes):
            nonlocal disk, crypt
            for n in nodes:
                if n.get("type") == "crypt":
                    crypt = True
                if n.get("type") == "disk":
                    disk = n
                walk(n.get("children") or [])
        walk(json.loads(out).get("blockdevices", []))
    except Exception:
        pass
    return disk, crypt


def linux_info():
    osr = linux_os_release()
    mem = {}
    for line in read("/proc/meminfo").splitlines():
        p = line.split()
        if len(p) >= 2:
            mem[p[0].rstrip(":")] = int(p[1]) * 1024
    cpu = ""
    for line in read("/proc/cpuinfo").splitlines():
        if line.startswith("model name"):
            cpu = line.split(":", 1)[1].strip()
            break
    up = 0.0
    try:
        up = float(read("/proc/uptime").split()[0])
    except Exception:
        pass
    dmi = {}
    for k in ("sys_vendor", "product_name", "board_vendor", "board_name", "bios_vendor", "bios_version", "bios_date"):
        dmi[k] = read("/sys/class/dmi/id/" + k).strip()
    return {
        "name": platform.node(),
        "os": osr.get("PRETTY_NAME") or "Linux",
        "kernel": platform.release(),
        "arch": platform.machine(),
        "cpu": cpu or platform.processor(),
        "cores": os.cpu_count(),
        "ram_total": mem.get("MemTotal"),
        "ram_available": mem.get("MemAvailable"),
        "swap_total": mem.get("SwapTotal"),
        "swap_free": mem.get("SwapFree"),
        "uptime": up,
        "model": (" ".join(x for x in (dmi["sys_vendor"], dmi["product_name"]) if x)).strip(),
        "dmi": dmi,
    }


def linux_volumes():
    vols, seen = [], set()
    for line in read("/proc/mounts").splitlines():
        p = line.split()
        if len(p) < 3:
            continue
        dev, mnt, fs = p[0], p[1].replace("\\040", " "), p[2]
        if fs not in REAL_FS or mnt.startswith(("/snap", "/var/snap", "/run/", "/sys", "/proc")):
            continue
        if dev in seen:
            continue
        seen.add(dev)
        try:
            st = os.statvfs(mnt)
        except Exception:
            continue
        size = st.f_blocks * st.f_frsize
        free = st.f_bavail * st.f_frsize
        label = "System drive" if mnt == "/" else ("Home" if mnt == "/home" else mnt)
        vols.append({"mount": mnt, "label": label, "size": size, "free": free, "fs": fs, "dev": dev})
    return vols


def linux_kernel_errors():
    out = run_out(["journalctl", "-k", "-b", "-p", "3", "-q", "--no-pager", "-o", "cat"], timeout=30)
    if not out.strip():
        out = run_out(["dmesg", "--level=emerg,alert,crit,err", "-T"], timeout=15)
    groups = {
        "disk": re.compile(r"I/O error|blk_update_request|ata\d+(\.\d+)?:.*(failed command|error|exception)|EXT4-fs error|BTRFS (error|critical)|XFS.*(corrupt|error)|nvme\d+.*(timeout|reset|I/O)|Buffer I/O", re.I),
        "usb": re.compile(r"usb .*(over-current|cannot enable|device descriptor read|unable to enumerate|not accepting address)", re.I),
        "mce": re.compile(r"mce:|machine check|hardware error|EDAC", re.I),
        "gpu": re.compile(r"drm.*(error|hang|timed out)|GPU HANG|amdgpu.*(timeout|fault)|nouveau.*(fail|error)|i915.*(error|hang)", re.I),
    }
    res = {k: [] for k in groups}
    for line in out.splitlines():
        for k, rx in groups.items():
            if rx.search(line):
                res[k].append(line.strip())
                break
    return res, bool(out.strip())


def linux_temps():
    temps = []
    for hw in glob.glob("/sys/class/hwmon/hwmon*"):
        name = read(os.path.join(hw, "name")).strip()
        for inp in glob.glob(os.path.join(hw, "temp*_input")):
            v = read_int(inp)
            if v is None:
                continue
            base = inp[:-6]
            label = read(base + "_label").strip() or name
            crit = read_int(base + "_crit")
            temps.append({"chip": name, "label": label, "c": v / 1000.0, "crit": (crit / 1000.0) if crit else None})
    cpu = [t for t in temps if t["chip"] in ("coretemp", "k10temp", "zenpower", "cpu_thermal")]
    pkg = [t for t in cpu if re.search(r"Package|Tctl|Tdie", t["label"])]
    if not cpu:
        for z in glob.glob("/sys/class/thermal/thermal_zone*"):
            if "x86_pkg" in read(os.path.join(z, "type")):
                v = read_int(os.path.join(z, "temp"))
                if v:
                    pkg.append({"chip": "zone", "label": "Package", "c": v / 1000.0, "crit": None})
    cpu_t = max((t["c"] for t in (pkg or cpu)), default=None)
    return cpu_t, temps


def linux_listeners(deep_ss=None):
    out = deep_ss or run_out(["ss", "-H", "-tuln"]) or ""
    res = []
    for line in out.splitlines():
        p = line.split()
        if len(p) < 5:
            continue
        proto = p[0]
        local = p[4]
        proc = ""
        mm = re.search(r'users:\(\("([^"]+)"', line)
        if mm:
            proc = mm.group(1)
        host, _, port = local.rpartition(":")
        host = host.strip("[]").split("%")[0]
        try:
            port = int(port)
        except ValueError:
            continue
        res.append({"proto": proto, "host": host, "port": port, "proc": proc})
    return res


def is_exposed(host):
    if host in ("0.0.0.0", "*", "::", ""):
        return True
    if host.startswith("127.") or host in ("::1", "localhost"):
        return False
    if host.startswith("fe80"):
        return False
    return True


def listener_findings(listeners, firewall_on):
    out = []
    exposed = {}
    for l in listeners:
        if is_exposed(l["host"]):
            exposed.setdefault(l["port"], l)
    risky = {p: l for p, l in exposed.items() if p in RISKY_PORTS}
    if risky:
        names = ", ".join("%s (%d%s)" % (RISKY_PORTS[p], p, (", " + l["proc"]) if l["proc"] else "") for p, l in sorted(risky.items()))
        urg = "watch" if firewall_on else "soon"
        out.append(finding("security", "risky_ports", urg, "Risky services are open to the network",
                           "Listening on all interfaces: %s.%s If you don't use them, turn them off. If you do, "
                           "keep the firewall on and limit who can reach them."
                           % (names, " The firewall is on, which helps." if firewall_on else " The firewall is off."),
                           metrics=[m("Exposed ports", ", ".join(str(p) for p in sorted(exposed)))],
                           fixes=[] if firewall_on else ["firewall_on"]))
    elif exposed:
        out.append(finding("security", "open_ports", "info", "%d service%s listening on the network" % (len(exposed), "" if len(exposed) == 1 else "s"),
                           "None of them are on the usual risky list.",
                           metrics=[m("Ports", ", ".join(str(p) for p in sorted(exposed)))]))
    else:
        out.append(finding("security", "open_ports", "fine", "Nothing is listening on the network",
                           "Every listening service is bound to this machine only."))
    return out, exposed


def secret_files():
    """Plain-text secrets lying around in the home folder."""
    hits = []
    for f in (".git-credentials", ".netrc", ".aws/credentials", ".docker/config.json", ".pgpass"):
        p = os.path.join(HOME, f)
        if os.path.isfile(p):
            hits.append(p)
    rx = re.compile(r"(recovery[-_ ]?codes?|backup[-_ ]?codes?|passwords?|keystore[-_ ]?pass(word)?|seed[-_ ]?phrase|secrets?|credentials?)[^/\\]*\.(txt|md|csv|json|rtf)$", re.I)
    for folder in ("Desktop", "Documents", "Downloads"):
        root = os.path.join(HOME, folder)
        if not os.path.isdir(root):
            continue
        base_depth = root.rstrip(os.sep).count(os.sep)
        for dirpath, dirnames, filenames in os.walk(root):
            if dirpath.count(os.sep) - base_depth >= 2:
                dirnames[:] = []
            dirnames[:] = [d for d in dirnames if not d.startswith(".") and d not in ("node_modules", "venv", ".git")]
            for fn in filenames:
                if rx.search(fn):
                    hits.append(os.path.join(dirpath, fn))
            if len(hits) > 40:
                break
    return hits


def ssh_key_issues():
    issues = []
    d = os.path.join(HOME, ".ssh")
    if not os.path.isdir(d):
        return issues
    try:
        if OS != "windows" and (os.stat(d).st_mode & 0o077):
            issues.append(("perm", d))
    except Exception:
        pass
    for p in glob.glob(os.path.join(d, "id_*")):
        if p.endswith(".pub"):
            continue
        try:
            st = os.stat(p)
            if OS != "windows" and (st.st_mode & 0o077):
                issues.append(("perm", p))
            txt = read(p)
            if "ENCRYPTED" in txt:
                continue
            if "BEGIN OPENSSH PRIVATE KEY" in txt:
                b = base64.b64decode("".join(l for l in txt.splitlines() if not l.startswith("-----")))
                # openssh-key-v1\0, then string ciphername, string kdfname
                off = len(b"openssh-key-v1\0")
                n = struct.unpack(">I", b[off:off + 4])[0]
                cipher = b[off + 4:off + 4 + n]
                if cipher == b"none":
                    issues.append(("nopass", p))
            elif "BEGIN RSA PRIVATE KEY" in txt or "BEGIN EC PRIVATE KEY" in txt:
                issues.append(("nopass", p))
        except Exception:
            continue
    return issues


def secrets_findings():
    out = []
    files = secret_files()
    if files:
        loose = []
        for p in files:
            try:
                if OS != "windows" and (os.stat(p).st_mode & 0o077):
                    loose.append(p)
            except Exception:
                pass
        rel = [os.path.relpath(p, HOME) for p in files]
        urg = "soon" if any(os.path.basename(p) == ".git-credentials" or "recovery" in p.lower() or "password" in p.lower() for p in files) else "watch"
        out.append(finding(
            "security", "plaintext_secrets", urg,
            "%d file%s with passwords or tokens in plain text" % (len(files), "" if len(files) == 1 else "s"),
            "Anything that can read your home folder can read these. Move recovery codes and passwords into a password "
            "manager, and use a credential helper instead of ~/.git-credentials. Locking permissions down is a stopgap.",
            when="This week",
            metrics=[m("Files", ", ".join(rel[:6]) + (" and %d more" % (len(rel) - 6) if len(rel) > 6 else "")),
                     m("Readable by others", str(len(loose)))],
            fixes=["secrets_perms"] if loose or OS == "windows" else [],
        ))
    else:
        out.append(finding("security", "plaintext_secrets", "fine", "No loose password files found",
                           "Checked Desktop, Documents, Downloads and common credential files."))
    ssh = ssh_key_issues()
    perm = [p for k, p in ssh if k == "perm"]
    nopass = [p for k, p in ssh if k == "nopass"]
    if perm:
        out.append(finding("security", "ssh_perms", "soon", "SSH keys are readable by other users",
                           "Private keys and the .ssh folder should be readable only by you.",
                           metrics=[m("Paths", ", ".join(os.path.relpath(p, HOME) for p in perm))], fixes=["ssh_perms"]))
    if nopass:
        out.append(finding("security", "ssh_nopass", "watch", "SSH key%s without a passphrase" % ("" if len(nopass) == 1 else "s"),
                           "Anyone who copies these files can use them. Add one with: ssh-keygen -p -f <key>",
                           metrics=[m("Keys", ", ".join(os.path.relpath(p, HOME) for p in nopass))]))
    return out


def dir_size(path, limit_files=200000):
    total, n = 0, 0
    for dirpath, dirnames, filenames in os.walk(path, onerror=lambda e: None):
        for fn in filenames:
            try:
                total += os.lstat(os.path.join(dirpath, fn)).st_size
            except Exception:
                pass
            n += 1
            if n > limit_files:
                return total
    return total


def process_table():
    """[(pid, ppid, state, name, rss_bytes, uid)] on Linux and macOS."""
    procs = []
    if OS == "linux":
        for sp in glob.glob("/proc/[0-9]*/stat"):
            try:
                s = read(sp)
                l, r = s.find("("), s.rfind(")")
                name = s[l + 1:r]
                rest = s[r + 2:].split()
                state, ppid = rest[0], int(rest[1])
                pid = int(sp.split("/")[2])
                rss = 0
                uid = None
                for line in read("/proc/%d/status" % pid).splitlines():
                    if line.startswith("VmRSS:"):
                        rss = int(line.split()[1]) * 1024
                    elif line.startswith("Uid:"):
                        uid = int(line.split()[1])
                procs.append((pid, ppid, state, name, rss, uid))
            except Exception:
                continue
    else:
        out = run_out(["ps", "-axo", "pid=,ppid=,stat=,rss=,uid=,comm="])
        for line in out.splitlines():
            p = line.split(None, 5)
            if len(p) < 6:
                continue
            try:
                procs.append((int(p[0]), int(p[1]), p[2][0], os.path.basename(p[5]), int(p[3]) * 1024, int(p[4])))
            except Exception:
                continue
    return procs


def process_findings(procs):
    out = []
    zomb = [p for p in procs if p[2] == "Z"]
    byid = {p[0]: p for p in procs}
    if zomb:
        parents = {}
        for z in zomb:
            parents.setdefault(z[1], []).append(z)
        desc = ", ".join("%s (%d)" % (byid[pp][3] if pp in byid else "pid %d" % pp, len(zs)) for pp, zs in parents.items())
        out.append(finding("system", "zombies", "watch", "%d dead process%s waiting on %s parent" % (len(zomb), "" if len(zomb) == 1 else "es", "its" if len(zomb) == 1 else "their"),
                           "Zombie processes use no CPU or memory, but a pile of them points to a buggy program. "
                           "Restarting the parent clears them.", metrics=[m("Parents", desc)], fixes=["zombie_parents"]))
    else:
        out.append(finding("system", "zombies", "fine", "No dead processes", "Every finished process was cleaned up."))
    agg = {}
    for p in procs:
        agg[p[3]] = agg.get(p[3], 0) + p[4]
    top = sorted(agg.items(), key=lambda kv: -kv[1])[:6]
    if top:
        out.append(finding("system", "top_memory", "info", "Biggest memory users right now", "Grouped by program name.",
                           metrics=[m(n, fmt_bytes(b)) for n, b in top]))
    return out


def linux_collect(deep=None, ctx=None):
    """Return (info, findings, snapshot, extras)."""
    info = linux_info()
    F = []
    hist = load_history()
    snap = {"t": time.time(), "disks": {}, "volumes": {}, "battery": None}
    extras = {"disks": [], "volumes": []}

    # ---- drives
    vols = linux_volumes()
    extras["volumes"] = vols
    for v in vols:
        snap["volumes"][v["mount"]] = v["free"]
    F += space_findings(vols, hist)

    root_disk, crypt = linux_root_disk()
    if root_disk and str(root_disk.get("rota")) in ("1", "True", "true"):
        F.append(finding("drives", "system_hdd", "watch", "Your system drive is a spinning hard disk",
                         "This is the main reason the machine feels slow. Boot, app launches and updates all wait on it. "
                         "A SATA SSD is the single biggest speed upgrade and costs little.",
                         when="Next upgrade", metrics=[m("Drive", root_disk.get("name", ""))]))

    smart = None
    if deep and deep.get("smart"):
        smart = deep["smart"]
    elif is_admin():
        smart = smart_read_all()
    if smart is not None and not smart.get("available"):
        smart = None
    if smart is None:
        if which("smartctl"):
            F.append(finding("drives", "smart_need_admin", "info", "Drive health needs a deep scan",
                             "Reading SMART data needs your password. Use Deep scan to include it.", when="Run a deep scan"))
        else:
            F.append(finding("drives", "smart_missing", "watch", "Drive health can't be read",
                             "smartmontools isn't installed, so How Soon can't see failing sectors or wear.",
                             when="Install it once", fixes=["smart_install"]))
    else:
        for j in smart.get("disks", []):
            sm = parse_smart(j)
            extras["disks"].append(sm)
            snap["disks"][sm["serial"] or sm["dev"]] = disk_snapshot(sm)
            F += smart_findings(sm, hist, ctx)

    kerr, have_log = linux_kernel_errors()
    if deep and deep.get("kernel"):
        kerr = deep["kernel"]
        have_log = True
    if kerr["disk"]:
        F.append(finding("drives", "kernel_disk_errors", "soon", "%d disk errors since this boot" % len(kerr["disk"]),
                         "The kernel logged read or write failures. Combined with SMART, this tells you if the drive or its cable is going.",
                         metrics=[m("Latest", kerr["disk"][-1][:160])], fixes=["smart_long"]))

    # ---- memory
    tot, avail = info["ram_total"] or 0, info["ram_available"] or 0
    st, sf = info["swap_total"] or 0, info["swap_free"] or 0
    used_pct = (tot - avail) * 100.0 / tot if tot else 0
    swap_pct = (st - sf) * 100.0 / st if st else 0
    mm_metrics = [m("Installed", fmt_bytes(tot)), m("In use", "%d%%" % round(used_pct)),
                  m("Swap used", "%s of %s" % (fmt_bytes(st - sf), fmt_bytes(st)))]
    if tot and avail / float(tot) < 0.08:
        F.append(finding("memory", "ram_pressure", "soon", "Memory is nearly full",
                         "Only %s free. The system is pushing work to the slow disk." % fmt_bytes(avail), metrics=mm_metrics))
    elif tot and tot < 7.5 * (1 << 30):
        F.append(finding("memory", "ram_small", "watch", "%s of RAM is tight today" % fmt_bytes(tot),
                         "A modern browser plus a desktop uses 4 GB on its own. 8 GB or more makes a real difference.",
                         when="Next upgrade", metrics=mm_metrics))
    else:
        F.append(finding("memory", "ram_ok", "fine", "%s installed, %d%% in use" % (fmt_bytes(tot), round(used_pct)),
                         "Plenty of headroom.", metrics=mm_metrics))
    if st and swap_pct > 60:
        F.append(finding("memory", "swap_heavy", "watch", "Swap is %d%% used" % round(swap_pct),
                         "Heavy swapping on a hard disk makes everything stall. Close heavy programs or add RAM.", metrics=mm_metrics))
    ce = sum(read_int(p, 0) for p in glob.glob("/sys/devices/system/edac/mc/mc*/ce_count"))
    ue = sum(read_int(p, 0) for p in glob.glob("/sys/devices/system/edac/mc/mc*/ue_count"))
    if ue:
        F.append(finding("memory", "ecc_ue", "now", "Memory has uncorrectable errors",
                         "%d uncorrectable ECC errors. A RAM stick is failing. Test and replace it." % ue, when="Today"))
    elif ce:
        F.append(finding("memory", "ecc_ce", "watch", "Memory corrected %d errors" % ce,
                         "ECC fixed them, but a rising count means a stick is weakening."))
    if kerr["mce"]:
        F.append(finding("board", "mce", "soon", "The CPU reported %d hardware errors" % len(kerr["mce"]),
                         "Machine check errors point to RAM, CPU or board trouble. Run a memory test from the boot menu (memtest86+).",
                         metrics=[m("Latest", kerr["mce"][-1][:160])]))

    # ---- board and cpu
    cpu_t, temps = linux_temps()
    bm = [m("CPU", info["cpu"]), m("Cores", str(info["cores"]))]
    if cpu_t is not None:
        bm.append(m("CPU temperature", "%d°C" % round(cpu_t)))
    try:
        la = os.getloadavg()[0]
        bm.append(m("Load", "%.2f on %d cores" % (la, info["cores"] or 1)))
    except Exception:
        la = 0
    if cpu_t is not None and cpu_t >= 90:
        F.append(finding("board", "cpu_hot", "now", "CPU is at %d°C" % round(cpu_t),
                         "That is at its limit. Clean the fan and vents. Old laptops often need new thermal paste.",
                         when="Today", metrics=bm))
    elif cpu_t is not None and cpu_t >= 80:
        F.append(finding("board", "cpu_warm", "soon", "CPU is running hot at %d°C" % round(cpu_t),
                         "Dust in the fan is the usual cause.", metrics=bm))
    throttle = sum(read_int(p, 0) for p in glob.glob("/sys/devices/system/cpu/cpu*/thermal_throttle/package_throttle_count"))
    if throttle:
        F.append(finding("board", "throttle", "watch", "CPU slowed itself %s times to cool down" % fmt_int(throttle),
                         "Thermal throttling since boot. It costs speed. Clean the fan and keep the vents clear.", metrics=bm))
    dmi = info["dmi"]
    bios_date = None
    try:
        bios_date = dt.datetime.strptime(dmi.get("bios_date", ""), "%m/%d/%Y")
    except Exception:
        pass
    fw_fix = ["firmware_check"] if which("fwupdmgr") else []
    if bios_date and (dt.datetime.now() - bios_date).days > 5 * 365:
        F.append(finding("board", "bios_old", "watch", "Firmware is from %d" % bios_date.year,
                         "Board firmware fixes security holes and hardware bugs. Check the maker's site or fwupd for a newer version.",
                         when="Check once", metrics=[m("Board", (dmi.get("board_vendor", "") + " " + dmi.get("board_name", "")).strip()),
                                                     m("BIOS", "%s, %s" % (dmi.get("bios_version", ""), dmi.get("bios_date", "")))],
                         fixes=fw_fix))
    if not [f for f in F if f["area"] == "board"]:
        F.append(finding("board", "board_ok", "fine", "CPU and board look fine",
                         "No overheating, throttling or hardware errors.", metrics=bm))
    if kerr["gpu"]:
        F.append(finding("board", "gpu_errors", "watch", "Graphics driver logged %d errors" % len(kerr["gpu"]),
                         "Screen freezes or flicker usually come from here. Updating the kernel and drivers often fixes it.",
                         metrics=[m("Latest", kerr["gpu"][-1][:160])]))
    up = info["uptime"]
    if os.path.exists("/var/run/reboot-required"):
        pk = read("/var/run/reboot-required.pkgs").split()
        F.append(finding("system", "reboot_required", "soon", "Restart to finish installing updates",
                         "Some updates only take effect after a restart%s." % ((": " + ", ".join(sorted(set(pk))[:5])) if pk else ""),
                         when="Today or tomorrow"))
    elif up > 21 * 86400:
        F.append(finding("system", "uptime_long", "watch", "Running for %d days without a restart" % (up // 86400),
                         "Kernel and library updates only take effect after a restart."))

    # ---- power
    bats = [p for p in glob.glob("/sys/class/power_supply/*") if read(os.path.join(p, "type")).strip() == "Battery"]
    for b in bats:
        full = read_int(os.path.join(b, "energy_full")) or read_int(os.path.join(b, "charge_full"))
        design = read_int(os.path.join(b, "energy_full_design")) or read_int(os.path.join(b, "charge_full_design"))
        cycles = read_int(os.path.join(b, "cycle_count"))
        cap = read_int(os.path.join(b, "capacity"))
        status = read(os.path.join(b, "status")).strip()
        F += battery_findings(full, design, cycles, cap, status, hist, snap)
    if not bats:
        F.append(finding("power", "no_battery", "info", "No battery found", "Desktop or battery removed."))

    # ---- io
    inputs = []
    cur = {}
    for line in read("/proc/bus/input/devices").splitlines() + [""]:
        if line.startswith("N: Name="):
            cur["name"] = line.split("=", 1)[1].strip('"')
        elif line.startswith("H: Handlers="):
            cur["h"] = line.split("=", 1)[1]
        elif not line.strip() and cur:
            h = cur.get("h", "")
            if "kbd" in h and "mouse" not in h and "leds" in h or "mouse" in h:
                inputs.append(cur.get("name", ""))
            cur = {}
    usb = []
    lsusb = run_out(["lsusb"])
    for line in lsusb.splitlines():
        mm2 = re.match(r"Bus \d+ Device \d+: ID \S+ (.*)", line)
        if mm2 and "root hub" not in mm2.group(1).lower():
            usb.append(mm2.group(1).strip() or "Unknown device")
    io_metrics = []
    if inputs:
        io_metrics.append(m("Keyboards and pointers", ", ".join(sorted(set(inputs))[:5])))
    if usb:
        io_metrics.append(m("USB devices", ", ".join(usb[:6])))
    if kerr["usb"]:
        F.append(finding("io", "usb_errors", "watch", "USB errors since this boot (%d)" % len(kerr["usb"]),
                         "A port or device failed to connect cleanly. Try another port or cable. Over-current means a device draws too much power.",
                         metrics=[m("Latest", kerr["usb"][-1][:160])]))
    net_bad = []
    for nd in glob.glob("/sys/class/net/*"):
        n = os.path.basename(nd)
        if n == "lo" or not os.path.exists(os.path.join(nd, "device")):
            continue
        st_ = lambda k: read_int(os.path.join(nd, "statistics", k), 0)
        pk = st_("rx_packets") + st_("tx_packets")
        err = st_("rx_errors") + st_("tx_errors")
        if pk > 1000 and err * 1000 > pk:
            net_bad.append("%s %s errors" % (n, fmt_int(err)))
    if net_bad:
        F.append(finding("io", "net_errors", "watch", "Network adapter errors", "Over 0.1% of packets had errors. Check the cable, Wi-Fi signal or driver.",
                         metrics=[m("Adapters", ", ".join(net_bad))]))
    failed = run_out(["systemctl", "--failed", "--no-legend", "--plain"]).split("\n")
    failed = [l.split()[0] for l in failed if l.strip() and not l.strip().startswith("0 ")]
    if failed:
        F.append(finding("system", "failed_units", "watch", "%d service%s failed to start" % (len(failed), "" if len(failed) == 1 else "s"),
                         "Failed services can mean a missing device, a bad config or a broken update.",
                         metrics=[m("Services", ", ".join(failed[:8]))], fixes=["restart_failed"]))
    F.append(finding("io", "io_list", "fine" if not kerr["usb"] and not net_bad else "info",
                     "%d input devices, %d USB devices" % (len(set(inputs)), len(usb)),
                     "Everything that answered at scan time." if have_log else "Kernel log wasn't readable, so errors weren't checked.",
                     metrics=io_metrics))

    # ---- security
    F += linux_security(info, deep, root_disk, crypt)

    # ---- system
    procs = process_table()
    F += process_findings(procs)
    reclaim = {}
    reclaim["Thumbnails"] = dir_size(os.path.join(HOME, ".cache", "thumbnails"))
    reclaim["Trash"] = dir_size(os.path.join(HOME, ".local", "share", "Trash"))
    reclaim["Package downloads"] = sum(os.path.getsize(p) for p in glob.glob("/var/cache/apt/archives/*.deb") if os.path.isfile(p))
    ju = run_out(["journalctl", "--disk-usage"])
    mj = re.search(r"take up ([\d.]+)([KMGT])", ju)
    if mj:
        reclaim["System logs"] = int(float(mj.group(1)) * {"K": 1 << 10, "M": 1 << 20, "G": 1 << 30, "T": 1 << 40}[mj.group(2)])
    total = sum(reclaim.values())
    rm = [m(k, fmt_bytes(v)) for k, v in reclaim.items() if v > 1 << 20]
    if total > 1 << 30:
        F.append(finding("system", "reclaim", "watch", "%s of caches and leftovers can go" % fmt_bytes(total),
                         "Safe to remove. They rebuild on their own if needed.", metrics=rm, fixes=["clean_caches", "empty_trash"]))
    else:
        F.append(finding("system", "reclaim", "fine", "Caches are small", "%s in caches and leftovers." % fmt_bytes(total), metrics=rm))
    auto = [p for p in glob.glob(os.path.join(HOME, ".config", "autostart", "*.desktop")) if "Hidden=true" not in read(p)]
    if auto:
        names = [os.path.basename(p)[:-8] for p in auto]
        F.append(finding("system", "startup", "watch" if len(auto) > 8 else "info",
                         "%d app%s start with your session" % (len(auto), "" if len(auto) == 1 else "s"),
                         "Each one adds to login time. Turn off the ones you don't need in Startup Applications.",
                         metrics=[m("Apps", ", ".join(names[:8]))]))
    return info, F, snap, extras


def battery_findings(full, design, cycles, cap, status, hist, snap):
    out = []
    if not full or not design:
        out.append(finding("power", "battery", "info", "Battery found, health unknown",
                           "The battery doesn't report its design capacity.",
                           metrics=[m("Charge", "%s%%" % cap if cap is not None else "unknown"), m("Status", status or "unknown")]))
        return out
    health = min(100.0, full * 100.0 / design)
    snap["battery"] = health
    bm = [m("Health", "%d%%" % round(health)), m("Charge", "%s%%" % cap if cap is not None else "unknown")]
    if cycles:
        bm.append(m("Cycles", fmt_int(cycles)))
    if status:
        bm.append(m("Status", status))
    when = None
    age, old = oldest_matching(hist, lambda s: s["battery"], min_age_days=14)
    if old is not None and old > health and age:
        per_month = (old - health) / age * 30
        bm.append(m("Wear", "%.1f%% a month" % per_month))
        if health > 50 and per_month > 0.1:
            months = (health - 50) / per_month
            when = "Down to half in about %d months" % max(1, round(months))
    if health < 40:
        urg, title = "soon", "Battery holds only %d%% of its original charge" % round(health)
        detail = "Expect short runtimes and sudden shutdowns. A replacement battery is usually cheap."
    elif health < 70:
        urg, title = "watch", "Battery is worn to %d%%" % round(health)
        detail = "Normal for an older battery. Replace it when runtime gets annoying."
    else:
        urg, title = "fine", "Battery health is %d%%" % round(health)
        detail = "Holding up well."
    out.append(finding("power", "battery", urg, title, detail, when=when, metrics=bm))
    return out


def linux_security(info, deep, root_disk, crypt):
    F = []
    osr = linux_os_release()
    pm = linux_pkg_manager()
    # updates
    total = sec = None
    if pm == "apt-get":
        out = run_out(["apt-get", "-s", "-o", "Debug::NoLocking=1", "upgrade"], timeout=60)
        inst = [l for l in out.splitlines() if l.startswith("Inst ")]
        total = len(inst)
        sec = len([l for l in inst if "-security" in l])
    elif pm == "dnf":
        rc, out = run(["dnf", "-q", "--cacheonly", "check-update"], timeout=60)
        if rc == 100:
            total = len([l for l in out.splitlines() if l.strip() and not l.startswith(" ")])
            rc2, out2 = run(["dnf", "-q", "--cacheonly", "updateinfo", "list", "--security"], timeout=60)
            sec = len([l for l in out2.splitlines() if l.strip()])
        elif rc == 0:
            total = 0
    elif pm == "pacman":
        out = run_out(["checkupdates"], timeout=60) if which("checkupdates") else run_out(["pacman", "-Qu"], timeout=30)
        total = len([l for l in out.splitlines() if l.strip()])
    elif pm == "zypper":
        out = run_out(["zypper", "-q", "--non-interactive", "lu"], timeout=90)
        total = len([l for l in out.splitlines() if l.startswith("v ")])
    if total is not None:
        mets = [m("Waiting", fmt_int(total))]
        if sec is not None:
            mets.append(m("Security fixes", fmt_int(sec)))
        if sec:
            F.append(finding("security", "updates", "soon", "%s updates waiting, %s of them security fixes" % (fmt_int(total), fmt_int(sec)),
                             "Security updates close holes that are already public. Install them soon.",
                             when="This week", metrics=mets, fixes=["updates_all"]))
        elif total and total > 30:
            F.append(finding("security", "updates", "soon", "%s updates waiting" % fmt_int(total),
                             "A big backlog. Install them to stay patched.", when="This week", metrics=mets, fixes=["updates_all"]))
        elif total:
            F.append(finding("security", "updates", "watch", "%s updates waiting" % fmt_int(total), "Install them when convenient.",
                             metrics=mets, fixes=["updates_all"]))
        else:
            F.append(finding("security", "updates", "fine", "Software is up to date", "As of the last package list refresh.", metrics=mets))
    if pm == "apt-get" and osr.get("ID_LIKE", osr.get("ID", "")).find("debian") >= 0 or osr.get("ID") in ("debian", "ubuntu"):
        au = read("/etc/apt/apt.conf.d/20auto-upgrades")
        if not re.search(r'Unattended-Upgrade\s+"1"', au):
            F.append(finding("security", "auto_updates", "watch", "Security updates don't install by themselves",
                             "Turn on unattended upgrades so security fixes land even when you forget.",
                             when="Set once", fixes=["auto_updates"]))

    # cpu vulnerabilities
    vuln = []
    for p in sorted(glob.glob("/sys/devices/system/cpu/vulnerabilities/*")):
        v = read(p).strip()
        if v.startswith("Vulnerable"):
            vuln.append("%s (%s)" % (os.path.basename(p).replace("_", " "), v[:60]))
    vendor = ""
    for line in read("/proc/cpuinfo").splitlines():
        if line.startswith("vendor_id"):
            vendor = line.split(":", 1)[1].strip()
            break
    mc_pkg = "intel-microcode" if "Intel" in vendor else ("amd64-microcode" if "AMD" in vendor else None)
    mc_missing = bool(mc_pkg and pm == "apt-get" and "install ok installed" not in run_out(["dpkg-query", "-W", "-f=${Status}", mc_pkg]))
    if vuln:
        F.append(finding("security", "cpu_vuln", "soon", "CPU has %d unpatched hardware flaw%s" % (len(vuln), "" if len(vuln) == 1 else "s"),
                         "Microcode and kernel updates add mitigations for these." + (" The %s package isn't installed." % mc_pkg if mc_missing else ""),
                         metrics=[m("Flaws", "; ".join(vuln[:4]))], fixes=(["microcode"] if mc_missing else []) + ["updates_all"]))
    elif mc_missing:
        F.append(finding("security", "microcode", "watch", "CPU microcode updates aren't installed",
                         "The %s package delivers CPU security and stability fixes at boot." % mc_pkg, fixes=["microcode"]))

    # firewall
    fw_on, fw_name = False, None
    if deep and deep.get("ufw"):
        fw_name = "ufw"
        fw_on = "Status: active" in deep["ufw"]
    elif os.path.exists("/etc/ufw/ufw.conf"):
        fw_name = "ufw"
        fw_on = bool(re.search(r"^ENABLED=yes", read("/etc/ufw/ufw.conf"), re.M)) and run_out(["systemctl", "is-active", "ufw"]).strip() == "active"
    if not fw_on and which("firewall-cmd"):
        if run_out(["firewall-cmd", "--state"]).strip() == "running":
            fw_on, fw_name = True, "firewalld"
        elif not fw_name:
            fw_name = "firewalld"
    listeners = linux_listeners(deep.get("ss") if deep else None)
    lf, exposed = listener_findings(listeners, fw_on)
    if fw_on:
        F.append(finding("security", "firewall", "fine", "Firewall is on", "%s is active." % fw_name))
    else:
        F.append(finding("security", "firewall", "soon" if exposed else "watch", "Firewall is off",
                         "Nothing blocks incoming connections. "
                         + ("Services are listening on the network, so turn it on." if exposed else "Nothing is exposed right now, but turning it on costs nothing."),
                         when="This week" if exposed else WHEN_DEFAULT["watch"],
                         fixes=["firewall_on"] if (fw_name or which("ufw") or linux_pkg_manager() == "apt-get") else []))
    F += lf

    # ssh server hardening
    if 22 in exposed:
        conf = read("/etc/ssh/sshd_config") + "".join(read(p) for p in sorted(glob.glob("/etc/ssh/sshd_config.d/*.conf")))
        def opt(name):
            mm3 = re.search(r"^\s*%s\s+(\S+)" % name, conf, re.M | re.I)
            return mm3.group(1).lower() if mm3 else None
        issues = []
        if opt("PermitRootLogin") == "yes":
            issues.append("root can log in")
        if opt("PasswordAuthentication") in (None, "yes"):
            issues.append("passwords are accepted")
        if issues:
            F.append(finding("security", "sshd", "watch", "SSH server is open and " + " and ".join(issues),
                             "Use keys instead of passwords and block root logins in /etc/ssh/sshd_config. "
                             "Test a key login first so you don't lock yourself out."))

    # disk encryption
    if crypt:
        F.append(finding("security", "encryption", "fine", "System drive is encrypted", "LUKS protects the data if the machine is lost."))
    else:
        laptop = bool(glob.glob("/sys/class/power_supply/BAT*"))
        F.append(finding("security", "encryption", "watch" if laptop else "info", "System drive isn't encrypted",
                         "If this %s is lost or stolen, anyone can read the drive by plugging it into another machine. "
                         "Encryption is set up at install time, so plan it for your next reinstall or the SSD swap."
                         % ("laptop" if laptop else "machine"), when="Next reinstall"))

    # secure boot
    if os.path.isdir("/sys/firmware/efi"):
        sb = None
        for p in glob.glob("/sys/firmware/efi/efivars/SecureBoot-*"):
            try:
                with open(p, "rb") as f:
                    sb = f.read()[-1] == 1
            except Exception:
                pass
        if sb is None and which("mokutil"):
            sb = "enabled" in run_out(["mokutil", "--sb-state"])
        if sb is False:
            F.append(finding("security", "secureboot", "watch", "Secure Boot is off",
                             "Secure Boot stops tampered bootloaders. Turn it on in the firmware setup if your drivers allow it.",
                             when="Next restart"))
        elif sb:
            F.append(finding("security", "secureboot", "fine", "Secure Boot is on", "Only signed bootloaders can start."))
    else:
        F.append(finding("security", "secureboot", "info", "Booting in legacy BIOS mode", "Secure Boot needs UEFI mode."))

    # screen lock and auto login
    if which("gsettings") and os.environ.get("DISPLAY") or os.environ.get("WAYLAND_DISPLAY"):
        le = run_out(["gsettings", "get", "org.gnome.desktop.screensaver", "lock-enabled"]).strip()
        if le == "false":
            F.append(finding("security", "screen_lock", "watch", "Screen doesn't lock when idle",
                             "Anyone at the keyboard gets your session. Turn the lock on.", fixes=["screen_lock"]))
    for conf in ("/etc/gdm3/custom.conf", "/etc/gdm/custom.conf"):
        if re.search(r"^\s*AutomaticLoginEnable\s*=\s*true", read(conf), re.M | re.I):
            F.append(finding("security", "autologin", "watch", "Automatic login is on",
                             "The machine starts straight into your account with no password. Turn it off in Settings > Users."))
            break
    F += secrets_findings()
    return F


# ------------------------------------------------------------------------------
#  Windows
# ------------------------------------------------------------------------------
WIN_PS = r"""
$ErrorActionPreference = 'SilentlyContinue'
$r = @{}
function T($k, [scriptblock]$b) { try { $r[$k] = & $b } catch { $r[$k] = $null } }
T os { $o = Get-CimInstance Win32_OperatingSystem; @{ caption=$o.Caption; version=$o.Version; build=$o.BuildNumber; total=[int64]$o.TotalVisibleMemorySize*1024; free=[int64]$o.FreePhysicalMemory*1024; boot=$o.LastBootUpTime.ToString('o'); arch=$o.OSArchitecture } }
T cs { $c = Get-CimInstance Win32_ComputerSystem; @{ maker=$c.Manufacturer; model=$c.Model } }
T cpu { $p = Get-CimInstance Win32_Processor | Select-Object -First 1; @{ name=$p.Name.Trim(); cores=$p.NumberOfLogicalProcessors; load=$p.LoadPercentage } }
T pagefile { Get-CimInstance Win32_PageFileUsage | ForEach-Object { @{ used=$_.CurrentUsage; size=$_.AllocatedBaseSize } } }
T bios { $b = Get-CimInstance Win32_BIOS; @{ version=$b.SMBIOSBIOSVersion; date=$b.ReleaseDate.ToString('yyyy-MM-dd'); maker=$b.Manufacturer } }
T board { $b = Get-CimInstance Win32_BaseBoard; @{ maker=$b.Manufacturer; product=$b.Product } }
T volumes { Get-Volume | Where-Object { $_.DriveLetter -and $_.DriveType -eq 'Fixed' -and $_.Size -gt 0 } | ForEach-Object { @{ letter="$($_.DriveLetter):"; label=$_.FileSystemLabel; size=[int64]$_.Size; free=[int64]$_.SizeRemaining; fs=$_.FileSystem } } }
T disks { Get-PhysicalDisk | ForEach-Object { $rc = $_ | Get-StorageReliabilityCounter; @{ name=$_.FriendlyName; media="$($_.MediaType)"; bus="$($_.BusType)"; health="$($_.HealthStatus)"; op="$($_.OperationalStatus)"; size=[int64]$_.Size; serial="$($_.SerialNumber)".Trim(); temp=$rc.Temperature; wear=$rc.Wear; poh=$rc.PowerOnHours; rerr=$rc.ReadErrorsUncorrected; werr=$rc.WriteErrorsUncorrected } } }
T sysdisk { (Get-Partition -DriveLetter ($env:SystemDrive.TrimEnd(':')) | Get-Disk).FriendlyName }
T battery { $b = Get-CimInstance Win32_Battery | Select-Object -First 1; if ($b) { $d = (Get-CimInstance -Namespace root\wmi -ClassName BatteryStaticData | Select-Object -First 1).DesignedCapacity; $f = (Get-CimInstance -Namespace root\wmi -ClassName BatteryFullChargedCapacity | Select-Object -First 1).FullChargedCapacity; $c = (Get-CimInstance -Namespace root\wmi -ClassName BatteryCycleCount | Select-Object -First 1).CycleCount; @{ charge=$b.EstimatedChargeRemaining; status=$b.BatteryStatus; design=$d; full=$f; cycles=$c } } }
T thermal { Get-CimInstance -Namespace root\wmi -ClassName MSAcpi_ThermalZoneTemperature | ForEach-Object { [math]::Round($_.CurrentTemperature/10 - 273.15,1) } }
T problems { Get-CimInstance Win32_PnPEntity | Where-Object { $_.ConfigManagerErrorCode -ne 0 } | ForEach-Object { @{ name=$_.Name; code=$_.ConfigManagerErrorCode; cls=$_.PNPClass } } }
T inputs { Get-CimInstance Win32_PnPEntity | Where-Object { $_.PNPClass -in 'Keyboard','Mouse','HIDClass','USB' -and $_.Status -eq 'OK' } | ForEach-Object { @{ name=$_.Name; cls=$_.PNPClass } } }
T diskevents { $since=(Get-Date).AddDays(-7); Get-WinEvent -FilterHashtable @{LogName='System'; Id=7,11,51,129,153,157; StartTime=$since} -MaxEvents 200 | ForEach-Object { @{ id=$_.Id; src=$_.ProviderName; msg=($_.Message -split "`n")[0] } } }
T whea { (Get-WinEvent -FilterHashtable @{LogName='System'; ProviderName='Microsoft-Windows-WHEA-Logger'; StartTime=(Get-Date).AddDays(-30)} -MaxEvents 200 | Measure-Object).Count }
T defender { $d = Get-MpComputerStatus; @{ av=$d.AntivirusEnabled; rtp=$d.RealTimeProtectionEnabled; sigage=$d.AntivirusSignatureAge; quickage=$d.QuickScanAge; service=$d.AMServiceEnabled } }
T firewall { Get-NetFirewallProfile | ForEach-Object { @{ name=$_.Name; on=[bool]$_.Enabled } } }
T bitlocker { $v = Get-BitLockerVolume -MountPoint $env:SystemDrive; @{ status="$($v.ProtectionStatus)"; pct=$v.EncryptionPercentage } }
T secureboot { Confirm-SecureBootUEFI }
T uac { (Get-ItemProperty 'HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\Policies\System').EnableLUA }
T rdp { (Get-ItemProperty 'HKLM:\System\CurrentControlSet\Control\Terminal Server').fDenyTSConnections }
T smb1 { (Get-SmbServerConfiguration).EnableSMB1Protocol }
T reboot { (Test-Path 'HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\Component Based Servicing\RebootPending') -or (Test-Path 'HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\WindowsUpdate\Auto Update\RebootRequired') }
T listen { Get-NetTCPConnection -State Listen | ForEach-Object { @{ host=$_.LocalAddress; port=$_.LocalPort; proc=(Get-Process -Id $_.OwningProcess).ProcessName } } }
T startup { (Get-CimInstance Win32_StartupCommand | Measure-Object).Count }
T startupnames { Get-CimInstance Win32_StartupCommand | Select-Object -First 10 | ForEach-Object { $_.Name } }
T temp { $s=0; foreach ($p in @($env:TEMP, "$env:SystemRoot\Temp")) { $s += (Get-ChildItem $p -Recurse -Force -File | Measure-Object Length -Sum).Sum }; [int64]$s }
T guest { (Get-LocalUser -Name Guest).Enabled }
T procs { Get-Process | Group-Object ProcessName | ForEach-Object { @{ name=$_.Name; rss=[int64](($_.Group | Measure-Object WorkingSet64 -Sum).Sum) } } | Sort-Object { -$_.rss } | Select-Object -First 6 }
T svcfail { Get-CimInstance Win32_Service -Filter "StartMode='Auto' AND State='Stopped' AND ExitCode<>0" | Select-Object -First 10 | ForEach-Object { $_.DisplayName } }
$r | ConvertTo-Json -Depth 5 -Compress
"""

WIN_UPDATES_PS = r"""
$ErrorActionPreference = 'Stop'
try {
  $s = (New-Object -ComObject Microsoft.Update.Session).CreateUpdateSearcher()
  $res = $s.Search("IsInstalled=0 and IsHidden=0 and Type='Software'")
  $sec = 0
  foreach ($u in $res.Updates) { foreach ($c in $u.Categories) { if ($c.Name -match 'Security') { $sec++; break } } }
  @{ total=$res.Updates.Count; security=$sec } | ConvertTo-Json -Compress
} catch { '{"error":"' + $_.Exception.Message.Replace('"',"'") + '"}' }
"""


def ps(script, timeout=120):
    exe = "powershell.exe"
    rc, out = run([exe, "-NoProfile", "-NonInteractive", "-ExecutionPolicy", "Bypass", "-Command", script], timeout=timeout)
    return out


def as_list(x):
    if x is None:
        return []
    return x if isinstance(x, list) else [x]


def windows_collect(deep=None, ctx=None):
    raw = ps(WIN_PS, timeout=180)
    try:
        r = json.loads(raw[raw.find("{"):])
    except Exception:
        r = {}
    hist = load_history()
    snap = {"t": time.time(), "disks": {}, "volumes": {}, "battery": None}
    extras = {"disks": [], "volumes": []}
    F = []
    o = r.get("os") or {}
    cpu = r.get("cpu") or {}
    cs = r.get("cs") or {}
    boot = None
    try:
        boot = dt.datetime.fromisoformat(o.get("boot", "")[:19])
    except Exception:
        pass
    pf = as_list(r.get("pagefile"))
    info = {
        "name": platform.node(),
        "os": o.get("caption") or "Windows",
        "kernel": "build %s" % o.get("build", ""),
        "arch": o.get("arch") or platform.machine(),
        "cpu": cpu.get("name") or platform.processor(),
        "cores": cpu.get("cores") or os.cpu_count(),
        "ram_total": o.get("total"),
        "ram_available": o.get("free"),
        "swap_total": sum((p.get("size") or 0) for p in pf) * (1 << 20),
        "swap_free": sum(((p.get("size") or 0) - (p.get("used") or 0)) for p in pf) * (1 << 20),
        "uptime": (dt.datetime.now() - boot).total_seconds() if boot else 0,
        "model": ("%s %s" % (cs.get("maker", ""), cs.get("model", ""))).strip(),
    }

    # drives
    vols = []
    for v in as_list(r.get("volumes")):
        label = v["letter"] + ((" " + v["label"]) if v.get("label") else "")
        if v["letter"].upper() == os.environ.get("SystemDrive", "C:").upper():
            label = "System drive (%s)" % v["letter"]
        vols.append({"mount": v["letter"], "label": label, "size": v.get("size"), "free": v.get("free"), "fs": v.get("fs")})
        snap["volumes"][v["letter"]] = v.get("free")
    extras["volumes"] = vols
    F += space_findings(vols, hist)

    smart = smart_read_all() if which("smartctl") else None
    smart_serials = set()
    if smart:
        for j in smart.get("disks", []):
            sm = parse_smart(j)
            extras["disks"].append(sm)
            smart_serials.add(sm["serial"])
            snap["disks"][sm["serial"] or sm["dev"]] = disk_snapshot(sm)
            F += smart_findings(sm, hist, ctx)
    for d in as_list(r.get("disks")):
        if d.get("serial") in smart_serials:
            continue
        metrics = [m("Type", "%s %s" % (d.get("media"), d.get("bus"))), m("Health", d.get("health"))]
        if d.get("temp"):
            metrics.append(m("Temperature", "%s°C" % d["temp"]))
        if d.get("poh"):
            metrics.append(m("Power-on hours", fmt_int(d["poh"])))
        if d.get("wear") is not None:
            metrics.append(m("Wear", "%s%%" % d["wear"]))
        name = d.get("name") or "Disk"
        errs = (d.get("rerr") or 0) + (d.get("werr") or 0)
        if d.get("health") in ("Unhealthy",):
            F.append(finding("drives", "disk_" + name, "now", "%s reports it is unhealthy" % name,
                             "Windows marked this drive unhealthy. Back up today and replace it.", when="Back up today", metrics=metrics))
        elif d.get("health") == "Warning" or errs:
            F.append(finding("drives", "disk_" + name, "soon", "%s has warnings" % name,
                             "%s uncorrected read/write errors. Back up and run a check." % fmt_int(errs), metrics=metrics, fixes=["chkdsk_scan"]))
        elif d.get("wear") and d["wear"] >= 90:
            F.append(finding("drives", "disk_" + name, "soon", "%s is %s%% worn" % (name, d["wear"]),
                             "This SSD is near the end of its rated write life.", metrics=metrics))
        else:
            F.append(finding("drives", "disk_" + name, "fine", "%s looks healthy" % name,
                             "Windows reports it healthy." + ("" if which("smartctl") else " Install smartmontools for sector-level detail."),
                             metrics=metrics, fixes=[] if which("smartctl") else ["smart_install"]))
        if d.get("media") == "HDD" and d.get("name") == r.get("sysdisk"):
            F.append(finding("drives", "system_hdd", "watch", "Windows is on a spinning hard disk",
                             "This is the main reason the PC feels slow. An SSD is the biggest speed upgrade you can make.",
                             when="Next upgrade"))
    ev = as_list(r.get("diskevents"))
    if ev:
        F.append(finding("drives", "disk_events", "soon", "%d disk errors in the last 7 days" % len(ev),
                         "Windows logged bad blocks, resets or paging errors. Check the drive and its cable.",
                         metrics=[m("Latest", (ev[0].get("msg") or "")[:160])], fixes=["chkdsk_scan"]))

    # memory
    tot, free = info["ram_total"] or 0, info["ram_available"] or 0
    used_pct = (tot - free) * 100.0 / tot if tot else 0
    mm_metrics = [m("Installed", fmt_bytes(tot)), m("In use", "%d%%" % round(used_pct))]
    if tot and free / float(tot) < 0.08:
        F.append(finding("memory", "ram_pressure", "soon", "Memory is nearly full", "Only %s free." % fmt_bytes(free), metrics=mm_metrics))
    elif tot and tot < 7.5 * (1 << 30):
        F.append(finding("memory", "ram_small", "watch", "%s of RAM is tight for Windows 10 or 11" % fmt_bytes(tot),
                         "8 GB or more makes a real difference.", when="Next upgrade", metrics=mm_metrics))
    else:
        F.append(finding("memory", "ram_ok", "fine", "%s installed, %d%% in use" % (fmt_bytes(tot), round(used_pct)), "Plenty of headroom.",
                         metrics=mm_metrics, fixes=["memdiag"]))
    whea = r.get("whea") or 0
    if whea:
        F.append(finding("board", "whea", "soon", "%d hardware errors in the last 30 days" % whea,
                         "WHEA errors point to RAM, CPU or board trouble. Run Windows Memory Diagnostic.", fixes=["memdiag"]))

    # board
    temps = [t for t in as_list(r.get("thermal")) if isinstance(t, (int, float)) and 0 < t < 130]
    bios = r.get("bios") or {}
    board = r.get("board") or {}
    bm = [m("CPU", info["cpu"]), m("Cores", str(info["cores"]))]
    if cpu.get("load") is not None:
        bm.append(m("Load", "%s%%" % cpu["load"]))
    if temps:
        bm.append(m("Temperature", "%d°C" % round(max(temps))))
        if max(temps) >= 90:
            F.append(finding("board", "cpu_hot", "now", "System is at %d°C" % round(max(temps)), "Clean the fan and vents.", when="Today", metrics=bm))
        elif max(temps) >= 80:
            F.append(finding("board", "cpu_warm", "soon", "System is running hot at %d°C" % round(max(temps)), "Dust in the fan is the usual cause.", metrics=bm))
    try:
        bd = dt.datetime.strptime(bios.get("date", ""), "%Y-%m-%d")
        if (dt.datetime.now() - bd).days > 5 * 365:
            F.append(finding("board", "bios_old", "watch", "Firmware is from %d" % bd.year,
                             "Check %s's support site for a newer BIOS." % (board.get("maker") or bios.get("maker") or "the maker"),
                             when="Check once", metrics=[m("BIOS", "%s, %s" % (bios.get("version", ""), bios.get("date", "")))]))
    except Exception:
        pass
    if not [f for f in F if f["area"] == "board"]:
        F.append(finding("board", "board_ok", "fine", "CPU and board look fine", "No overheating or hardware errors.", metrics=bm))

    # power
    b = r.get("battery")
    if b:
        F += battery_findings(b.get("full"), b.get("design"), b.get("cycles"), b.get("charge"), "", hist, snap)
    else:
        F.append(finding("power", "no_battery", "info", "No battery found", "Desktop or battery removed."))

    # io
    probs = as_list(r.get("problems"))
    if probs:
        F.append(finding("io", "pnp_problems", "soon", "%d device%s with driver problems" % (len(probs), "" if len(probs) == 1 else "s"),
                         "These show a warning in Device Manager. Reinstall or update their drivers.",
                         metrics=[m("Devices", ", ".join("%s (code %s)" % (p.get("name"), p.get("code")) for p in probs[:5]))],
                         fixes=["open_devmgmt"]))
    inputs = as_list(r.get("inputs"))
    kb = [i["name"] for i in inputs if i.get("cls") in ("Keyboard", "Mouse")]
    F.append(finding("io", "io_list", "fine" if not probs else "info", "%d keyboards and pointers, %d USB and HID devices" % (len(kb), len(inputs) - len(kb)),
                     "Everything that answered at scan time.", metrics=[m("Inputs", ", ".join(sorted(set(kb))[:5]))]))
    sf = as_list(r.get("svcfail"))
    if sf:
        F.append(finding("system", "failed_units", "watch", "%d services stopped with an error" % len(sf), "They are set to start automatically but crashed.",
                         metrics=[m("Services", ", ".join(sf[:6]))]))

    # security
    upd = None
    try:
        upd = json.loads(ps(WIN_UPDATES_PS, timeout=150).strip() or "{}")
    except Exception:
        upd = None
    if upd and "total" in upd:
        if upd["security"]:
            F.append(finding("security", "updates", "soon", "%d updates waiting, %d security" % (upd["total"], upd["security"]),
                             "Install them in Windows Update.", when="This week", fixes=["updates_all"]))
        elif upd["total"]:
            F.append(finding("security", "updates", "watch", "%d updates waiting" % upd["total"], "Install them when convenient.", fixes=["updates_all"]))
        else:
            F.append(finding("security", "updates", "fine", "Windows is up to date", "No updates waiting."))
    d = r.get("defender") or {}
    if d:
        if not d.get("rtp") or not d.get("av"):
            F.append(finding("security", "defender", "now", "Real-time virus protection is off",
                             "Turn Microsoft Defender back on unless another antivirus is installed.", when="Today", fixes=["defender_on"]))
        elif (d.get("sigage") or 0) > 7:
            F.append(finding("security", "defender", "soon", "Virus definitions are %d days old" % d["sigage"], "Update them.",
                             fixes=["defender_sigs"]))
        else:
            F.append(finding("security", "defender", "fine", "Microsoft Defender is on and current",
                             "Last quick scan %s days ago." % d.get("quickage", "?"), fixes=["defender_quick"]))
    fw = as_list(r.get("firewall"))
    off = [p["name"] for p in fw if not p.get("on")]
    if off:
        F.append(finding("security", "firewall", "soon", "Firewall is off for %s" % ", ".join(off), "Turn it back on.", when="This week",
                         fixes=["firewall_on"]))
    elif fw:
        F.append(finding("security", "firewall", "fine", "Firewall is on", "All profiles are protected."))
    bl = r.get("bitlocker")
    if bl and bl.get("status") != "On":
        F.append(finding("security", "encryption", "watch", "System drive isn't encrypted",
                         "Turn on BitLocker or Device Encryption so a lost laptop doesn't expose your files.", fixes=["open_bitlocker"]))
    elif bl:
        F.append(finding("security", "encryption", "fine", "BitLocker is on", "The system drive is encrypted."))
    if r.get("secureboot") is False:
        F.append(finding("security", "secureboot", "watch", "Secure Boot is off", "Turn it on in the firmware setup."))
    if r.get("uac") == 0:
        F.append(finding("security", "uac", "soon", "User Account Control is off", "Programs can change the system without asking. Turn UAC back on.",
                         fixes=["uac_on"]))
    if r.get("smb1"):
        F.append(finding("security", "smb1", "soon", "SMBv1 file sharing is on", "This old protocol was used by WannaCry. Turn it off.",
                         fixes=["smb1_off"]))
    if r.get("guest"):
        F.append(finding("security", "guest", "watch", "Guest account is enabled", "Disable it in Computer Management."))
    if r.get("rdp") == 0:
        F.append(finding("security", "rdp", "info", "Remote Desktop is on", "Fine if you use it. Keep NLA on and the firewall limited."))
    listeners = [{"host": l.get("host", ""), "port": l.get("port"), "proc": l.get("proc", ""), "proto": "tcp"} for l in as_list(r.get("listen"))]
    lf, exposed = listener_findings(listeners, not off)
    F += lf
    F += secrets_findings()

    # system
    if r.get("reboot"):
        F.append(finding("system", "reboot_required", "soon", "Restart to finish installing updates", "Windows is waiting for a restart.", when="Today or tomorrow"))
    elif info["uptime"] > 21 * 86400:
        F.append(finding("system", "uptime_long", "watch", "Running for %d days without a restart" % (info["uptime"] // 86400),
                         "Fast Startup doesn't count as a restart. Use Restart, not Shut down."))
    procs = as_list(r.get("procs"))
    if procs:
        F.append(finding("system", "top_memory", "info", "Biggest memory users right now", "Grouped by program name.",
                         metrics=[m(p["name"], fmt_bytes(p["rss"])) for p in procs]))
    tmp = r.get("temp") or 0
    if tmp > 1 << 30:
        F.append(finding("system", "reclaim", "watch", "%s of temporary files can go" % fmt_bytes(tmp), "Safe to remove.",
                         fixes=["clean_caches", "component_cleanup"]))
    else:
        F.append(finding("system", "reclaim", "fine", "Temporary files are small", "%s in temp folders." % fmt_bytes(tmp)))
    su = r.get("startup") or 0
    if su:
        F.append(finding("system", "startup", "watch" if su > 8 else "info", "%d app%s start with Windows" % (su, "" if su == 1 else "s"),
                         "Turn off the ones you don't need in Task Manager > Startup apps.",
                         metrics=[m("Apps", ", ".join(as_list(r.get("startupnames"))[:8]))], fixes=["open_startup"]))
    return info, F, snap, extras


# ------------------------------------------------------------------------------
#  macOS
# ------------------------------------------------------------------------------
def mac_collect(deep=None, ctx=None):
    hist = load_history()
    snap = {"t": time.time(), "disks": {}, "volumes": {}, "battery": None}
    extras = {"disks": [], "volumes": []}
    F = []
    sysctl = lambda k: run_out(["sysctl", "-n", k]).strip()
    total = int(sysctl("hw.memsize") or 0)
    boot = re.search(r"sec = (\d+)", sysctl("kern.boottime"))
    up = time.time() - int(boot.group(1)) if boot else 0
    swap = sysctl("vm.swapusage")
    sw_tot = re.search(r"total = ([\d.]+)M", swap)
    sw_used = re.search(r"used = ([\d.]+)M", swap)
    pressure = run_out(["memory_pressure"])
    free_pct = re.search(r"free percentage: (\d+)%", pressure)
    info = {
        "name": platform.node().replace(".local", ""),
        "os": "macOS " + run_out(["sw_vers", "-productVersion"]).strip(),
        "kernel": platform.release(),
        "arch": platform.machine(),
        "cpu": sysctl("machdep.cpu.brand_string") or platform.processor(),
        "cores": os.cpu_count(),
        "ram_total": total,
        "ram_available": int(total * int(free_pct.group(1)) / 100) if free_pct else None,
        "swap_total": int(float(sw_tot.group(1)) * (1 << 20)) if sw_tot else 0,
        "swap_free": int((float(sw_tot.group(1)) - float(sw_used.group(1))) * (1 << 20)) if sw_tot and sw_used else 0,
        "uptime": up,
        "model": sysctl("hw.model"),
    }
    # drives
    vols = []
    for mnt, label in (("/System/Volumes/Data", "System drive"), ("/", None)):
        if os.path.isdir(mnt) and (label or not vols):
            try:
                st = os.statvfs(mnt)
                vols.append({"mount": mnt, "label": label or "System drive", "size": st.f_blocks * st.f_frsize, "free": st.f_bavail * st.f_frsize})
            except Exception:
                pass
    for v in glob.glob("/Volumes/*"):
        if os.path.ismount(v) and not os.path.islink(v):
            try:
                st = os.statvfs(v)
                vols.append({"mount": v, "label": os.path.basename(v), "size": st.f_blocks * st.f_frsize, "free": st.f_bavail * st.f_frsize})
            except Exception:
                pass
    for v in vols:
        snap["volumes"][v["mount"]] = v["free"]
    extras["volumes"] = vols
    F += space_findings(vols, hist)
    dinfo = run_out(["diskutil", "info", "/"])
    smart_status = re.search(r"SMART Status:\s+(.*)", dinfo)
    smart = smart_read_all() if which("smartctl") else None
    if smart and smart.get("disks"):
        for j in smart["disks"]:
            sm = parse_smart(j)
            extras["disks"].append(sm)
            snap["disks"][sm["serial"] or sm["dev"]] = disk_snapshot(sm)
            F += smart_findings(sm, hist, ctx)
    elif smart_status:
        s = smart_status.group(1).strip()
        if s.lower().startswith("fail"):
            F.append(finding("drives", "smart_mac", "now", "The internal drive reports it is failing", "Back up with Time Machine today.", when="Back up today"))
        else:
            F.append(finding("drives", "smart_mac", "fine", "The internal drive reports %s" % s.lower(),
                             "Install smartmontools for wear and error detail.", fixes=["smart_install"] if not which("smartctl") else []))
    # memory
    if free_pct:
        fp = int(free_pct.group(1))
        mm_metrics = [m("Installed", fmt_bytes(total)), m("Free", "%d%%" % fp), m("Swap used", "%s" % fmt_bytes(info["swap_total"] - info["swap_free"]))]
        if fp < 10:
            F.append(finding("memory", "ram_pressure", "soon", "Memory pressure is high", "Close heavy apps or browser tabs.", metrics=mm_metrics))
        else:
            F.append(finding("memory", "ram_ok", "fine", "%s installed, %d%% free" % (fmt_bytes(total), fp), "Memory pressure is normal.", metrics=mm_metrics))
    # board
    F.append(finding("board", "board_ok", "info", info["model"] or "Mac", "macOS doesn't expose CPU temperature without admin tools.",
                     metrics=[m("CPU", info["cpu"]), m("Cores", str(info["cores"]))]))
    # power
    try:
        pj = json.loads(run_out(["system_profiler", "SPPowerDataType", "-json"], timeout=30) or "{}")
        for item in pj.get("SPPowerDataType", []):
            hi = item.get("sppower_battery_health_info")
            if hi:
                cyc = hi.get("sppower_battery_cycle_count")
                cond = hi.get("sppower_battery_health")
                maxc = hi.get("sppower_battery_health_maximum_capacity")
                h = int(str(maxc).rstrip("%")) if maxc else None
                bm = [m("Condition", cond or "unknown")]
                if cyc:
                    bm.append(m("Cycles", fmt_int(cyc)))
                if h:
                    bm.append(m("Maximum capacity", "%d%%" % h))
                    snap["battery"] = h
                if cond and cond.lower() not in ("good", "normal"):
                    F.append(finding("power", "battery", "soon", "Battery condition: %s" % cond, "Apple recommends service.", metrics=bm))
                elif h and h < 80:
                    F.append(finding("power", "battery", "watch", "Battery is worn to %d%%" % h, "Normal for an older battery.", metrics=bm))
                else:
                    F.append(finding("power", "battery", "fine", "Battery is healthy", "Holding up well.", metrics=bm))
    except Exception:
        pass
    # security
    fw = run_out(["/usr/libexec/ApplicationFirewall/socketfilterfw", "--getglobalstate"])
    fw_on = "enabled" in fw.lower()
    F.append(finding("security", "firewall", "fine" if fw_on else "watch", "Firewall is on" if fw_on else "Firewall is off",
                     "" if fw_on else "Turn on the macOS firewall.", fixes=[] if fw_on else ["firewall_on"]))
    fv = run_out(["fdesetup", "status"])
    if "On" in fv:
        F.append(finding("security", "encryption", "fine", "FileVault is on", "The drive is encrypted."))
    else:
        F.append(finding("security", "encryption", "watch", "FileVault is off", "Turn it on in Privacy & Security.", fixes=["open_filevault"]))
    gk = run_out(["spctl", "--status"])
    if "disabled" in gk:
        F.append(finding("security", "gatekeeper", "soon", "Gatekeeper is off", "Any downloaded app can run without checks.", fixes=["gatekeeper_on"]))
    sip = run_out(["csrutil", "status"])
    if "disabled" in sip.lower():
        F.append(finding("security", "sip", "soon", "System Integrity Protection is off", "Turn it back on from Recovery: csrutil enable."))
    su = run_out(["softwareupdate", "-l"], timeout=90)
    if su:
        n = len([l for l in su.splitlines() if l.strip().startswith("* Label:") or l.strip().startswith("*")])
        if n:
            F.append(finding("security", "updates", "soon", "%d macOS update%s waiting" % (n, "" if n == 1 else "s"), "Install them in System Settings.",
                             fixes=["updates_all"]))
        elif "No new software" in su:
            F.append(finding("security", "updates", "fine", "macOS is up to date", "No updates waiting."))
    listeners = []
    for line in run_out(["lsof", "-nP", "-iTCP", "-sTCP:LISTEN"]).splitlines()[1:]:
        p = line.split()
        if len(p) >= 9:
            host, _, port = p[8].rpartition(":")
            try:
                listeners.append({"host": host.strip("[]"), "port": int(port), "proc": p[0], "proto": "tcp"})
            except ValueError:
                pass
    lf, exposed = listener_findings(listeners, fw_on)
    F += lf
    F += secrets_findings()
    procs = process_table()
    F += process_findings(procs)
    caches = dir_size(os.path.join(HOME, "Library", "Caches"))
    if caches > 2 << 30:
        F.append(finding("system", "reclaim", "watch", "%s of app caches" % fmt_bytes(caches), "They rebuild on their own.", fixes=["clean_caches"]))
    if up > 21 * 86400:
        F.append(finding("system", "uptime_long", "watch", "Running for %d days without a restart" % (up // 86400), "Restart to apply updates."))
    F.append(finding("io", "io_list", "info", "Inputs and outputs", "macOS reports USB and Bluetooth devices in System Information."))
    return info, F, snap, extras


# ------------------------------------------------------------------------------
#  Fixes
# ------------------------------------------------------------------------------
class Fix:
    def __init__(self, fid, title, desc, risk="safe", admin=False, slow=False, restart=False, steps=None, func=None, area="system"):
        self.id, self.title, self.desc, self.risk = fid, title, desc, risk
        self.admin, self.slow, self.restart = admin, slow, restart
        self.steps = steps or []      # list of (label, argv)
        self.func = func              # callable(log) for python-side work
        self.area = area

    def public(self):
        return {"id": self.id, "title": self.title, "desc": self.desc, "risk": self.risk, "admin": self.admin,
                "slow": self.slow, "restart": self.restart, "area": self.area}


def _fix_secrets_perms(log):
    for p in secret_files():
        try:
            if OS == "windows":
                user = os.environ.get("USERNAME", "")
                rc, out = run(["icacls", p, "/inheritance:r", "/grant:r", "%s:F" % user])
            else:
                os.chmod(p, 0o600)
                rc = 0
            log("ok" if rc == 0 else "warn", "Locked down %s" % os.path.relpath(p, HOME))
        except Exception as e:
            log("err", "%s: %s" % (p, e))


def _fix_ssh_perms(log):
    d = os.path.join(HOME, ".ssh")
    try:
        os.chmod(d, 0o700)
        log("ok", "~/.ssh is now private")
    except Exception as e:
        log("err", str(e))
    for p in glob.glob(os.path.join(d, "id_*")):
        if not p.endswith(".pub"):
            try:
                os.chmod(p, 0o600)
                log("ok", "Locked down %s" % os.path.relpath(p, HOME))
            except Exception as e:
                log("err", str(e))


def _fix_zombie_parents(log):
    procs = process_table()
    byid = {p[0]: p for p in procs}
    me = os.getuid() if hasattr(os, "getuid") else None
    parents = sorted({p[1] for p in procs if p[2] == "Z"})
    if not parents:
        log("skip", "No dead processes left")
    for pp in parents:
        par = byid.get(pp)
        if pp <= 1 or not par:
            log("skip", "Parent %d is the init process. These clear on their own." % pp)
            continue
        if me is not None and par[5] != me:
            log("skip", "%s (%d) belongs to another user, left alone" % (par[3], pp))
            continue
        try:
            os.kill(pp, 15)
            log("ok", "Asked %s (%d) to exit" % (par[3], pp))
        except Exception as e:
            log("err", "%s: %s" % (par[3], e))


def _fix_clear_dir(path, label):
    def f(log):
        n, size = 0, 0
        for entry in glob.glob(os.path.join(path, "*")) + glob.glob(os.path.join(path, ".*")):
            try:
                if os.path.isdir(entry) and not os.path.islink(entry):
                    size += dir_size(entry)
                    shutil.rmtree(entry, ignore_errors=True)
                else:
                    size += os.lstat(entry).st_size
                    os.remove(entry)
                n += 1
            except Exception:
                pass
        log("ok", "%s: removed %s" % (label, fmt_bytes(size)))
    return f


def _fix_auto_updates(log):
    try:
        with open("/etc/apt/apt.conf.d/20auto-upgrades", "w") as f:
            f.write('APT::Periodic::Update-Package-Lists "1";\nAPT::Periodic::Unattended-Upgrade "1";\n')
        log("ok", "Security updates will now install automatically")
    except Exception as e:
        log("err", str(e))


def build_fixes():
    fx = {}

    def add(f):
        fx[f.id] = f

    smart = which("smartctl") or "smartctl"

    def smart_test(kind):
        devs = [d["name"] for d in smart_scan_devices()] or ["/dev/sda"]
        return [("Start %s self-test on %s" % (kind, d), [smart, "-t", kind, d]) for d in devs]

    if OS == "linux":
        pm = linux_pkg_manager()
        inst = {"apt-get": ["apt-get", "install", "-y"], "dnf": ["dnf", "install", "-y"], "pacman": ["pacman", "-S", "--noconfirm"],
                "zypper": ["zypper", "-n", "install"]}.get(pm, ["apt-get", "install", "-y"])
        upd = {
            "apt-get": [("Refresh package lists", ["apt-get", "update"]), ("Install updates", ["apt-get", "-y", "-o", "Dpkg::Options::=--force-confold", "upgrade"])],
            "dnf": [("Install updates", ["dnf", "-y", "upgrade"])],
            "pacman": [("Install updates", ["pacman", "-Syu", "--noconfirm"])],
            "zypper": [("Install updates", ["zypper", "-n", "update"])],
        }.get(pm, [])
        add(Fix("smart_install", "Install smartmontools", "Lets How Soon read drive health, bad sectors and wear.", "safe", admin=True,
                steps=[("Install smartmontools", inst + ["smartmontools"])], area="drives"))
        add(Fix("updates_all", "Install all updates", "Installs every waiting package update, security fixes included.", "moderate", admin=True, slow=True,
                steps=upd, area="security"))
        add(Fix("auto_updates", "Turn on automatic security updates", "Installs unattended-upgrades and switches it on.", "moderate", admin=True,
                steps=[("Install unattended-upgrades", ["apt-get", "install", "-y", "unattended-upgrades"])], func=_fix_auto_updates, area="security"))
        vendor = "intel" if "Intel" in read("/proc/cpuinfo") else "amd64"
        add(Fix("microcode", "Install CPU microcode updates", "Adds the %s-microcode package. Takes effect after a restart." % vendor, "moderate",
                admin=True, restart=True, steps=[("Install microcode", inst + ["%s-microcode" % vendor])], area="security"))
        fw_steps = []
        if which("ufw") or pm == "apt-get":
            if not which("ufw"):
                fw_steps.append(("Install ufw", inst + ["ufw"]))
            if linux_listeners() and any(l["port"] == 22 and is_exposed(l["host"]) for l in linux_listeners()):
                fw_steps.append(("Keep SSH reachable", ["ufw", "allow", "OpenSSH"]))
            fw_steps.append(("Turn on ufw", ["ufw", "--force", "enable"]))
        elif which("firewall-cmd") or which("systemctl"):
            fw_steps.append(("Start firewalld", ["systemctl", "enable", "--now", "firewalld"]))
        add(Fix("firewall_on", "Turn on the firewall", "Blocks incoming connections you didn't start. Keeps SSH open if it is in use.", "moderate",
                admin=True, steps=fw_steps, area="security"))
        add(Fix("smart_short", "Run a short drive self-test", "About 2 minutes. Rescan afterwards to see the result.", "safe", admin=True,
                steps=smart_test("short"), area="drives"))
        add(Fix("smart_long", "Run a full drive surface test", "Reads every sector, about 1 to 3 hours on a hard disk. You can keep working. Rescan when it is done.",
                "safe", admin=True, slow=True, steps=smart_test("long"), area="drives"))
        add(Fix("fstrim", "Trim SSDs", "Tells SSDs which blocks are free, which keeps write speed up.", "safe", admin=True,
                steps=[("Trim mounted filesystems", ["fstrim", "-av"])], area="drives"))
        add(Fix("clean_caches", "Clear package and log caches", "Removes downloaded package files and trims system logs to 2 weeks.", "safe", admin=True,
                steps=([("Clear package cache", ["apt-get", "clean"])] if pm == "apt-get" else
                       [("Clear package cache", ["dnf", "clean", "all"])] if pm == "dnf" else
                       [("Clear package cache", ["pacman", "-Sc", "--noconfirm"])] if pm == "pacman" else []) +
                      [("Trim system logs", ["journalctl", "--vacuum-time=2weeks"])], area="system"))
        if pm == "apt-get":
            add(Fix("autoremove", "Remove unused packages", "apt autoremove: old kernels and libraries nothing depends on any more.", "moderate", admin=True,
                    steps=[("Remove unused packages", ["apt-get", "autoremove", "--purge", "-y"])], area="system"))
        add(Fix("clear_thumbs", "Clear thumbnail cache", "File manager previews. They rebuild as you browse.", "safe",
                func=_fix_clear_dir(os.path.join(HOME, ".cache", "thumbnails"), "Thumbnails"), area="system"))
        add(Fix("empty_trash", "Empty the Trash", "Permanently deletes everything in the Trash.", "moderate",
                func=_fix_clear_dir(os.path.join(HOME, ".local", "share", "Trash", "files"), "Trash"), area="system"))
        add(Fix("restart_failed", "Restart failed services", "Tries each failed service once more.", "moderate", admin=True,
                steps=[("Restart %s" % u, ["systemctl", "restart", u]) for u in
                       [l.split()[0] for l in run_out(["systemctl", "--failed", "--no-legend", "--plain"]).splitlines() if l.strip()]][:10],
                area="system"))
        add(Fix("screen_lock", "Lock the screen when idle", "Turns on GNOME's screen lock.", "safe",
                steps=[("Turn on screen lock", ["gsettings", "set", "org.gnome.desktop.screensaver", "lock-enabled", "true"])], area="security"))
        if which("fwupdmgr"):
            add(Fix("firmware_check", "Check for firmware updates", "Asks fwupd (LVFS) if your board, SSD or dock has newer firmware. Only checks, installs nothing.",
                    "safe", steps=[("Refresh firmware list", ["fwupdmgr", "refresh", "--force"]), ("List updates", ["fwupdmgr", "get-updates"])], area="board"))
            add(Fix("firmware_apply", "Install firmware updates", "Flashes firmware from fwupd. Keep the laptop on power and don't interrupt it.",
                    "advanced", admin=True, restart=True, steps=[("Install firmware", ["fwupdmgr", "update", "-y", "--no-reboot-check"])], area="board"))
        add(Fix("flatpak_unused", "Remove unused Flatpak runtimes", "Old runtimes left behind by removed apps.", "safe",
                steps=[("Remove unused runtimes", ["flatpak", "uninstall", "--unused", "-y"])] if which("flatpak") else [], area="system"))
    elif OS == "windows":
        P = lambda s: ["powershell.exe", "-NoProfile", "-ExecutionPolicy", "Bypass", "-Command", s]
        add(Fix("restore_point", "Create a restore point", "So you can roll back. Made automatically before Moderate and Advanced fixes.", "safe", admin=True,
                steps=[("Create restore point", P("Enable-ComputerRestore -Drive $env:SystemDrive; Checkpoint-Computer -Description 'How Soon - before fixes' -RestorePointType MODIFY_SETTINGS"))]))
        add(Fix("smart_install", "Install smartmontools", "Lets How Soon read sector-level drive health. Uses winget.", "safe", admin=True,
                steps=[("Install smartmontools", ["winget", "install", "-e", "--id", "smartmontools.smartmontools", "--accept-source-agreements", "--accept-package-agreements"])],
                area="drives"))
        add(Fix("updates_all", "Check and install Windows updates", "Starts Windows Update and opens it so you can watch.", "moderate", admin=True, slow=True,
                steps=[("Start update scan", ["UsoClient.exe", "StartInteractiveScan"]), ("Open Windows Update", ["cmd", "/c", "start", "ms-settings:windowsupdate"])],
                area="security"))
        add(Fix("defender_sigs", "Update virus definitions", "Downloads the latest Microsoft Defender definitions.", "safe", admin=True,
                steps=[("Update definitions", P("Update-MpSignature"))], area="security"))
        add(Fix("defender_quick", "Run a quick virus scan", "Microsoft Defender quick scan, a few minutes.", "safe", admin=True, slow=True,
                steps=[("Quick scan", P("Start-MpScan -ScanType QuickScan"))], area="security"))
        add(Fix("defender_on", "Turn real-time protection on", "Re-enables Microsoft Defender real-time protection.", "moderate", admin=True,
                steps=[("Turn on protection", P("Set-MpPreference -DisableRealtimeMonitoring $false"))], area="security"))
        add(Fix("firewall_on", "Turn on the firewall", "Turns on Windows Firewall for every profile.", "moderate", admin=True,
                steps=[("Turn on firewall", P("Set-NetFirewallProfile -All -Enabled True"))], area="security"))
        add(Fix("smb1_off", "Turn off SMBv1", "Disables the old file sharing protocol. Very old NAS boxes may stop working.", "advanced", admin=True, restart=True,
                steps=[("Disable SMBv1", P("Set-SmbServerConfiguration -EnableSMB1Protocol $false -Force"))], area="security"))
        add(Fix("uac_on", "Turn User Account Control on", "Programs will ask before changing the system again.", "moderate", admin=True, restart=True,
                steps=[("Turn on UAC", P("Set-ItemProperty 'HKLM:\\SOFTWARE\\Microsoft\\Windows\\CurrentVersion\\Policies\\System' EnableLUA 1"))], area="security"))
        add(Fix("open_bitlocker", "Open encryption settings", "BitLocker needs you to save a recovery key, so it is turned on by hand.", "safe",
                steps=[("Open BitLocker", ["control.exe", "/name", "Microsoft.BitLockerDriveEncryption"])], area="security"))
        add(Fix("sfc", "Repair system files (SFC)", "Checks and repairs Windows system files. 10 to 30 minutes.", "safe", admin=True, slow=True,
                steps=[("sfc /scannow", ["sfc.exe", "/scannow"])], area="system"))
        add(Fix("dism", "Repair the Windows image (DISM)", "Fixes the store SFC repairs from. 10 to 40 minutes.", "safe", admin=True, slow=True,
                steps=[("DISM RestoreHealth", ["DISM.exe", "/Online", "/Cleanup-Image", "/RestoreHealth"])], area="system"))
        add(Fix("chkdsk_scan", "Scan the system drive for errors", "Online chkdsk scan. Doesn't need a restart.", "safe", admin=True, slow=True,
                steps=[("chkdsk /scan", ["chkdsk.exe", os.environ.get("SystemDrive", "C:"), "/scan"])], area="drives"))
        add(Fix("smart_short", "Run a short drive self-test", "About 2 minutes. Needs smartmontools.", "safe", admin=True, steps=smart_test("short") if which("smartctl") else [], area="drives"))
        add(Fix("smart_long", "Run a full drive surface test", "1 to 3 hours on a hard disk. Needs smartmontools.", "safe", admin=True, slow=True,
                steps=smart_test("long") if which("smartctl") else [], area="drives"))
        add(Fix("memdiag", "Open Windows Memory Diagnostic", "Tests RAM on the next restart. You choose when.", "safe", admin=True, restart=True,
                steps=[("Open Memory Diagnostic", ["mdsched.exe"])], area="memory"))
        add(Fix("optimize", "Optimize drives", "TRIM on SSDs, defragment on hard disks.", "safe", admin=True, slow=True,
                steps=[("Optimize system drive", P("Optimize-Volume -DriveLetter $env:SystemDrive.TrimEnd(':') -Verbose"))], area="drives"))
        add(Fix("clean_caches", "Clear temporary files", "Your temp folder and the Windows temp folder.", "safe", admin=True,
                steps=[("Clear temp", P("Remove-Item \"$env:TEMP\\*\",\"$env:SystemRoot\\Temp\\*\" -Recurse -Force -ErrorAction SilentlyContinue"))], area="system"))
        add(Fix("component_cleanup", "Clean up old Windows components", "Removes superseded update files. 5 to 20 minutes.", "safe", admin=True, slow=True,
                steps=[("DISM StartComponentCleanup", ["DISM.exe", "/Online", "/Cleanup-Image", "/StartComponentCleanup"])], area="system"))
        add(Fix("open_devmgmt", "Open Device Manager", "Reinstall or update the drivers flagged with a warning.", "safe",
                steps=[("Open Device Manager", ["mmc.exe", "devmgmt.msc"])], area="io"))
        add(Fix("open_startup", "Open startup apps", "Task Manager, Startup apps tab.", "safe", steps=[("Open Task Manager", ["taskmgr.exe", "/7", "/startup"])], area="system"))
    else:  # mac
        brew = which("brew")
        add(Fix("smart_install", "Install smartmontools", "Uses Homebrew. Lets How Soon read drive wear and errors.", "safe",
                steps=[("brew install smartmontools", [brew, "install", "smartmontools"])] if brew else [], area="drives"))
        add(Fix("updates_all", "Install macOS updates", "Downloads and installs every waiting update. May restart the Mac.", "moderate", admin=True, slow=True, restart=True,
                steps=[("softwareupdate", ["softwareupdate", "-ia", "--verbose"])], area="security"))
        add(Fix("firewall_on", "Turn on the firewall", "macOS application firewall.", "moderate", admin=True,
                steps=[("Turn on firewall", ["/usr/libexec/ApplicationFirewall/socketfilterfw", "--setglobalstate", "on"])], area="security"))
        add(Fix("gatekeeper_on", "Turn Gatekeeper back on", "Checks downloaded apps before they run.", "moderate", admin=True,
                steps=[("Enable Gatekeeper", ["spctl", "--master-enable"])], area="security"))
        add(Fix("open_filevault", "Open FileVault settings", "Save the recovery key somewhere safe when you turn it on.", "safe",
                steps=[("Open settings", ["open", "x-apple.systempreferences:com.apple.preference.security?FileVault"])], area="security"))
        add(Fix("verify_disk", "Verify the system disk", "Disk Utility First Aid check, read only.", "safe", slow=True,
                steps=[("diskutil verifyVolume", ["diskutil", "verifyVolume", "/"])], area="drives"))
        add(Fix("clean_caches", "Clear app caches", "Your Library/Caches folder. Apps rebuild what they need.", "moderate",
                func=_fix_clear_dir(os.path.join(HOME, "Library", "Caches"), "Caches"), area="system"))
        add(Fix("smart_short", "Run a short drive self-test", "Needs smartmontools.", "safe", admin=True, steps=smart_test("short") if which("smartctl") else [], area="drives"))
        add(Fix("smart_long", "Run a full drive self-test", "Needs smartmontools.", "safe", admin=True, slow=True, steps=smart_test("long") if which("smartctl") else [], area="drives"))

    add(Fix("secrets_perms", "Restrict password files to you", "Makes the flagged files readable only by your account. Moving them into a password manager is still the real fix.",
            "safe", func=_fix_secrets_perms, area="security"))
    if OS != "windows":
        add(Fix("ssh_perms", "Lock down SSH keys", "chmod 700 ~/.ssh and 600 on private keys.", "safe", func=_fix_ssh_perms, area="security"))
        add(Fix("zombie_parents", "Restart parents of dead processes", "Asks the programs that left zombies behind to exit. Skips system processes.",
                "moderate", func=_fix_zombie_parents, area="system"))
    # drop fixes with nothing to do
    return {k: v for k, v in fx.items() if v.steps or v.func}


# ------------------------------------------------------------------------------
#  Fix runner (in-process for user fixes, one elevated helper for admin fixes)
# ------------------------------------------------------------------------------
class Runner:
    def __init__(self, state):
        self.state = state
        self.proc = None
        self.stop = False

    def log(self, lvl, text):
        self.state.add_log(lvl, text)

    def run_steps(self, fx, log, proc_hook=None):
        for label, argv in fx.steps:
            if self.stop:
                log("warn", "Stopped")
                return False
            log("info", label)
            log("cmd", " ".join(shlex.quote(a) for a in argv) if OS != "windows" else " ".join(argv))
            try:
                env = dict(os.environ)
                env["DEBIAN_FRONTEND"] = "noninteractive"
                p = subprocess.Popen(argv, stdout=subprocess.PIPE, stderr=subprocess.STDOUT, text=True, env=env,
                                     encoding="utf-8", errors="replace", creationflags=NO_WINDOW, bufsize=1)
                if proc_hook:
                    proc_hook(p)
                for line in p.stdout:
                    line = line.rstrip()
                    if line:
                        log("out", line[:400])
                rc = p.wait()
                if rc == 0:
                    log("ok", "%s: done" % label)
                else:
                    log("err", "%s: exited with code %d" % (label, rc))
            except FileNotFoundError:
                log("err", "%s: %s isn't installed" % (label, argv[0]))
            except Exception as e:
                log("err", "%s: %s" % (label, e))
        if fx.func:
            try:
                fx.func(log)
            except Exception as e:
                log("err", str(e))
        return True

    def start(self, ids):
        fixes = build_fixes()
        chosen = [fixes[i] for i in ids if i in fixes]
        if not chosen:
            return False
        self.stop = False
        t = threading.Thread(target=self._work, args=(chosen,), daemon=True)
        t.start()
        return True

    def _work(self, chosen):
        st = self.state
        st.running = True
        st.run_title = "Running %d fix%s" % (len(chosen), "" if len(chosen) == 1 else "es")
        logfile = os.path.join(data_dir(), "logs", dt.datetime.now().strftime("run-%Y%m%d-%H%M%S.log"))
        st.current_log = logfile
        try:
            user = [f for f in chosen if not f.admin]
            admin = [f for f in chosen if f.admin]
            if OS == "windows" and any(f.risk != "safe" for f in admin) and "restore_point" not in [f.id for f in admin]:
                rp = build_fixes().get("restore_point")
                if rp:
                    admin.insert(0, rp)
            for f in user:
                if self.stop:
                    break
                self.log("head", f.title)
                self.run_steps(f, self.log)
            if admin and not self.stop:
                if is_admin():
                    for f in admin:
                        if self.stop:
                            break
                        self.log("head", f.title)
                        self.run_steps(f, self.log, proc_hook=lambda p: setattr(self, "proc", p))
                else:
                    self.run_elevated([f.id for f in admin])
            self.log("done", "Finished. Rescan to see what changed.")
        except Exception as e:
            self.log("err", "Run failed: %s" % e)
        finally:
            st.running = False
            try:
                with open(logfile, "w", encoding="utf-8") as f:
                    for _, lvl, text in st.logs[st.run_log_start:]:
                        f.write("%s\t%s\n" % (lvl, text))
            except Exception:
                pass

    def run_elevated(self, ids):
        tmp = tempfile.NamedTemporaryFile(prefix="howsoon-", suffix=".log", delete=False)
        tmp.close()
        if OS != "windows":
            os.chmod(tmp.name, 0o666)
        args = self_cmd() + ["--run-fixes", ",".join(ids), "--log", tmp.name, "--home", HOME]
        self.log("info", "Asking for your password to run %d admin fix%s" % (len(ids), "" if len(ids) == 1 else "es"))
        if OS == "linux":
            if which("pkexec") and (os.environ.get("DISPLAY") or os.environ.get("WAYLAND_DISPLAY")):
                cmd = ["pkexec"] + args
            elif run(["sudo", "-n", "true"])[0] == 0:
                cmd = ["sudo", "-n"] + args
            else:
                self.log("err", "No graphical password prompt (pkexec) found. Start How Soon with sudo to run admin fixes.")
                return
        elif OS == "mac":
            sh = " ".join(shlex.quote(a) for a in args)
            sh = sh.replace("\\", "\\\\").replace('"', '\\"')
            cmd = ["osascript", "-e", 'do shell script "%s" with administrator privileges' % sh]
        else:
            self.log("err", "How Soon isn't running as administrator. Restart it and accept the prompt.")
            return
        p = subprocess.Popen(cmd, stdout=subprocess.DEVNULL, stderr=subprocess.PIPE, text=True)
        self.proc = p
        pos = 0
        while True:
            done = p.poll() is not None
            try:
                with open(tmp.name, "r", encoding="utf-8", errors="replace") as f:
                    f.seek(pos)
                    chunk = f.read()
                    pos = f.tell()
                for line in chunk.splitlines():
                    if "\t" in line:
                        lvl, text = line.split("\t", 1)
                        self.log(lvl, text)
            except Exception:
                pass
            if done:
                break
            if self.stop:
                try:
                    p.terminate()
                except Exception:
                    pass
            time.sleep(0.3)
        if p.returncode in (126, 127) and OS == "linux":
            self.log("warn", "Password prompt was cancelled")
        elif p.returncode and OS == "mac" and "User canceled" in (p.stderr.read() if p.stderr else ""):
            self.log("warn", "Password prompt was cancelled")
        try:
            os.remove(tmp.name)
        except Exception:
            pass


def helper_run_fixes(ids, logpath):
    """Runs inside the elevated helper process."""
    fixes = build_fixes()
    f = open(logpath, "a", encoding="utf-8", buffering=1)

    def log(lvl, text):
        f.write("%s\t%s\n" % (lvl, str(text).replace("\n", " ")))
    dummy = type("S", (), {"add_log": lambda self, l, t: log(l, t)})()
    r = Runner(dummy)
    for i in ids:
        fx = fixes.get(i)
        if not fx:
            continue
        log("head", fx.title)
        r.run_steps(fx, log)
    f.close()


def helper_collect():
    """Privileged data for a deep scan, printed as JSON."""
    out = {}
    if OS == "linux":
        out["smart"] = smart_read_all()
        out["ufw"] = run_out(["ufw", "status"]) if which("ufw") else ""
        out["ss"] = run_out(["ss", "-H", "-tulnp"])
        k, _ = linux_kernel_errors()
        out["kernel"] = k
    elif OS == "mac":
        out["smart"] = smart_read_all()
    print(json.dumps(out))


def deep_collect(state):
    """Run helper_collect elevated. Returns dict or None."""
    if is_admin():
        rc, txt = 0, ""
        buf = {}
        if OS == "linux":
            buf["smart"] = smart_read_all()
            buf["ufw"] = run_out(["ufw", "status"]) if which("ufw") else ""
            buf["ss"] = run_out(["ss", "-H", "-tulnp"])
        return buf
    args = self_cmd() + ["--collect"]
    if OS == "linux":
        if which("pkexec") and (os.environ.get("DISPLAY") or os.environ.get("WAYLAND_DISPLAY")):
            rc, txt = run(["pkexec"] + args, timeout=300)
        else:
            rc, txt = run(["sudo", "-n"] + args, timeout=300)
    elif OS == "mac":
        sh = " ".join(shlex.quote(a) for a in args).replace("\\", "\\\\").replace('"', '\\"')
        rc, txt = run(["osascript", "-e", 'do shell script "%s" with administrator privileges' % sh], timeout=300)
    else:
        return None
    if rc != 0:
        state.add_log("warn", "Deep scan cancelled or not allowed. Showing the quick scan.")
        return None
    try:
        return json.loads(txt[txt.find("{"):])
    except Exception:
        return None


# ------------------------------------------------------------------------------
#  Scan orchestration
# ------------------------------------------------------------------------------
def summarize(findings):
    counts = {"now": 0, "soon": 0, "watch": 0, "fine": 0, "info": 0}
    for f in findings:
        counts[f["urgency"]] += 1
    areas = {}
    for key, label in AREAS:
        fs = [f for f in findings if f["area"] == key]
        worst = min((URGENCY_ORDER[f["urgency"]] for f in fs if f["urgency"] != "info"), default=3)
        areas[key] = {"label": label, "worst": [k for k, v in URGENCY_ORDER.items() if v == worst][0], "count": len(fs)}
    return counts, areas


def area_figure(key, info, findings, extras):
    """One headline figure per area for the overview cards."""
    if key == "drives":
        sysv = next((v for v in extras.get("volumes", []) if v["label"].startswith("System")), None)
        if sysv:
            return fmt_bytes(sysv["free"]) + " free", "on the system drive"
    if key == "memory" and info.get("ram_total"):
        used = (info["ram_total"] - (info.get("ram_available") or 0)) * 100.0 / info["ram_total"]
        return fmt_bytes(info["ram_total"]), "%d%% in use" % round(used)
    if key == "board":
        for f in findings:
            for mm in f["metrics"]:
                if "emperature" in mm["label"]:
                    return mm["value"], "CPU"
        return "%s cores" % info.get("cores"), "CPU"
    if key == "power":
        for f in findings:
            if f["id"] == "battery":
                for mm in f["metrics"]:
                    if mm["label"] in ("Health", "Maximum capacity"):
                        return mm["value"], "battery health"
        return "AC", "no battery"
    if key == "security":
        n = len([f for f in findings if f["area"] == "security" and f["urgency"] in ("now", "soon", "watch")])
        return str(n), "issue" if n == 1 else "issues"
    if key == "io":
        return str(len([f for f in findings if f["area"] == "io" and f["urgency"] in ("now", "soon", "watch")])), "problems"
    if key == "system":
        return fmt_duration(info.get("uptime")), "since restart"
    return "", ""


def do_scan(state, deep=False):
    state.scanning = True
    state.scan_step = "Starting"
    t0 = time.time()
    try:
        deep_data = None
        if deep:
            state.scan_step = "Waiting for your password"
            deep_data = deep_collect(state)
        state.scan_step = "Checking drives, memory, board, power and security"
        collect = {"linux": linux_collect, "windows": windows_collect, "mac": mac_collect}[OS]
        info, F, snap, extras = collect(deep_data, {})
        fixes = build_fixes()
        for f in F:
            f["fixes"] = [x for x in f["fixes"] if x in fixes]
        F.sort(key=lambda f: (URGENCY_ORDER[f["urgency"]], [a for a, _ in AREAS].index(f["area"])))
        counts, areas = summarize(F)
        for key in areas:
            fig, cap = area_figure(key, info, F, extras)
            areas[key]["figure"], areas[key]["caption"] = fig, cap
        used = set(x for f in F if f["urgency"] in ("now", "soon", "watch") for x in f["fixes"])
        maint = {"smart_long", "smart_short", "fstrim", "clean_caches", "sfc", "dism", "chkdsk_scan", "optimize",
                 "defender_quick", "verify_disk", "memdiag", "firmware_check", "clear_thumbs", "flatpak_unused", "restore_point", "component_cleanup"}
        fix_list = []
        for fid, fx in fixes.items():
            if fid in used or fid in maint:
                d = fx.public()
                d["suggested"] = fid in used
                d["for"] = [f["title"] for f in F if fid in f["fixes"] and f["urgency"] in ("now", "soon", "watch")][:3]
                fix_list.append(d)
        risk_rank = {"safe": 0, "moderate": 1, "advanced": 2}
        fix_list.sort(key=lambda d: (not d["suggested"], risk_rank[d["risk"]], d["title"]))
        snap["counts"] = counts
        save_history(snap)
        info["is_admin"] = is_admin()
        info["platform"] = OS
        info["uptime_text"] = fmt_duration(info.get("uptime"))
        info["ram_text"] = fmt_bytes(info.get("ram_total"))
        state.report = {
            "info": info, "findings": F, "counts": counts, "areas": areas, "fixes": fix_list,
            "volumes": [dict(v, free_text=fmt_bytes(v["free"]), size_text=fmt_bytes(v["size"])) for v in extras.get("volumes", [])],
            "disks": [{k: v for k, v in d.items() if k != "attrs"} for d in extras.get("disks", [])],
            "scanned_at": dt.datetime.now().strftime("%Y-%m-%d %H:%M"), "deep": bool(deep_data),
            "took": round(time.time() - t0, 1), "scans": len(load_history()),
        }
        state.add_log("ok", "Scan finished in %.1fs: %d now, %d soon, %d watch" % (time.time() - t0, counts["now"], counts["soon"], counts["watch"]))
    except Exception as e:
        state.add_log("err", "Scan failed: %s" % e)
        state.add_log("out", traceback.format_exc()[-800:])
    finally:
        state.scanning = False
        state.scan_step = ""


def export_report(report):
    if not report:
        return None
    lines = ["# How Soon report: %s" % report["info"]["name"], "",
             "%s, %s. Scanned %s%s." % (report["info"]["os"], report["info"].get("model") or "", report["scanned_at"], " (deep scan)" if report["deep"] else ""), "",
             "| Now | Soon | Watch | Fine |", "|---|---|---|---|",
             "| %d | %d | %d | %d |" % tuple(report["counts"][k] for k in ("now", "soon", "watch", "fine")), ""]
    for key, label in AREAS:
        fs = [f for f in report["findings"] if f["area"] == key]
        if not fs:
            continue
        lines += ["## %s" % label, ""]
        for f in fs:
            lines.append("- **%s** %s: %s %s" % (f["urgency"].capitalize(), f["title"], f["detail"], ("(" + f["when"] + ")") if f["urgency"] != "fine" else ""))
            for mm in f["metrics"]:
                lines.append("    - %s: %s" % (mm["label"], mm["value"]))
        lines.append("")
    folder = os.path.join(HOME, "Documents") if os.path.isdir(os.path.join(HOME, "Documents")) else HOME
    path = os.path.join(folder, "HowSoon-%s-%s.md" % (re.sub(r"\W", "-", report["info"]["name"]), dt.datetime.now().strftime("%Y%m%d-%H%M")))
    with open(path, "w", encoding="utf-8") as f:
        f.write("\n".join(lines))
    return path


def open_path(path):
    try:
        if OS == "windows":
            os.startfile(path)  # noqa
        elif OS == "mac":
            subprocess.Popen(["open", path])
        else:
            subprocess.Popen(["xdg-open", path], stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL)
    except Exception:
        pass


# ------------------------------------------------------------------------------
#  Demo data (for screenshots and trying the UI without scanning)
# ------------------------------------------------------------------------------
def demo_report():
    F = [
        finding("security", "plaintext_secrets", "soon", "3 files with passwords or tokens in plain text",
                "Anything that can read your home folder can read these. Move recovery codes and passwords into a password manager, and use a credential helper instead of ~/.git-credentials.",
                when="This week", metrics=[m("Files", ".git-credentials, Downloads/github-recovery-codes.txt, Documents/keys/KEYSTORE-PASSWORD.txt"), m("Readable by others", "2")], fixes=["secrets_perms"]),
        finding("security", "updates", "soon", "239 updates waiting, 41 of them security fixes", "Security updates close holes that are already public. Install them soon.",
                when="This week", metrics=[m("Waiting", "239"), m("Security fixes", "41")], fixes=["updates_all"]),
        finding("security", "firewall", "soon", "Firewall is off", "Nothing blocks incoming connections. Services are listening on the network, so turn it on.",
                when="This week", fixes=["firewall_on"]),
        finding("drives", "smart_realloc", "watch", "ST9500325AS has reallocated sectors",
                "1 bad spot already swapped for a spare. A few is normal wear. If this number grows between scans, the drive is on its way out.",
                when="Rescan monthly", metrics=[m("Power-on hours", "5,619"), m("Temperature", "37°C"), m("Reallocated sectors", "1"), m("Pending sectors", "0")],
                fixes=["smart_short", "smart_long"]),
        finding("drives", "smart_past", "watch", "ST9500325AS went out of range in the past",
                "These attributes crossed their limit at some point: Airflow Temperature Cel. If it was temperature, keep the vents clear.",
                metrics=[m("Power-on hours", "5,619"), m("Temperature", "37°C")]),
        finding("drives", "system_hdd", "watch", "Your system drive is a spinning hard disk",
                "This is the main reason the machine feels slow. Boot, app launches and updates all wait on it. A SATA SSD is the single biggest speed upgrade and costs little.",
                when="Next upgrade", metrics=[m("Drive", "sda")]),
        finding("security", "encryption", "watch", "System drive isn't encrypted",
                "If this laptop is lost or stolen, anyone can read the drive by plugging it into another machine. Plan it for your next reinstall or the SSD swap.", when="Next reinstall"),
        finding("board", "bios_old", "watch", "Firmware is from 2017", "Board firmware fixes security holes and hardware bugs. Check the maker's site or fwupd for a newer version.",
                when="Check once", metrics=[m("Board", "Acer Ironman_SK"), m("BIOS", "V1.24, 03/09/2017")], fixes=["firmware_check"]),
        finding("power", "battery", "watch", "Battery is worn to 61%", "Normal for an older battery. Replace it when runtime gets annoying.",
                when="Down to half in about 14 months", metrics=[m("Health", "61%"), m("Charge", "88%"), m("Cycles", "412"), m("Wear", "0.8% a month")]),
        finding("system", "zombies", "watch", "2 dead processes waiting on their parent",
                "Zombie processes use no CPU or memory, but a pile of them points to a buggy program. Restarting the parent clears them.",
                metrics=[m("Parents", "steamwebhelper (2)")], fixes=["zombie_parents"]),
        finding("system", "startup", "info", "6 apps start with your session", "Each one adds to login time.", metrics=[m("Apps", "steam, telegramdesktop, qbittorrent, willyspeed, sticky, localsend")]),
        finding("drives", "space_root", "fine", "System drive has 212 GB free", "47% free.", metrics=[m("Free", "212 GB"), m("Size", "457 GB"), m("Used", "53%")]),
        finding("memory", "ram_ok", "fine", "18 GB installed, 14% in use", "Plenty of headroom.", metrics=[m("Installed", "18 GB"), m("In use", "14%"), m("Swap used", "0 B of 2 GB")]),
        finding("board", "board_ok", "fine", "CPU and board look fine", "No overheating, throttling or hardware errors.",
                metrics=[m("CPU", "Intel Core i5-7200U CPU @ 2.50GHz"), m("Cores", "4"), m("CPU temperature", "52°C"), m("Load", "0.84 on 4 cores")]),
        finding("io", "io_list", "fine", "4 input devices, 3 USB devices", "Everything that answered at scan time.",
                metrics=[m("Keyboards and pointers", "AT Translated Set 2 keyboard, ELAN Touchpad, Logitech M185"), m("USB devices", "Realtek card reader, HD WebCam, Logitech receiver")]),
        finding("security", "open_ports", "info", "2 services listening on the network", "None of them are on the usual risky list.", metrics=[m("Ports", "1716, 53317")]),
        finding("security", "secureboot", "fine", "Secure Boot is on", "Only signed bootloaders can start."),
        finding("system", "reclaim", "fine", "Caches are small", "640 MB in caches and leftovers."),
    ]
    F.sort(key=lambda f: (URGENCY_ORDER[f["urgency"]], [a for a, _ in AREAS].index(f["area"])))
    info = {"name": "brad-aspire-e5-575", "os": "Ubuntu 22.04.5 LTS", "kernel": "6.8.0-136-generic", "arch": "x86_64",
            "cpu": "Intel Core i5-7200U CPU @ 2.50GHz", "cores": 4, "ram_total": 18 << 30, "ram_available": int(15.4 * (1 << 30)),
            "uptime": 3 * 86400 + 4 * 3600, "model": "Acer Aspire E5-575", "is_admin": False, "platform": "linux",
            "uptime_text": "3d 4h", "ram_text": "18 GB"}
    counts, areas = summarize(F)
    figs = {"drives": ("212 GB free", "on the system drive"), "memory": ("18 GB", "14% in use"), "board": ("52°C", "CPU"),
            "power": ("61%", "battery health"), "security": ("4", "issues"), "io": ("0", "problems"), "system": ("3d 4h", "since restart")}
    for k in areas:
        areas[k]["figure"], areas[k]["caption"] = figs[k]
    fx = [
        {"id": "secrets_perms", "title": "Restrict password files to you", "desc": "Makes the flagged files readable only by your account. Moving them into a password manager is still the real fix.", "risk": "safe", "admin": False, "slow": False, "restart": False, "area": "security", "suggested": True, "for": ["3 files with passwords or tokens in plain text"]},
        {"id": "smart_short", "title": "Run a short drive self-test", "desc": "About 2 minutes. Rescan afterwards to see the result.", "risk": "safe", "admin": True, "slow": False, "restart": False, "area": "drives", "suggested": True, "for": ["ST9500325AS has reallocated sectors"]},
        {"id": "smart_long", "title": "Run a full drive surface test", "desc": "Reads every sector, about 1 to 3 hours on a hard disk. You can keep working. Rescan when it is done.", "risk": "safe", "admin": True, "slow": True, "restart": False, "area": "drives", "suggested": True, "for": ["ST9500325AS has reallocated sectors"]},
        {"id": "firmware_check", "title": "Check for firmware updates", "desc": "Asks fwupd (LVFS) if your board, SSD or dock has newer firmware. Only checks, installs nothing.", "risk": "safe", "admin": False, "slow": False, "restart": False, "area": "board", "suggested": True, "for": ["Firmware is from 2017"]},
        {"id": "updates_all", "title": "Install all updates", "desc": "Installs every waiting package update, security fixes included.", "risk": "moderate", "admin": True, "slow": True, "restart": False, "area": "security", "suggested": True, "for": ["239 updates waiting, 41 of them security fixes"]},
        {"id": "firewall_on", "title": "Turn on the firewall", "desc": "Blocks incoming connections you didn't start. Keeps SSH open if it is in use.", "risk": "moderate", "admin": True, "slow": False, "restart": False, "area": "security", "suggested": True, "for": ["Firewall is off"]},
        {"id": "zombie_parents", "title": "Restart parents of dead processes", "desc": "Asks the programs that left zombies behind to exit. Skips system processes.", "risk": "moderate", "admin": False, "slow": False, "restart": False, "area": "system", "suggested": True, "for": ["2 dead processes waiting on their parent"]},
        {"id": "clean_caches", "title": "Clear package and log caches", "desc": "Removes downloaded package files and trims system logs to 2 weeks.", "risk": "safe", "admin": True, "slow": False, "restart": False, "area": "system", "suggested": False, "for": []},
        {"id": "clear_thumbs", "title": "Clear thumbnail cache", "desc": "File manager previews. They rebuild as you browse.", "risk": "safe", "admin": False, "slow": False, "restart": False, "area": "system", "suggested": False, "for": []},
        {"id": "firmware_apply", "title": "Install firmware updates", "desc": "Flashes firmware from fwupd. Keep the laptop on power and don't interrupt it.", "risk": "advanced", "admin": True, "slow": False, "restart": True, "area": "board", "suggested": False, "for": []},
    ]
    return {"info": info, "findings": F, "counts": counts, "areas": areas, "fixes": fx,
            "volumes": [{"mount": "/", "label": "System drive", "size": 491 << 30, "free": 228 << 30, "free_text": "212 GB", "size_text": "457 GB"}],
            "disks": [{"dev": "/dev/sda", "model": "ST9500325AS", "serial": "5VE1XXXX", "capacity": 500107862016, "rotation": 5400, "passed": True,
                       "poh": 5619, "temp": 37, "life_left": None, "last_test": None}],
            "scanned_at": dt.datetime.now().strftime("%Y-%m-%d %H:%M"), "deep": True, "took": 6.4, "scans": 3}


# ------------------------------------------------------------------------------
#  App state and local server
# ------------------------------------------------------------------------------
class State:
    def __init__(self):
        self.lock = threading.Lock()
        self.logs = []          # (seq, lvl, text)
        self.seq = 0
        self.report = None
        self.scanning = False
        self.scan_step = ""
        self.running = False
        self.run_title = ""
        self.run_log_start = 0
        self.current_log = None
        self.last_ping = time.time()
        self.runner = Runner(self)

    def add_log(self, lvl, text):
        with self.lock:
            self.seq += 1
            self.logs.append((self.seq, lvl, str(text)))
            self.logs = self.logs[-4000:]


STATE = State()
TOKEN = secrets.token_urlsafe(24)
DEMO = False


def ui_html():
    here = os.path.dirname(os.path.abspath(__file__))
    for p in (os.path.join(here, "ui.html"), os.path.join(getattr(sys, "_MEIPASS", here), "ui.html")):
        if os.path.isfile(p):
            return read(p)
    return UI_HTML


UI_HTML = "__UI_HTML__"


class Handler(http.server.BaseHTTPRequestHandler):
    protocol_version = "HTTP/1.1"

    def log_message(self, *a):
        pass

    def _send(self, code, body, ctype="application/json"):
        data = body if isinstance(body, bytes) else body.encode("utf-8")
        self.send_response(code)
        self.send_header("Content-Type", ctype)
        self.send_header("Content-Length", str(len(data)))
        self.send_header("Cache-Control", "no-store")
        self.send_header("X-Content-Type-Options", "nosniff")
        self.end_headers()
        self.wfile.write(data)

    def _json(self, obj, code=200):
        self._send(code, json.dumps(obj))

    def _authed(self):
        return secrets.compare_digest(self.headers.get("X-HowSoon-Token", ""), TOKEN)

    def do_GET(self):
        u = urllib.parse.urlparse(self.path)
        if u.path == "/":
            q = urllib.parse.parse_qs(u.query)
            if not secrets.compare_digest((q.get("t") or [""])[0], TOKEN):
                return self._send(403, "Forbidden", "text/plain")
            html = ui_html().replace("__TOKEN__", TOKEN).replace("__VERSION__", APP_VERSION)
            self.send_response(200)
            data = html.encode("utf-8")
            self.send_header("Content-Type", "text/html; charset=utf-8")
            self.send_header("Content-Length", str(len(data)))
            self.send_header("Content-Security-Policy", "default-src 'self' 'unsafe-inline'; img-src 'self' data:; connect-src 'self'")
            self.send_header("Cache-Control", "no-store")
            self.end_headers()
            self.wfile.write(data)
            return
        if u.path == "/favicon.ico":
            return self._send(204, b"", "image/x-icon")
        if not self._authed():
            return self._send(403, "{}")
        if u.path == "/api/state":
            q = urllib.parse.parse_qs(u.query)
            since = int((q.get("since") or ["0"])[0])
            with STATE.lock:
                logs = [{"seq": s, "lvl": l, "text": t} for s, l, t in STATE.logs if s > since]
            STATE.last_ping = time.time()
            return self._json({
                "scanning": STATE.scanning, "scan_step": STATE.scan_step, "running": STATE.running, "run_title": STATE.run_title,
                "logs": logs, "has_report": STATE.report is not None, "report_id": id(STATE.report), "demo": DEMO,
            })
        if u.path == "/api/report":
            return self._json(STATE.report or {})
        return self._send(404, "{}")

    def do_POST(self):
        if not self._authed():
            return self._send(403, "{}")
        n = int(self.headers.get("Content-Length") or 0)
        try:
            body = json.loads(self.rfile.read(n) or b"{}")
        except Exception:
            body = {}
        p = urllib.parse.urlparse(self.path).path
        if p == "/api/scan":
            if STATE.scanning or STATE.running:
                return self._json({"ok": False, "error": "busy"})
            if DEMO:
                STATE.report = demo_report()
                STATE.add_log("ok", "Demo data loaded")
                return self._json({"ok": True})
            STATE.add_log("head", "Deep scan" if body.get("deep") else "Quick scan")
            threading.Thread(target=do_scan, args=(STATE, bool(body.get("deep"))), daemon=True).start()
            return self._json({"ok": True})
        if p == "/api/fix":
            ids = [str(i) for i in (body.get("ids") or [])][:40]
            if STATE.running or STATE.scanning:
                return self._json({"ok": False, "error": "busy"})
            if DEMO:
                STATE.add_log("head", "Demo run")
                for i in ids:
                    STATE.add_log("ok", "Would run %s" % i)
                STATE.add_log("done", "Demo mode changes nothing.")
                return self._json({"ok": True})
            STATE.run_log_start = len(STATE.logs)
            ok = STATE.runner.start(ids)
            return self._json({"ok": ok})
        if p == "/api/stop":
            STATE.runner.stop = True
            pr = STATE.runner.proc
            if pr and pr.poll() is None:
                try:
                    pr.terminate()
                except Exception:
                    pass
            return self._json({"ok": True})
        if p == "/api/export":
            try:
                path = export_report(STATE.report)
                if path:
                    STATE.add_log("ok", "Report saved to %s" % path)
                    open_path(path)
                return self._json({"ok": bool(path), "path": path})
            except Exception as e:
                return self._json({"ok": False, "error": str(e)})
        if p == "/api/open-logs":
            open_path(os.path.join(data_dir(), "logs"))
            return self._json({"ok": True})
        if p == "/api/ping":
            STATE.last_ping = time.time()
            return self._json({"ok": True})
        return self._send(404, "{}")


class Server(socketserver.ThreadingMixIn, http.server.HTTPServer):
    daemon_threads = True
    allow_reuse_address = True


def find_browser():
    cands = []
    if OS == "windows":
        for env in ("ProgramFiles(x86)", "ProgramFiles", "LOCALAPPDATA"):
            base = os.environ.get(env)
            if not base:
                continue
            cands += [os.path.join(base, r"Microsoft\Edge\Application\msedge.exe"),
                      os.path.join(base, r"Google\Chrome\Application\chrome.exe"),
                      os.path.join(base, r"BraveSoftware\Brave-Browser\Application\brave.exe")]
    elif OS == "mac":
        cands = ["/Applications/Google Chrome.app/Contents/MacOS/Google Chrome",
                 "/Applications/Microsoft Edge.app/Contents/MacOS/Microsoft Edge",
                 "/Applications/Brave Browser.app/Contents/MacOS/Brave Browser",
                 "/Applications/Chromium.app/Contents/MacOS/Chromium"]
    else:
        for n in ("google-chrome", "google-chrome-stable", "brave-browser", "brave", "chromium", "chromium-browser", "microsoft-edge"):
            p = shutil.which(n)
            if p:
                cands.append(p)
        cands += ["/var/lib/flatpak/exports/bin/com.google.Chrome", os.path.join(HOME, ".local/share/flatpak/exports/bin/com.google.Chrome"),
                  "/var/lib/flatpak/exports/bin/com.brave.Browser", "/snap/bin/chromium"]
    for c in cands:
        if c and os.path.isfile(c):
            return c
    return None


def open_window(url):
    """Returns 'webview' if a native window was used (and blocks until closed), else 'browser'."""
    try:
        import webview  # type: ignore
        icon = None
        webview.create_window(APP_NAME, url, width=1280, height=820, min_size=(980, 640), background_color="#111113")
        webview.start()
        return "webview"
    except ImportError:
        pass
    except Exception as e:
        print("Native window failed (%s), falling back to a browser window." % e)
    br = find_browser()
    if br:
        prof = os.path.join(data_dir(), "window-profile")
        try:
            subprocess.Popen([br, "--app=" + url, "--user-data-dir=" + prof, "--window-size=1280,820", "--no-first-run",
                              "--no-default-browser-check", "--disable-features=Translate"],
                             stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL, creationflags=NO_WINDOW)
            return "browser"
        except Exception:
            pass
    webbrowser.open(url)
    return "browser"


def windows_elevate():
    """Relaunch elevated like OPC V7 does. Returns True if this process should exit."""
    if OS != "windows" or is_admin() or "--no-elevate" in sys.argv:
        return False
    params = subprocess.list2cmdline((self_cmd()[1:] if not getattr(sys, "frozen", False) else []) + sys.argv[1:] + ["--no-elevate"])
    try:
        rc = ctypes.windll.shell32.ShellExecuteW(None, "runas", sys.executable, params, None, 1)
        return rc > 32
    except Exception:
        return False


def main():
    global DEMO
    argv = sys.argv[1:]
    if "--collect" in argv:
        helper_collect()
        return
    if "--run-fixes" in argv:
        ids = argv[argv.index("--run-fixes") + 1].split(",")
        logp = argv[argv.index("--log") + 1]
        global HOME
        if "--home" in argv:
            HOME = argv[argv.index("--home") + 1]
        helper_run_fixes(ids, logp)
        return
    DEMO = "--demo" in argv
    if not DEMO and windows_elevate():
        return
    srv = Server(("127.0.0.1", 0), Handler)
    port = srv.server_address[1]
    threading.Thread(target=srv.serve_forever, daemon=True).start()
    url = "http://127.0.0.1:%d/?t=%s" % (port, TOKEN)
    STATE.add_log("info", "How Soon %s on %s" % (APP_VERSION, platform.node()))
    if DEMO:
        STATE.report = demo_report()
    else:
        STATE.add_log("head", "Quick scan")
        threading.Thread(target=do_scan, args=(STATE, False), daemon=True).start()
    if "--no-window" in argv:
        print(url)
        while True:
            time.sleep(3600)
    mode = open_window(url)
    if mode == "webview":
        return
    print("How Soon is running at %s" % url)
    print("Close the window to quit.")
    STATE.last_ping = time.time() + 40
    while True:
        time.sleep(2)
        if time.time() - STATE.last_ping > 25 and not STATE.running:
            break


if __name__ == "__main__":
    main()
