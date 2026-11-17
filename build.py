#!/usr/bin/env python3
"""Builds dist/HowSoon: one howsoon.py with the UI embedded, launchers, icon and README, plus HowSoon.zip."""
import os
import shutil
import stat
import subprocess

here = os.path.dirname(os.path.abspath(__file__))
dist = os.path.join(here, "dist", "HowSoon")
shutil.rmtree(os.path.join(here, "dist"), ignore_errors=True)
os.makedirs(os.path.join(dist, "assets"))

src = open(os.path.join(here, "howsoon.py"), encoding="utf-8").read()
ui = open(os.path.join(here, "ui.html"), encoding="utf-8").read()
assert '"__UI_HTML__"' in src
src = src.replace('"__UI_HTML__"', repr(ui), 1)
compile(src, "howsoon.py", "exec")
open(os.path.join(dist, "howsoon.py"), "w", encoding="utf-8", newline="\n").write(src)


def write(name, text, exe=False, crlf=False):
    p = os.path.join(dist, name)
    if crlf:
        text = text.replace("\r\n", "\n").replace("\n", "\r\n")
    open(p, "w", encoding="utf-8", newline="").write(text)
    if exe:
        os.chmod(p, os.stat(p).st_mode | stat.S_IXUSR | stat.S_IXGRP | stat.S_IXOTH)


write("run-howsoon.sh", """#!/bin/sh
# How Soon launcher for Linux. Needs python3 (already on most distros).
cd "$(dirname "$0")" && exec python3 howsoon.py "$@"
""", exe=True)

write("Run How Soon.command", """#!/bin/sh
# How Soon launcher for macOS. Double-click it in Finder.
cd "$(dirname "$0")" && python3 howsoon.py &
sleep 1
osascript -e 'tell application "Terminal" to close (every window whose name contains "Run How Soon")' >/dev/null 2>&1 &
exit 0
""", exe=True)

write("Run-HowSoon.cmd", """@echo off
REM How Soon launcher for Windows. Needs Python 3 from python.org or the Microsoft Store.
REM The app asks for administrator rights by itself.
where pyw >nul 2>nul && (start "" pyw -3 "%~dp0howsoon.py" & exit /b)
where pythonw >nul 2>nul && (start "" pythonw "%~dp0howsoon.py" & exit /b)
echo Python 3 was not found. Install it from https://www.python.org/downloads/ and tick "Add python.exe to PATH".
pause
""", crlf=True)

write("install-linux.sh", """#!/bin/sh
# Adds How Soon to your app menu (no root needed). Run it again after moving the folder.
set -e
DIR="$(cd "$(dirname "$0")" && pwd)"
APPS="${XDG_DATA_HOME:-$HOME/.local/share}/applications"
ICONS="${XDG_DATA_HOME:-$HOME/.local/share}/icons/hicolor/256x256/apps"
mkdir -p "$APPS" "$ICONS"
cp "$DIR/assets/howsoon.png" "$ICONS/howsoon.png"
cat > "$APPS/howsoon.desktop" <<EOF
[Desktop Entry]
Type=Application
Name=How Soon
Comment=Hardware health and security checker
Exec=python3 "$DIR/howsoon.py"
Icon=howsoon
Terminal=false
Categories=System;Monitor;Utility;
Keywords=smart;disk;drive;battery;security;health;
EOF
chmod +x "$APPS/howsoon.desktop"
command -v update-desktop-database >/dev/null && update-desktop-database "$APPS" >/dev/null 2>&1 || true
echo "How Soon is now in your app menu."
""", exe=True)

shutil.copy(os.path.join(here, "assets", "howsoon-256.png"), os.path.join(dist, "assets", "howsoon.png"))
shutil.copy(os.path.join(here, "README.md"), os.path.join(dist, "README.md"))

srcdir = os.path.join(dist, "source")
os.makedirs(srcdir)
for f in ("howsoon.py", "ui.html", "build.py", "requirements-build.txt", "README.md", "LICENSE"):
    shutil.copy(os.path.join(here, f), srcdir)
shutil.copytree(os.path.join(here, "assets"), os.path.join(srcdir, "assets"))
shutil.copytree(os.path.join(here, ".github"), os.path.join(srcdir, ".github"))

os.chdir(os.path.join(here, "dist"))
if shutil.which("zip"):
    subprocess.run(["zip", "-qr9", "HowSoon.zip", "HowSoon"], check=True)
else:
    shutil.make_archive("HowSoon", "zip", ".", "HowSoon")
print("Built", os.path.join(here, "dist", "HowSoon.zip"))
