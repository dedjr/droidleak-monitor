#!/data/data/com.termux/files/usr/bin/sh
set -eu

if ! command -v pkg >/dev/null 2>&1; then
    echo "This installer is for Android Termux. Install Termux, then run it again." >&2
    exit 1
fi

pkg update -y
pkg install python git -y

python - <<'PY'
import sys

if sys.version_info < (3, 11):
    raise SystemExit(
        "DroidLeak Monitor requires Python 3.11 or newer; "
        f"found {sys.version.split()[0]}."
    )
PY

python -m pip install -r requirements.txt
echo "DroidLeak Monitor dependencies are installed."
echo "Try: python droidleak.py --help"
