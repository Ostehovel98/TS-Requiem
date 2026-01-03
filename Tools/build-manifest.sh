#!/usr/bin/env bash
set -euo pipefail

REPO_ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
REQ_DIR="$REPO_ROOT/Requiem"

VALUES="$REQ_DIR/manifest.values.json"
OUT_JSON="$REQ_DIR/manifest.json"
OUT_SIG="$REQ_DIR/manifest.sig"

# Adjust this path if needed
KEY_DIR="/c/Users/andre/requiem-signing"
PRIV="$KEY_DIR/requiem_private.pem"

if [[ ! -f "$VALUES" ]]; then
  echo "Missing: $VALUES" >&2
  exit 1
fi
if [[ ! -f "$PRIV" ]]; then
  echo "Missing private key: $PRIV" >&2
  echo "Fix KEY_DIR or filename in tools/build-manifest.sh" >&2
  exit 1
fi

# Requires python (Windows usually has python or py launcher).
# If you don't have python, tell me and I'll give a pure-jq alternative.
python - <<'PY' "$VALUES" "$OUT_JSON"
import json, sys, datetime
values_path, out_path = sys.argv[1], sys.argv[2]
with open(values_path, "r", encoding="utf-8") as f:
    v = json.load(f)
m = {
  "product": v["product"],
  "minVersion": v["minVersion"],
  "currentVersion": v["currentVersion"],
  "releaseKeyId": v["releaseKeyId"],
  "message": v["message"],
  "publishedUtc": datetime.datetime.utcnow().replace(microsecond=0).isoformat() + "Z"
}
# Canonical JSON: minified, stable order, LF newline
s = json.dumps(m, separators=(",", ":"), ensure_ascii=False) + "\n"
with open(out_path, "w", encoding="utf-8", newline="\n") as f:
    f.write(s)
PY

# Sign exact bytes
openssl dgst -sha256 -sign "$PRIV" -out "$OUT_SIG.der" "$OUT_JSON"

# Base64 one-liner signature (no spaces/newlines)
openssl base64 -A -in "$OUT_SIG.der" > "$OUT_SIG"
echo "" >> "$OUT_SIG"  # end with newline for cleanliness

rm -f "$OUT_SIG.der"

echo "✅ Built manifest.json + manifest.sig"
echo "   $OUT_JSON"
echo "   $OUT_SIG"
