#!/usr/bin/env bash
# Regenerate the extension's RSA keypair and update manifest.json + every
# place that hardcodes the derived extension ID.
#
# Run this once if you fork this project; the committed key/ID work for the
# PW POC but anyone shipping their own build should rotate to their own.
#
# Files updated (in-tree):
#   - vdi/extension/manifest.json  ("key" field)
#   - vdi/install.sh               (EXT_ID default)
#   - vdi/bootstrap.sh             (EXT_ID default)
# Private key is written to vdi/extension/.private-key.pem and is .gitignored.

set -euo pipefail

HERE="$(cd "$(dirname "$0")" && pwd)"
ROOT="$(cd "$HERE/../.." && pwd)"

KEY_PEM="$HERE/.private-key.pem"
KEY_DER_TMP="$(mktemp)"
trap 'rm -f "$KEY_DER_TMP"' EXIT

openssl genrsa -out "$KEY_PEM" 2048 2>/dev/null
openssl rsa -in "$KEY_PEM" -pubout -outform DER -out "$KEY_DER_TMP" 2>/dev/null
PUB_B64=$(base64 < "$KEY_DER_TMP" | tr -d '\n')
EXT_ID=$(python3 -c "
import hashlib, sys
with open('$KEY_DER_TMP','rb') as f: der = f.read()
h = hashlib.sha256(der).digest()
print(''.join(chr(ord('a') + ((h[i] >> 4) & 0xf)) + chr(ord('a') + (h[i] & 0xf)) for i in range(16)))
")

echo "generated new keypair:"
echo "  private key: $KEY_PEM"
echo "  extension id: $EXT_ID"
echo

# Update manifest.json
python3 - "$HERE/manifest.json" "$PUB_B64" <<'PY'
import json, sys
path, pub = sys.argv[1], sys.argv[2]
m = json.load(open(path))
m["key"] = pub
json.dump(m, open(path, "w"), indent=2)
open(path, "a").write("\n")
PY
echo "updated $HERE/manifest.json"

# Update install.sh and bootstrap.sh EXT_ID default
for f in "$ROOT/vdi/install.sh" "$ROOT/vdi/bootstrap.sh"; do
  [[ -f "$f" ]] || continue
  python3 - "$f" "$EXT_ID" <<'PY'
import re, sys
path, ext_id = sys.argv[1], sys.argv[2]
src = open(path).read()
new = re.sub(r'^(EXT_ID_DEFAULT=)\S+$', r'\g<1>"' + ext_id + r'"', src, flags=re.M)
if new != src:
    open(path, "w").write(new)
    print(f"updated EXT_ID_DEFAULT in {path}")
PY
done

echo
echo "Done. Don't forget to git add manifest.json install.sh bootstrap.sh"
echo "(.private-key.pem is gitignored.)"
