#!/usr/bin/env bash
#
# Functional test: prove the watch's pczt_summary display==signed verification
# (CR-1295) accepts REAL redacted shielded PCZTs built from a funded wallet.
#
# This is the end-to-end check the unit tests can't give us: it builds a real
# shielded transfer and a real shielding PCZT, runs them through the SDK's
# redactPCZTForSigner (the exact bytes the watch receives), then runs the
# watch's pczt_summary over them. If redaction strips the Orchard/Sapling
# output recipient/value, verify-summary FAILS (has_unverified / no match) —
# which is precisely the risk we wanted to settle.
#
# SAFETY: never proposes a broadcast. `propose` + `redact` + `verify-summary`
# only. No `prove`, no `broadcast`, no `send`. No funds move.
#
# Requires (NOT committed — supply via your environment):
#   ZCASH_SEED        24-word mnemonic of the funded wallet fixture
# Optional:
#   ZCASH_NETWORK     mainnet (default) | testnet
#   RECIPIENT_UA      transfer destination UA (default: self-send to own UA)
#   XFER_AMOUNT       transfer amount in zatoshi   (default 10000)
#   SHIELD_THRESHOLD  shielding threshold zatoshi  (default 10000)
#
# Usage:
#   ZCASH_SEED="word1 word2 ... word24" deps/zcash-signer/scripts/verify-shielded-roundtrip.sh

set -euo pipefail

if [[ -z "${ZCASH_SEED:-}" ]]; then
  echo "SKIP: ZCASH_SEED is not set (the funded wallet fixture). Export it and re-run." >&2
  exit 0
fi

NET="${ZCASH_NETWORK:-mainnet}"
XFER_AMOUNT="${XFER_AMOUNT:-10000}"
SHIELD_THRESHOLD="${SHIELD_THRESHOLD:-10000}"

cd "$(dirname "$0")/.."   # deps/zcash-signer

jqua() { python3 -c 'import sys,json;print(json.load(sys.stdin)["'"$1"'"])'; }

# The host (macOS) zcash-signer slice must include the pczt_summary FFI (CR-1295).
# The shipping iOS xcframework is rebuilt by `tools/build-deps ios`, but the host
# slice the CLI links (vendor/ZcashSigner.xcframework, macOS) can lag behind a
# Rust change, which fails the swift build with "cannot find 'zsig_pczt_summary'".
# Self-heal: rebuild the xcframework if the host header is stale.
MAC_HDR="$(find vendor/ZcashSigner.xcframework -path '*macos*' -name zcash_signer.h 2>/dev/null | head -1)"
if [[ -z "$MAC_HDR" ]] || ! grep -q "zsig_pczt_summary" "$MAC_HDR"; then
  echo "== Host zcash-signer slice is stale (missing zsig_pczt_summary) — rebuilding xcframework ==" >&2
  ./build-xcframework.sh >&2
fi

echo "== Building pczt-cli ==" >&2
swift build --product pczt-cli >&2
BIN="$(swift build --product pczt-cli --show-bin-path)/pczt-cli"

echo "== init + derive own UA ==" >&2
"$BIN" init >/dev/null
OWN_UA="$("$BIN" address | jqua unified)"
RECIPIENT_UA="${RECIPIENT_UA:-$OWN_UA}"
echo "   own UA:             $OWN_UA" >&2
echo "   transfer recipient: $RECIPIENT_UA" >&2

echo "== TRANSFER (shielded), redact for signer, verify watch summary ==" >&2
XFER_PCZT="$("$BIN" propose transfer "$RECIPIENT_UA" "$XFER_AMOUNT" --redact --network "$NET" | jqua pcztFile)"
"$BIN" verify-summary "$XFER_PCZT" --recipient "$RECIPIENT_UA" --network "$NET" --expect-amount "$XFER_AMOUNT"

echo "== SHIELD (t->z), redact for signer, verify watch summary ==" >&2
SHIELD_PCZT="$("$BIN" propose shield "$SHIELD_THRESHOLD" --redact --network "$NET" | jqua pcztFile)"
"$BIN" verify-summary "$SHIELD_PCZT" --recipient "$OWN_UA" --network "$NET"

echo "== ALL VERIFIED OK — redacted shielded PCZTs pass the watch display==signed check. No broadcast performed. ==" >&2
