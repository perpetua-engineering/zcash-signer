#!/usr/bin/env bash
#
# Functional test: prove the watch's ZEC PCZT display==signed verification
# accepts REAL redacted PCZTs built from a funded wallet, then complete the
# funded sign -> prove -> txid roundtrip.
#
# This is the end-to-end check the unit tests can't give us: it builds real
# shielded transfer and shielding PCZTs from a funded wallet, redacts them with
# the SDK's redactPCZTForSigner (the exact bytes the watch verifies + signs),
# runs the CR-1337 watch summary/ownership checks, signs the redacted PCZT,
# proves the original full PCZT, then broadcasts via the SDK's
# createTransactionFromPCZT(proofs, sigs) path.
#
# SAFETY: this broadcasts low-value mainnet ZEC transactions from the funded
# fixture. Defaults are deliberately small. Use only with controlled fixture
# wallets.
#
# Requires (NOT committed — supply via your environment):
#   ZCASH_SEED        24-word mnemonic of the funded wallet fixture
# Optional:
#   ZCASH_NETWORK     mainnet (default) | testnet
#   ZCASH_BIRTHDAY    wallet birthday height (default 2657762)
#   PCZT_CLI_BIN      prebuilt pczt-cli path; skips swift build when set
#   RECIPIENT_UA      transfer destination UA (default: self-send to own UA)
#   ADVERSARY_UA      foreign UA used for refusal-only ZEC-4 negative
#   XFER_AMOUNT       transfer amount in zatoshi   (default 10000)
#   SHIELD_THRESHOLD  shielding threshold zatoshi  (default 10000)
#   FEE_ZATOSHI       legacy alias for TRANSFER_FEE_ZATOSHI
#   TRANSFER_FEE_ZATOSHI approved transfer fee zatoshi (default 10000)
#   SHIELD_FEE_ZATOSHI   approved shielding fee zatoshi (default 15000)
#   ROUNDTRIP_MODE    all | transfer | shield (default all)
#   SYNC_TIMEOUT      sync timeout in seconds       (default 3600)
#
# Usage:
#   ZCASH_SEED="word1 word2 ... word24" deps/zcash-signer/scripts/verify-shielded-roundtrip.sh

set -euo pipefail

if [[ -z "${ZCASH_SEED:-}" ]]; then
  echo "SKIP: ZCASH_SEED is not set (the funded wallet fixture). Export it and re-run." >&2
  exit 0
fi

NET="${ZCASH_NETWORK:-mainnet}"
BIRTHDAY="${ZCASH_BIRTHDAY:-2657762}"
XFER_AMOUNT="${XFER_AMOUNT:-10000}"
SHIELD_THRESHOLD="${SHIELD_THRESHOLD:-10000}"
TRANSFER_FEE_ZATOSHI="${TRANSFER_FEE_ZATOSHI:-${FEE_ZATOSHI:-10000}}"
SHIELD_FEE_ZATOSHI="${SHIELD_FEE_ZATOSHI:-15000}"
ROUNDTRIP_MODE="${ROUNDTRIP_MODE:-all}"
SYNC_TIMEOUT="${SYNC_TIMEOUT:-3600}"

case "$ROUNDTRIP_MODE" in
  all|transfer|shield) ;;
  *)
    echo "FAIL: ROUNDTRIP_MODE must be all, transfer, or shield (got '$ROUNDTRIP_MODE')" >&2
    exit 1
    ;;
esac

cd "$(dirname "$0")/.."   # deps/zcash-signer

jqua() { python3 -c 'import sys,json;print(json.load(sys.stdin)["'"$1"'"])'; }
jqint() { python3 -c 'import sys,json;print(int(json.load(sys.stdin)["'"$1"'"]))'; }
jqpczt() { python3 -c 'import sys,json; data=json.load(sys.stdin); print(data.get("pczt_file") or data.get("pcztFile"))'; }

if [[ "$NET" == "testnet" ]]; then
  sign_pczt() { "$BIN" sign "$1" --testnet; }
else
  sign_pczt() { "$BIN" sign "$1"; }
fi

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

if [[ -n "${PCZT_CLI_BIN:-}" ]]; then
  BIN="$PCZT_CLI_BIN"
else
  echo "== Building pczt-cli ==" >&2
  swift build --product pczt-cli >&2
  BIN="$(swift build --product pczt-cli --show-bin-path)/pczt-cli"
fi

echo "== init + sync funded fixture ==" >&2
"$BIN" init --network "$NET" --birthday "$BIRTHDAY" >/dev/null
SYNC_JSON="$("$BIN" sync --timeout "$SYNC_TIMEOUT")"
TOTAL_BALANCE="$(printf '%s' "$SYNC_JSON" | jqint totalBalance)"
SPENDABLE_BALANCE="$(printf '%s' "$SYNC_JSON" | jqint spendableBalance)"
TRANSPARENT_BALANCE="$(printf '%s' "$SYNC_JSON" | jqint transparentBalance)"
LATEST_HEIGHT="$(printf '%s' "$SYNC_JSON" | jqint latestBlockHeight)"
echo "   latest height:       $LATEST_HEIGHT" >&2
echo "   shielded total:      $TOTAL_BALANCE zatoshi" >&2
echo "   shielded spendable:  $SPENDABLE_BALANCE zatoshi" >&2
echo "   transparent:         $TRANSPARENT_BALANCE zatoshi" >&2

if [[ "$ROUNDTRIP_MODE" != "shield" ]] && (( SPENDABLE_BALANCE < XFER_AMOUNT + TRANSFER_FEE_ZATOSHI )); then
  echo "FAIL: shielded spendable balance ($SPENDABLE_BALANCE) is not enough for transfer amount ($XFER_AMOUNT) plus fee ($TRANSFER_FEE_ZATOSHI)" >&2
  exit 1
fi
if [[ "$ROUNDTRIP_MODE" != "transfer" ]] && (( TRANSPARENT_BALANCE < SHIELD_THRESHOLD )); then
  echo "FAIL: transparent balance ($TRANSPARENT_BALANCE) is below shielding threshold ($SHIELD_THRESHOLD)" >&2
  exit 1
fi

echo "== derive own UA ==" >&2
OWN_UA="$("$BIN" address | jqua unified)"
RECIPIENT_UA="${RECIPIENT_UA:-$OWN_UA}"
echo "   own UA:             $OWN_UA" >&2
echo "   transfer recipient: $RECIPIENT_UA" >&2

XFER_TXID="${TRANSFER_TXID:-}"
SHIELD_TXID=""

# verify-summary auto-runs the CR-1337 viewing-key ownership totality + memo
# check whenever ZCASH_SEED is set (which it is here), so each verify below
# exercises BOTH the amount/fee summary AND the change/own-receiver totality on
# the exact redacted bytes the watch signs. A legitimate redacted PCZT must
# PASS: its change output is wallet-owned, so all_outputs_accounted == true (the
# P0 "can't send ZEC" regression guard).
if [[ "$ROUNDTRIP_MODE" != "shield" ]]; then
  echo "== TRANSFER (shielded): full -> redacted signer bytes -> verify totality + fee ==" >&2
  XFER_FULL_PCZT="$("$BIN" propose transfer "$RECIPIENT_UA" "$XFER_AMOUNT" --network "$NET" | jqpczt)"
  XFER_PCZT="$("$BIN" redact "$XFER_FULL_PCZT" | jqpczt)"
  "$BIN" verify-summary "$XFER_PCZT" --recipient "$RECIPIENT_UA" --network "$NET" \
    --expect-amount "$XFER_AMOUNT" --expect-fee "$TRANSFER_FEE_ZATOSHI"

  # ── Adversarial negatives: the verifier MUST refuse these (exit non-zero). ────
  # A bash helper that inverts the exit code: succeeds only if verify-summary fails.
  expect_refusal() {
    local label="$1"; shift
    if "$@" >/dev/null 2>&1; then
      echo "!! SECURITY REGRESSION: verifier ACCEPTED $label (expected refusal)" >&2
      exit 1
    fi
    echo "   correctly REFUSED: $label" >&2
  }

  echo "== Adversarial: display!=signed memo on the transfer note must be REFUSED ==" >&2
  expect_refusal "altered memo (display says 'attacker', note has none)" \
    "$BIN" verify-summary "$XFER_PCZT" --recipient "$RECIPIENT_UA" --network "$NET" \
      --expect-amount "$XFER_AMOUNT" --expect-fee "$TRANSFER_FEE_ZATOSHI" --memo "attacker"

  echo "== Adversarial: wrong approved recipient must be REFUSED ==" >&2
  if [[ -n "${ADVERSARY_UA:-}" ]]; then
    expect_refusal "approved recipient differs from signed output" \
      "$BIN" verify-summary "$XFER_PCZT" --recipient "$ADVERSARY_UA" --network "$NET" \
        --expect-amount "$XFER_AMOUNT" --expect-fee "$TRANSFER_FEE_ZATOSHI"
  else
    echo "   (skipped: set ADVERSARY_UA to a controlled foreign UA to exercise)" >&2
  fi

  echo "== Adversarial: a transfer falsely framed as shielding (ZEC-4) must be REFUSED for a foreign recipient ==" >&2
  if [[ -n "${ADVERSARY_UA:-}" ]]; then
    ADVERSARY_PCZT="$("$BIN" propose transfer "$ADVERSARY_UA" "$XFER_AMOUNT" --redact --network "$NET" | jqpczt)"
    expect_refusal "external recipient framed as shielding self-send" \
      "$BIN" verify-summary "$ADVERSARY_PCZT" --recipient "$ADVERSARY_UA" --network "$NET" \
        --expect-amount "$XFER_AMOUNT" --expect-fee "$TRANSFER_FEE_ZATOSHI" --shielding
  else
    echo "   (skipped: set ADVERSARY_UA to a controlled foreign UA to exercise)" >&2
  fi

  echo "== TRANSFER (shielded): sign -> prove -> txid ==" >&2
  XFER_SIGNED_PCZT="$(sign_pczt "$XFER_PCZT" | jqpczt)"
  XFER_PROVEN_PCZT="$("$BIN" prove "$XFER_FULL_PCZT" | jqpczt)"
  XFER_TXID="$("$BIN" broadcast "$XFER_PROVEN_PCZT" "$XFER_SIGNED_PCZT" | jqua txid)"
  echo "   transfer txid:      $XFER_TXID" >&2
else
  echo "== TRANSFER: skipped by ROUNDTRIP_MODE=shield ==" >&2
fi

if [[ "$ROUNDTRIP_MODE" != "transfer" ]]; then
  SHIELD_EXPECT_AMOUNT="${SHIELD_AMOUNT:-$(( TRANSPARENT_BALANCE - SHIELD_FEE_ZATOSHI ))}"
  if (( SHIELD_EXPECT_AMOUNT <= 0 )); then
    echo "FAIL: shield amount ($SHIELD_EXPECT_AMOUNT) must be positive" >&2
    exit 1
  fi

  echo "== SHIELD (t->z): full -> redacted signer bytes -> verify totality + ZEC-4 -> sign -> prove -> txid ==" >&2
  SHIELD_FULL_PCZT="$("$BIN" propose shield "$SHIELD_THRESHOLD" --network "$NET" | jqpczt)"
  SHIELD_PCZT="$("$BIN" redact "$SHIELD_FULL_PCZT" | jqpczt)"
  # --shielding: the destination must be wallet-owned (ZEC-4). For a real shield
  # the output is our own Orchard receiver, so this must PASS.
  "$BIN" verify-summary "$SHIELD_PCZT" --recipient "$OWN_UA" --network "$NET" \
    --expect-amount "$SHIELD_EXPECT_AMOUNT" --expect-fee "$SHIELD_FEE_ZATOSHI" --shielding

  SHIELD_SIGNED_PCZT="$(sign_pczt "$SHIELD_PCZT" | jqpczt)"
  SHIELD_PROVEN_PCZT="$("$BIN" prove "$SHIELD_FULL_PCZT" | jqpczt)"
  SHIELD_TXID="$("$BIN" broadcast "$SHIELD_PROVEN_PCZT" "$SHIELD_SIGNED_PCZT" | jqua txid)"
  echo "   shield txid:        $SHIELD_TXID" >&2
else
  echo "== SHIELD: skipped by ROUNDTRIP_MODE=transfer ==" >&2
fi

cat <<JSON
{
  "transfer_txid": "$XFER_TXID",
  "shield_txid": "$SHIELD_TXID"
}
JSON

echo "== ALL VERIFIED OK — funded redacted PCZTs passed display==signed + ownership totality, adversarial mutations were refused, and sign->prove->txid completed. ==" >&2
