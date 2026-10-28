#!/bin/bash
# fdo.tpm-quote demo on swtpm: DI with the Device Key (DAK) in the TPM, then
# TO2 in which the Owner obtains a PCR quote and verifies the chain
#   EK certificate -> trusted CA -> EK -> AK (ActivateCredential)
#   -> Certify(voucher's Device Key) -> Quote(PCRs), all with an Owner nonce.
# swtpm_localca issues the EK certificate; its CA stands in for the TPM vendor.
#
# Usage: BIN=<dir with fdo-server, fdo-client-tpm> ./tpm-quote-demo.sh
# Needs swtpm, swtpm_setup, swtpm_localca, openssl.
set -u
BIN=$(realpath "${BIN:-./bin}")
WORK=${WORK:-/tmp/fdo-tpm-quote}
PORT=${PORT:-19998}
URL="http://127.0.0.1:$PORT"
SWTPM_PID="" SERVER_PID=""
PASSED=() FAILED=()

say() { printf '\n=== %s ===\n' "$*"; }
ok() { echo "OK:   $*"; PASSED+=("$*"); }
bad() { echo "FAIL: $*"; FAILED+=("$*"); return 1; }
cleanup() {
	[ -n "$SERVER_PID" ] && kill "$SERVER_PID" 2>/dev/null && wait "$SERVER_PID" 2>/dev/null
	[ -n "$SWTPM_PID" ] && kill "$SWTPM_PID" 2>/dev/null && wait "$SWTPM_PID" 2>/dev/null
	SERVER_PID="" SWTPM_PID=""
}
trap cleanup EXIT

client() { FDO_TPM_DEVICE="$WORK/swtpm.sock" "$BIN/fdo-client-tpm" client "$@"; }

start_server() { # [extra flags]
	[ -n "$SERVER_PID" ] && kill "$SERVER_PID" 2>/dev/null && wait "$SERVER_PID" 2>/dev/null
	"$BIN/fdo-server" server -http "127.0.0.1:$PORT" -db "$WORK/fdo.db" -rv-bypass -reuse-cred "$@" >>"$WORK/server.log" 2>&1 &
	SERVER_PID=$!
	for _ in $(seq 40); do
		(echo >"/dev/tcp/127.0.0.1/$PORT") 2>/dev/null && return 0
		kill -0 "$SERVER_PID" 2>/dev/null || { tail "$WORK/server.log"; return 1; }
		sleep 0.25
	done
	return 1
}

# to2 <label> [env...]: run TO2, print the Owner's fdo.tpm-quote lines for it
to2() {
	local label=$1 mark
	shift
	mark=$(wc -l <"$WORK/server.log")
	env "$@" FDO_TPM_DEVICE="$WORK/swtpm.sock" "$BIN/fdo-client-tpm" client -fdo-version 200 -kex ECDH256 \
		>"$WORK/client-$label.log" 2>&1
	local rc=$?
	tail -n +"$((mark + 1))" "$WORK/server.log" | grep -a '\[fdo.tpm-quote\]' >"$WORK/owner-$label.log"
	sed 's/^/  owner| /' "$WORK/owner-$label.log"
	grep -a '\[fdo.tpm-quote\]' "$WORK/client-$label.log" | sed 's/^/  device| /'
	return $rc
}

rm -rf "$WORK" && mkdir -p "$WORK/tpm" "$WORK/ca" || exit 1
cd "$WORK" || exit 1

say "1. Manufacture the TPM: EK + EK certificate from a local CA (the 'TPM vendor')"
cat >"$WORK/localca.conf" <<EOF
statedir = $WORK/ca
signingkey = $WORK/ca/signkey.pem
issuercert = $WORK/ca/issuercert.pem
certserial = $WORK/ca/certserial
EOF
cat >"$WORK/swtpm_setup.conf" <<EOF
create_certs_tool= /usr/bin/swtpm_localca
create_certs_tool_config = $WORK/localca.conf
create_certs_tool_options = /etc/swtpm-localca.options
active_pcr_banks = sha256
EOF
swtpm_setup --tpm2 --tpmstate "$WORK/tpm" --config "$WORK/swtpm_setup.conf" \
	--create-ek-cert --lock-nvram --overwrite >"$WORK/swtpm_setup.log" 2>&1 || { cat "$WORK/swtpm_setup.log"; exit 1; }
grep -E 'RSA 2048 EK with handle|RSA 2048 EK certificate' "$WORK/swtpm_setup.log"
# A second, genuine TPM from the same vendor CA: its EK certificate is valid,
# but its EK is not in the device's TPM.
mkdir -p "$WORK/tpm2" "$WORK/tpm2-certs"
swtpm_setup --tpm2 --tpmstate "$WORK/tpm2" --config "$WORK/swtpm_setup.conf" --create-ek-cert \
	--write-ek-cert-files "$WORK/tpm2-certs" --overwrite >>"$WORK/swtpm_setup.log" 2>&1
OTHER_EK=$(ls "$WORK"/tpm2-certs/ek-rsa2048*.crt 2>/dev/null | head -1)
cat "$WORK/ca/swtpm-localca-rootca-cert.pem" "$WORK/ca/issuercert.pem" >"$WORK/tpm-vendor-ca.pem"
openssl req -x509 -newkey ec -pkeyopt ec_paramgen_curve:P-256 -nodes -keyout /dev/null \
	-subj "/CN=untrusted-tpm-vendor" -days 1 -out "$WORK/wrong-ca.pem" 2>/dev/null
swtpm socket --tpm2 --tpmstate "dir=$WORK/tpm" --server "type=unixio,path=$WORK/swtpm.sock" \
	--ctrl "type=unixio,path=$WORK/swtpm.ctrl" --flags startup-clear >"$WORK/swtpm.log" 2>&1 &
SWTPM_PID=$!
sleep 1

say "2. DI: Device Key (DAK) + HMAC key in the TPM"
"$BIN/fdo-server" server -db "$WORK/fdo.db" -initOnly >/dev/null 2>&1
start_server -tpm-quote-ca "$WORK/tpm-vendor-ca.pem" -tpm-quote-pcrs 0,7,16 || { bad "server start"; exit 1; }
client -di "$URL" -di-key ec256 -fdo-version 200 >"$WORK/di.log" 2>&1 && ok "DI" || { tail "$WORK/di.log"; bad "DI"; exit 1; }

say "3. Measure something (PCR 16 stands in for a boot measurement)"
client -tpm-pcr-extend "16:demo boot stage A"

say "4. TO2 with fdo.tpm-quote"
to2 good && grep -aq 'VERIFIED' "$WORK/owner-good.log" && ok "Owner verified the quote chain" || bad "positive TO2"

say "5. Change the measured state and onboard again: PCR 16 differs in the verified quote"
client -tpm-pcr-extend "16:unexpected stage B"
to2 good2 && grep -aq 'VERIFIED' "$WORK/owner-good2.log" &&
	[ "$(grep -a 'PCR\[16\]' "$WORK/owner-good.log")" != "$(grep -a 'PCR\[16\]' "$WORK/owner-good2.log")" ] &&
	ok "TO2 after the PCR change: verified, PCR 16 differs" || bad "TO2 after PCR change"

say "6. Negative: lying device / untrusted TPM"
# negative <label> <expected Owner FAIL text> [env...]: TO2 must fail, at that check
negative() {
	local label=$1 want=$2
	shift 2
	if to2 "$label" "$@"; then
		bad "$label was accepted"
	elif grep -aq "FAIL .*$want" "$WORK/owner-$label.log"; then
		ok "$label rejected: $want"
	else
		bad "$label failed, but not with '$want' (see $WORK/client-$label.log)"
	fi
}
negative tamper-nonce "is not the Owner's" FDO_TPM_QUOTE_TAMPER=nonce
negative tamper-dak "not the voucher's Device Key" FDO_TPM_QUOTE_TAMPER=dak
negative tamper-quote "quote: AK signature does not verify" FDO_TPM_QUOTE_TAMPER=quote
negative tamper-activate "wrong secret" FDO_TPM_QUOTE_TAMPER=activate
if [ -n "$OTHER_EK" ]; then
	negative other-tpm-ek "ActivateCredential" FDO_TPM_QUOTE_EK_CERT_FILE="$OTHER_EK"
else
	bad "no EK certificate written for the second TPM (see $WORK/swtpm_setup.log)"
fi
start_server -tpm-quote-ca "$WORK/wrong-ca.pem" -tpm-quote-pcrs 0,7,16
negative untrusted-ek-ca "does not chain to the trusted TPM CA"

say "Summary"
printf 'passed: %s\n' "${#PASSED[@]}"
printf 'failed: %s\n' "${#FAILED[@]}"
for f in "${FAILED[@]}"; do echo "  $f"; done
[ ${#FAILED[@]} -eq 0 ]
