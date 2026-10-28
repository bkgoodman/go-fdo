#!/bin/bash
# fdo.tpm-quote demo on swtpm: the Owner obtains a PCR quote in TO2 and
# verifies it comes from the TPM that holds the voucher's Device Key (DAK):
#   EK -> AK (MakeCredential/ActivateCredential) -> Certify(DAK by AK)
#   -> Quote(PCRs), all with an Owner nonce.
# The EK is trusted because
#   A. the manufacturer recorded it in the voucher at DI (quick-di
#      -tpm-record-ek: OVEExtraInfo PT_TPM_EK_CERT, after checking that the
#      EK is in the DAK's TPM); the Owner needs no TPM vendor CA, or
#   B. its certificate chains to a TPM vendor CA the Owner trusts
#      (swtpm_localca stands in for the vendor).
#
# Usage: BIN=<dir with fdo-server, fdo-client-tpm, quick-di-tpm> ./tpm-quote-demo.sh
# Needs swtpm, swtpm_setup, swtpm_localca, openssl.
set -u
BIN=$(realpath "${BIN:-./bin}")
WORK=${WORK:-/tmp/fdo-tpm-quote}
PORT=${PORT:-19998}
ADDR="127.0.0.1:$PORT"
URL="http://$ADDR"
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
export FDO_TPM_DEVICE="$WORK/swtpm.sock"

client() { "$BIN/fdo-client-tpm" client "$@"; }

start_server() { # [extra flags]
	[ -n "$SERVER_PID" ] && kill "$SERVER_PID" 2>/dev/null && wait "$SERVER_PID" 2>/dev/null
	"$BIN/fdo-server" server -http "$ADDR" -db "$WORK/fdo.db" -reuse-cred "$@" >>"$WORK/server.log" 2>&1 &
	SERVER_PID=$!
	for _ in $(seq 40); do
		(echo >"/dev/tcp/127.0.0.1/$PORT") 2>/dev/null && return 0
		kill -0 "$SERVER_PID" 2>/dev/null || { tail "$WORK/server.log"; return 1; }
		sleep 0.25
	done
	return 1
}

# quickdi <label> [quick-di flags...]: DI with quick-di, signed over to the
# Owner; imports the voucher and registers it (TO0). Prints the GUID.
quickdi() {
	local label=$1 vdir="$WORK/vouchers-$1" voucher guid
	shift
	rm -rf "$vdir" && mkdir -p "$vdir"
	"$BIN/quick-di-tpm" -quick -protocol-version 2.0 -rv "$ADDR:http" -no-dell-extra \
		-device-info "quote-demo-$label" -output-dir "$vdir" -signover-key "$WORK/owner.pem" "$@" \
		>"$WORK/quickdi-$label.log" 2>&1 || return 1
	grep -E '^EK:|PT_TPM_EK_CERT' "$WORK/quickdi-$label.log" | sed 's/^/  quick-di| /'
	voucher=$(ls -t "$vdir"/*.fdoov | head -1)
	guid=$(basename "$voucher" .fdoov)
	sed -i 's/FDO OWNERSHIP VOUCHER/OWNERSHIP VOUCHER/g' "$voucher"
	"$BIN/fdo-server" server -db "$WORK/fdo.db" -import-voucher "$voucher" >/dev/null 2>&1 || return 1
	"$BIN/fdo-server" server -http "$ADDR" -db "$WORK/fdo.db" -to0 "$URL" -to0-guid "$guid" >/dev/null 2>&1 || return 1
	echo "  voucher $guid imported and registered (TO0)"
}

# to2 <label> [env...]: run TO2, keep the Owner's fdo.tpm-quote lines
to2() {
	local label=$1 mark
	shift
	mark=$(wc -l <"$WORK/server.log")
	env "$@" "$BIN/fdo-client-tpm" client -fdo-version 200 -kex ECDH256 >"$WORK/client-$label.log" 2>&1
	local rc=$?
	tail -n +"$((mark + 1))" "$WORK/server.log" | grep -a '\[fdo.tpm-quote\]' >"$WORK/owner-$label.log"
	sed 's/^/  owner| /' "$WORK/owner-$label.log"
	grep -a '\[fdo.tpm-quote\]' "$WORK/client-$label.log" | sed 's/^/  device| /'
	return $rc
}

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

rm -rf "$WORK" && mkdir -p "$WORK/tpm" "$WORK/tpm2" "$WORK/tpm2-certs" "$WORK/ca" || exit 1
cd "$WORK" || exit 1

say "1. Manufacture the TPM (EK + EK certificate) and a second TPM from the same vendor"
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
swtpm_setup --tpm2 --tpmstate "$WORK/tpm2" --config "$WORK/swtpm_setup.conf" --create-ek-cert \
	--write-ek-cert-files "$WORK/tpm2-certs" --overwrite >>"$WORK/swtpm_setup.log" 2>&1
OTHER_EK=$(ls "$WORK"/tpm2-certs/ek-rsa2048*.crt 2>/dev/null | head -1)
grep -E 'RSA 2048 EK with handle' "$WORK/swtpm_setup.log" | head -1
cat "$WORK/ca/swtpm-localca-rootca-cert.pem" "$WORK/ca/issuercert.pem" >"$WORK/tpm-vendor-ca.pem"
openssl req -x509 -newkey ec -pkeyopt ec_paramgen_curve:P-256 -nodes -keyout /dev/null \
	-subj "/CN=untrusted-tpm-vendor" -days 1 -out "$WORK/wrong-ca.pem" 2>/dev/null
swtpm socket --tpm2 --tpmstate "dir=$WORK/tpm" --server "type=unixio,path=$FDO_TPM_DEVICE" \
	--ctrl "type=unixio,path=$WORK/swtpm.ctrl" --flags startup-clear >"$WORK/swtpm.log" 2>&1 &
SWTPM_PID=$!
sleep 1
"$BIN/fdo-server" server -db "$WORK/fdo.db" -initOnly >/dev/null 2>&1
"$BIN/fdo-server" server -db "$WORK/fdo.db" -print-owner-public SECP256R1 2>/dev/null |
	sed -n '/BEGIN PUBLIC/,/END PUBLIC/p' >"$WORK/owner.pem"
# The server is also the rendezvous server for TO0/TO1.
start_server -tpm-quote -tpm-quote-pcrs 0,7,16 || { bad "server start"; exit 1; }

say "A1. DI (factory): claim another TPM's EK -> the binding check refuses it"
if quickdi claim-other -tpm-record-ek -tpm-ek-cert-file "$OTHER_EK"; then
	bad "DI recorded another TPM's EK"
elif grep -q 'EK is not in the TPM holding the Device Key' "$WORK/quickdi-claim-other.log"; then
	ok "DI refused to record an EK that is not in the DAK's TPM"
	grep -m1 'EK is not in the TPM' "$WORK/quickdi-claim-other.log" | sed 's/^/  quick-di| /'
else
	bad "DI with another EK failed for another reason (see $WORK/quickdi-claim-other.log)"
fi

say "A2. DI (factory): check the EK<->DAK binding, record the EK in the voucher"
quickdi good -tpm-record-ek && ok "DI with the EK recorded in the voucher" || { bad "DI"; exit 1; }

say "A3. TO2: Owner has NO TPM vendor CA; the EK comes from the voucher"
client -tpm-pcr-extend "16:demo boot stage A"
to2 good && grep -aq 'EK anchored by the manufacturer' "$WORK/owner-good.log" && grep -aq VERIFIED "$WORK/owner-good.log" &&
	ok "quote verified with the voucher's EK (no TPM CA)" || bad "TO2 with the voucher EK"

say "A4. Change the measured state: the next verified quote shows the new PCR 16"
client -tpm-pcr-extend "16:unexpected stage B"
to2 good2 && grep -aq VERIFIED "$WORK/owner-good2.log" &&
	[ "$(grep -a 'PCR\[16\]' "$WORK/owner-good.log")" != "$(grep -a 'PCR\[16\]' "$WORK/owner-good2.log")" ] &&
	ok "TO2 after the PCR change: verified, PCR 16 differs" || bad "TO2 after PCR change"

say "A5. Negative: lying device"
negative tamper-nonce "is not the verifier's" FDO_TPM_QUOTE_TAMPER=nonce
negative tamper-dak "not the voucher's Device Key" FDO_TPM_QUOTE_TAMPER=dak
negative tamper-quote "quote: AK signature does not verify" FDO_TPM_QUOTE_TAMPER=quote
negative tamper-activate "wrong secret" FDO_TPM_QUOTE_TAMPER=activate
# With the EK anchored in the voucher, the EK certificate the device reports
# is not used: the Owner encrypts to the voucher's EK, which this TPM holds.
to2 device-reports-other-ek FDO_TPM_QUOTE_EK_CERT_FILE="$OTHER_EK" &&
	grep -aq 'device reports the same EK certificate: false' "$WORK/owner-device-reports-other-ek.log" &&
	grep -aq VERIFIED "$WORK/owner-device-reports-other-ek.log" &&
	ok "device-reported EK cert ignored when the voucher anchors the EK (mismatch logged)" || bad "device-reports-other-ek"

say "B. No EK in the voucher: EK certificate checked against a TPM vendor CA"
quickdi no-ek && ok "DI without an EK in the voucher" || bad "DI (no EK)"
negative no-anchor "no EK anchor"
start_server -tpm-quote-ca "$WORK/tpm-vendor-ca.pem" -tpm-quote-pcrs 0,7,16
to2 vendor-ca && grep -aq 'chains to the trusted TPM CA' "$WORK/owner-vendor-ca.log" && grep -aq VERIFIED "$WORK/owner-vendor-ca.log" &&
	ok "quote verified with the vendor CA" || bad "TO2 with the vendor CA"
negative other-tpm-ek "ActivateCredential" FDO_TPM_QUOTE_EK_CERT_FILE="$OTHER_EK"
start_server -tpm-quote-ca "$WORK/wrong-ca.pem" -tpm-quote-pcrs 0,7,16
negative untrusted-ek-ca "does not chain to the trusted TPM CA"

say "C. Voucher records the wrong EK (factory check skipped): the Owner catches it"
start_server -tpm-quote -tpm-quote-pcrs 0,7,16
QUICKDI_TPM_EK_SKIP_VERIFY=1 quickdi wrong-ek -tpm-record-ek -tpm-ek-cert-file "$OTHER_EK" &&
	ok "DI recorded another TPM's EK (check skipped, test only)" || bad "DI with the wrong EK"
negative voucher-wrong-ek "ActivateCredential"

say "Summary"
printf 'passed: %s\n' "${#PASSED[@]}"
printf 'failed: %s\n' "${#FAILED[@]}"
for f in "${FAILED[@]}"; do echo "  $f"; done
[ ${#FAILED[@]} -eq 0 ]
