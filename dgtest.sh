#!/bin/bash
set -x 1
set -e 1
#go run ./examples/cmd delegate -db test.db create test2 onboard,redirect SECP384R1 SECP384R1 SECP384R1
go run ./examples/cmd server -debug -owner-certs  -db test.db -onboardDelegate = -rvDelegate '='  -reuse-cred
RV=test2

#go run ./examples/cmd delegate -db test.db create ob onboard SECP384R1 SECP384R1
#go run ./examples/cmd delegate -db test.db create rv redirect SECP384R1 SECP384R1
#go run ./examples/cmd delegate -db test.db create invalid provision SECP384R1 SECP384R1

figlet DI
go run ./examples/cmd/ client -debug -di http://127.0.0.1:8080
GUID=`sqlite3 test.db 'select hex(guid) from owner_vouchers;'`
figlet TO0
go run ./examples/cmd server -debug -reuse-cred -db test.db -to0 http://127.0.0.1:8080 -rvDelegate $RV -to0-guid $GUID 
figlet RV
go run ./examples/cmd client  -rv-only -debug
figlet Final
go run ./examples/cmd client  -debug
