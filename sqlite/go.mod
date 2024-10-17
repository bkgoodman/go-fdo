module github.com/fido-device-onboard/go-fdo/sqlite

go 1.23

replace github.com/fido-device-onboard/go-fdo => ../

require (
	github.com/fido-device-onboard/go-fdo v0.0.0-00010101000000-000000000000
	github.com/ncruces/go-sqlite3 v0.18.4
	golang.org/x/crypto v0.27.0
)

require (
	github.com/ncruces/julianday v1.0.0 // indirect
	github.com/tetratelabs/wazero v1.8.0 // indirect
	golang.org/x/sys v0.25.0 // indirect
)
