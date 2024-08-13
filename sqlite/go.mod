module github.com/fido-device-onboard/go-fdo/sqlite

go 1.23.0

replace github.com/fido-device-onboard/go-fdo => ../

require (
	github.com/fido-device-onboard/go-fdo v0.0.0-00010101000000-000000000000
	github.com/ncruces/go-sqlite3 v0.17.1
	golang.org/x/exp v0.0.0-20240325151524-a685a6edb6d8
)

require (
	github.com/ncruces/julianday v1.0.0 // indirect
	github.com/tetratelabs/wazero v1.7.3 // indirect
	golang.org/x/crypto v0.25.0 // indirect
	golang.org/x/sys v0.24.0 // indirect
	lukechampine.com/adiantum v1.1.1 // indirect
)
