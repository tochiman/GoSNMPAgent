module github.com/tochiman/GoSNMPAgent

go 1.22.5

require (
	github.com/comail/colog v0.0.0-20160416085026-fba8e7b1f46c
	github.com/gosnmp/gosnmp v1.38.0
	github.com/quic-go/quic-go v0.47.0
	github.com/spf13/cobra v1.8.1
)

require (
	github.com/go-task/slim-sprig/v3 v3.0.0 // indirect
	github.com/google/pprof v0.0.0-20240910150728-a0b0bb1d4134 // indirect
	github.com/inconshreveable/mousetrap v1.1.0 // indirect
	github.com/onsi/ginkgo/v2 v2.20.2 // indirect
	github.com/spf13/pflag v1.0.5 // indirect
	go.uber.org/mock v0.4.0 // indirect
	golang.org/x/crypto v0.27.0 // indirect
	golang.org/x/exp v0.0.0-20240909161429-701f63a606c0 // indirect
	golang.org/x/mod v0.21.0 // indirect
	golang.org/x/net v0.29.0 // indirect
	golang.org/x/sync v0.8.0 // indirect
	golang.org/x/sys v0.25.0 // indirect
	golang.org/x/tools v0.25.0 // indirect
)

replace github.com/gosnmp/gosnmp => ../gosnmp
