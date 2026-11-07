// Command gonet is the GoNet topology discovery CLI. It performs read-only
// SNMP collection of LLDP and exports JSON snapshots; M1 implements single
// device collection only.
package main

import (
	"os"

	"gonet/internal/cli"
)

func main() {
	os.Exit(cli.Run(os.Args[1:], os.Stdout, os.Stderr))
}
