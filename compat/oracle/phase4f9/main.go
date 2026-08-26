package main

import (
	"context"
	"fmt"
	"os"
	"path/filepath"

	"github.com/metacubex/mihomo/component/geodata"
	C "github.com/metacubex/mihomo/config"
	P "github.com/metacubex/mihomo/constant"
	D "github.com/metacubex/mihomo/dns"
	_ "github.com/metacubex/mihomo/hub/executor"
)

func main() {
	if len(os.Args) != 3 {
		fmt.Fprintln(os.Stderr, "usage: phase4f9 <config> <host>")
		os.Exit(2)
	}
	configPath, err := filepath.Abs(os.Args[1])
	if err != nil {
		fail(err)
	}
	P.SetHomeDir(filepath.Dir(configPath))
	source, err := os.ReadFile(configPath)
	if err != nil {
		fail(err)
	}
	parsed, err := C.Parse(source)
	if err != nil {
		fail(err)
	}
	geodata.SetGeodataMode(parsed.General.GeodataMode)
	config := parsed.DNS
	resolver := D.NewResolver(D.Config{
		Main:                 config.NameServer,
		Default:              config.DefaultNameserver,
		Policy:               config.NameServerPolicy,
		Fallback:             config.Fallback,
		FallbackIPFilter:     config.FallbackIPFilter,
		FallbackDomainFilter: config.FallbackDomainFilter,
		FallbackLazyQuery:    config.FallbackLazyQuery,
	}).Resolver
	addresses, err := resolver.LookupIPv4(context.Background(), os.Args[2])
	if err != nil || len(addresses) == 0 {
		if err == nil {
			err = fmt.Errorf("resolver returned no address")
		}
		fail(err)
	}
	fmt.Println(addresses[0])
}

func fail(err error) {
	fmt.Fprintln(os.Stderr, err)
	os.Exit(1)
}
