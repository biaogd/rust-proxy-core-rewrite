package main

import (
	"context"
	"encoding/hex"
	"fmt"
	"os"
	"path/filepath"
	"strings"

	C "github.com/metacubex/mihomo/config"
	P "github.com/metacubex/mihomo/constant"
	D "github.com/metacubex/mihomo/dns"
	_ "github.com/metacubex/mihomo/hub/executor"
)

func main() {
	if len(os.Args) != 4 {
		fmt.Fprintln(os.Stderr, "usage: phase4f10 <config> <operation> <host>")
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
	config := parsed.DNS
	resolver := D.NewResolver(D.Config{
		Main:                 config.NameServer,
		Default:              config.DefaultNameserver,
		Policy:               config.NameServerPolicy,
		Fallback:             config.Fallback,
		FallbackIPFilter:     config.FallbackIPFilter,
		FallbackDomainFilter: config.FallbackDomainFilter,
		FallbackLazyQuery:    config.FallbackLazyQuery,
		IPv6:                 config.IPv6,
		IPv6Timeout:          config.IPv6Timeout,
	}).Resolver
	ctx := context.Background()
	switch os.Args[2] {
	case "lookup":
		addresses, err := resolver.LookupIP(ctx, os.Args[3])
		if err != nil {
			fail(err)
		}
		values := make([]string, 0, len(addresses))
		for _, address := range addresses {
			values = append(values, address.String())
		}
		fmt.Println(strings.Join(values, ","))
	case "primary":
		addresses, err := resolver.LookupIPPrimaryIPv4(ctx, os.Args[3])
		if err != nil {
			fail(err)
		}
		values := make([]string, 0, len(addresses))
		for _, address := range addresses {
			values = append(values, address.String())
		}
		fmt.Println(strings.Join(values, ","))
	case "ech":
		ech, err := resolver.ResolveECH(ctx, os.Args[3])
		if err != nil {
			fail(err)
		}
		fmt.Println(hex.EncodeToString(ech))
	default:
		fmt.Fprintln(os.Stderr, "unknown operation")
		os.Exit(2)
	}
}

func fail(err error) {
	fmt.Fprintln(os.Stderr, err)
	os.Exit(1)
}
