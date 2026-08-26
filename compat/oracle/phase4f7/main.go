package main

import (
	"context"
	"fmt"
	"os"

	C "github.com/metacubex/mihomo/config"
	D "github.com/metacubex/mihomo/dns"
	_ "github.com/metacubex/mihomo/hub/executor"
)

func main() {
	if len(os.Args) != 4 {
		fmt.Fprintln(os.Stderr, "usage: phase4f7 <config> <set> <host>")
		os.Exit(2)
	}
	source, err := os.ReadFile(os.Args[1])
	if err != nil {
		fail(err)
	}
	parsed, err := C.Parse(source)
	if err != nil {
		fail(err)
	}
	config := parsed.DNS
	resolvers := D.NewResolver(D.Config{
		Main:                 config.NameServer,
		Fallback:             config.Fallback,
		Default:              config.DefaultNameserver,
		ProxyServer:          config.ProxyServerNameserver,
		DirectServer:         config.DirectNameServer,
		DirectFollowPolicy:   config.DirectFollowPolicy,
		Policy:               config.NameServerPolicy,
		FallbackIPFilter:     config.FallbackIPFilter,
		FallbackDomainFilter: config.FallbackDomainFilter,
		FallbackLazyQuery:    config.FallbackLazyQuery,
	})
	resolver := resolvers.Resolver
	switch os.Args[2] {
	case "default":
		resolver = D.NewResolver(D.Config{Main: config.DefaultNameserver}).Resolver
	case "direct":
		resolver = resolvers.DirectResolver
	case "proxy":
		resolver = resolvers.ProxyResolver
	case "main":
	default:
		fmt.Fprintln(os.Stderr, "unknown resolver set")
		os.Exit(2)
	}
	if resolver == nil {
		fail(fmt.Errorf("resolver set is empty"))
	}
	addresses, err := resolver.LookupIPv4(context.Background(), os.Args[3])
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
