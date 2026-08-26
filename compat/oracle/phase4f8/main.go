package main

import (
	"context"
	"fmt"
	"os"
	"path/filepath"

	C "github.com/metacubex/mihomo/config"
	P "github.com/metacubex/mihomo/constant"
	D "github.com/metacubex/mihomo/dns"
	_ "github.com/metacubex/mihomo/hub/executor"
	T "github.com/metacubex/mihomo/tunnel"
)

func main() {
	if len(os.Args) != 4 {
		fmt.Fprintln(os.Stderr, "usage: phase4f8 <config> <set> <host>")
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
	T.UpdateRules(parsed.Rules, parsed.SubRules, parsed.RuleProviders)
	config := parsed.DNS
	resolvers := D.NewResolver(D.Config{
		Main:                 config.NameServer,
		Default:              config.DefaultNameserver,
		Policy:               config.NameServerPolicy,
		ProxyServer:          config.ProxyServerNameserver,
		ProxyServerPolicy:    config.ProxyServerPolicy,
		DirectServer:         config.DirectNameServer,
		DirectFollowPolicy:   config.DirectFollowPolicy,
		Fallback:             config.Fallback,
		FallbackIPFilter:     config.FallbackIPFilter,
		FallbackDomainFilter: config.FallbackDomainFilter,
		FallbackLazyQuery:    config.FallbackLazyQuery,
	})
	resolver := resolvers.Resolver
	switch os.Args[2] {
	case "main":
	case "proxy":
		resolver = resolvers.ProxyResolver
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
