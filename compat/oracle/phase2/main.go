// Command phase2-oracle exposes deterministic configuration and pure-rule
// observations from the pinned Go implementation. It is test-only.
package main

import (
	"context"
	"encoding/json"
	"fmt"
	"io"
	"net/netip"
	"os"
	"strings"

	"github.com/metacubex/mihomo/config"
	C "github.com/metacubex/mihomo/constant"
	_ "github.com/metacubex/mihomo/hub/executor" // supplies config's linknamed temporary state hook
	MLog "github.com/metacubex/mihomo/log"
)

type request struct {
	Op        string              `json:"op"`
	YAML      string              `json:"yaml"`
	Rules     []string            `json:"rules"`
	SubRules  map[string][]string `json:"sub-rules"`
	Rematches []rematchInput      `json:"rematches"`
	Metadata  metadataInput       `json:"metadata"`
}

type rematchInput struct {
	Name              string  `json:"name"`
	TargetRematchName *string `json:"target-rematch-name"`
	TargetSubRule     *string `json:"target-sub-rule"`
}

type metadataInput struct {
	Network         string `json:"network"`
	Host            string `json:"host"`
	SniffHost       string `json:"sniff-host"`
	SourceIP        string `json:"source-ip"`
	DestinationIP   string `json:"destination-ip"`
	SourcePort      uint16 `json:"source-port"`
	DestinationPort uint16 `json:"destination-port"`
	InboundPort     uint16 `json:"inbound-port"`
	RematchName     string `json:"rematch-name"`
	SpecialRules    string `json:"special-rules"`
}

type response struct {
	Accepted   bool              `json:"accepted"`
	ErrorClass *string           `json:"error-class"`
	Config     *normalizedConfig `json:"config"`
	Decision   *decision         `json:"decision"`
}

type normalizedConfig struct {
	Port              int                 `json:"port"`
	SocksPort         int                 `json:"socks-port"`
	RedirPort         int                 `json:"redir-port"`
	TProxyPort        int                 `json:"tproxy-port"`
	MixedPort         int                 `json:"mixed-port"`
	AllowLan          bool                `json:"allow-lan"`
	BindAddress       string              `json:"bind-address"`
	Mode              string              `json:"mode"`
	UnifiedDelay      bool                `json:"unified-delay"`
	LogLevel          string              `json:"log-level"`
	IPv6              bool                `json:"ipv6"`
	Interface         string              `json:"interface-name"`
	RoutingMark       int                 `json:"routing-mark"`
	TCPConcurrent     bool                `json:"tcp-concurrent"`
	KeepAliveIdle     int                 `json:"keep-alive-idle"`
	KeepAliveInterval int                 `json:"keep-alive-interval"`
	DisableKeepAlive  bool                `json:"disable-keep-alive"`
	ETagSupport       bool                `json:"etag-support"`
	Rules             []string            `json:"rules"`
	SubRules          map[string][]string `json:"sub-rules"`
}

type decision struct {
	Target        string             `json:"target"`
	MatchedKind   *string            `json:"matched-kind"`
	RematchCycle  bool               `json:"rematch-cycle"`
	FinalMetadata normalizedMetadata `json:"final-metadata"`
}

type normalizedMetadata struct {
	RematchName  string `json:"rematch-name"`
	SpecialRules string `json:"special-rules"`
}

func main() {
	MLog.SetLevel(MLog.SILENT)
	input, err := io.ReadAll(os.Stdin)
	if err != nil {
		fatal(err)
	}
	var requests []request
	if err := json.Unmarshal(input, &requests); err != nil {
		fatal(err)
	}

	responses := make([]response, 0, len(requests))
	for _, req := range requests {
		responses = append(responses, observe(req))
	}
	encoder := json.NewEncoder(os.Stdout)
	encoder.SetEscapeHTML(false)
	if err := encoder.Encode(responses); err != nil {
		fatal(err)
	}
}

func fatal(err error) {
	_, _ = fmt.Fprintln(os.Stderr, err)
	os.Exit(1)
}

func observe(req request) response {
	switch req.Op {
	case "config":
		return observeConfig(req.YAML)
	case "rules":
		return observeRules(req)
	default:
		return rejected("invalid-request")
	}
}

func observeConfig(source string) response {
	raw, err := config.UnmarshalRawConfig([]byte(source))
	if err != nil {
		return rejected(classifyError(err))
	}
	if raw.Rule == nil {
		raw.Rule = []string{}
	}
	if raw.SubRules == nil {
		raw.SubRules = map[string][]string{}
	}
	return response{
		Accepted: true,
		Config: &normalizedConfig{
			Port: raw.Port, SocksPort: raw.SocksPort, RedirPort: raw.RedirPort,
			TProxyPort: raw.TProxyPort, MixedPort: raw.MixedPort,
			AllowLan: raw.AllowLan, BindAddress: raw.BindAddress,
			Mode: raw.Mode.String(), UnifiedDelay: raw.UnifiedDelay,
			LogLevel: raw.LogLevel.String(), IPv6: raw.IPv6,
			Interface: raw.Interface, RoutingMark: raw.RoutingMark,
			TCPConcurrent: raw.TCPConcurrent, KeepAliveIdle: raw.KeepAliveIdle,
			KeepAliveInterval: raw.KeepAliveInterval,
			DisableKeepAlive:  raw.DisableKeepAlive, ETagSupport: raw.ETagSupport,
			Rules: raw.Rule, SubRules: raw.SubRules,
		},
	}
}

func observeRules(req request) response {
	raw := config.DefaultRawConfig()
	raw.Rule = req.Rules
	raw.SubRules = req.SubRules
	for _, rematch := range req.Rematches {
		mapping := map[string]any{"name": rematch.Name, "type": "rematch"}
		if rematch.TargetRematchName != nil {
			mapping["target-rematch-name"] = *rematch.TargetRematchName
		}
		if rematch.TargetSubRule != nil {
			mapping["target-sub-rule"] = *rematch.TargetSubRule
		}
		raw.Proxy = append(raw.Proxy, mapping)
	}

	parsed, err := config.ParseRawConfig(raw)
	if err != nil {
		return rejected(classifyError(err))
	}
	metadata, err := makeMetadata(req.Metadata)
	if err != nil {
		return rejected("invalid-metadata")
	}
	result := evaluate(parsed, metadata)
	return response{Accepted: true, Decision: &result}
}

func makeMetadata(input metadataInput) (*C.Metadata, error) {
	metadata := &C.Metadata{
		Host: input.Host, SniffHost: input.SniffHost,
		SrcPort: input.SourcePort, DstPort: input.DestinationPort,
		InPort: input.InboundPort, RematchName: input.RematchName,
		SpecialRules: input.SpecialRules,
	}
	switch strings.ToUpper(input.Network) {
	case "", "TCP":
		metadata.NetWork = C.TCP
	case "UDP":
		metadata.NetWork = C.UDP
	default:
		return nil, fmt.Errorf("invalid network")
	}
	var err error
	if input.SourceIP != "" {
		metadata.SrcIP, err = netip.ParseAddr(input.SourceIP)
		if err != nil {
			return nil, err
		}
	}
	if input.DestinationIP != "" {
		metadata.DstIP, err = netip.ParseAddr(input.DestinationIP)
		if err != nil {
			return nil, err
		}
	}
	return metadata, nil
}

func evaluate(parsed *config.Config, metadata *C.Metadata) decision {
	rematchChain := map[string]bool{}
	for iteration := 0; iteration < 64; iteration++ {
		rules := parsed.Rules
		if selected, ok := parsed.SubRules[metadata.SpecialRules]; ok {
			rules = selected
		}

		var rematchProxy C.Proxy
		var rematchRule C.Rule
	ruleLoop:
		for _, rule := range rules {
			matched, target := rule.Match(metadata, C.RuleMatchHelper{})
			if !matched {
				continue
			}
			proxy, ok := parsed.Proxies[target]
			if !ok {
				continue
			}
			for current := C.ProxyAdapter(proxy); current != nil; {
				switch current.Type() {
				case C.Pass:
					continue ruleLoop
				case C.Rematch:
					rematchProxy = proxy
					rematchRule = rule
					break ruleLoop
				}
				next := current.Unwrap(metadata, false)
				if next == nil {
					break
				}
				current = next
			}
			kind := rule.RuleType().String()
			return makeDecision(target, &kind, false, metadata)
		}

		if rematchProxy == nil {
			return makeDecision("DIRECT", nil, false, metadata)
		}
		kind := rematchRule.RuleType().String()
		if rematchChain[rematchProxy.Name()] {
			return makeDecision(rematchProxy.Name(), &kind, true, metadata)
		}
		rematchChain[rematchProxy.Name()] = true
		conn, err := rematchProxy.DialContext(context.Background(), metadata)
		if conn != nil {
			_ = conn.Close()
		}
		if err != nil {
			return makeDecision(rematchProxy.Name(), &kind, false, metadata)
		}
	}
	return makeDecision("DIRECT", nil, true, metadata)
}

func makeDecision(target string, kind *string, cycle bool, metadata *C.Metadata) decision {
	return decision{
		Target: target, MatchedKind: kind, RematchCycle: cycle,
		FinalMetadata: normalizedMetadata{
			RematchName:  metadata.RematchName,
			SpecialRules: metadata.SpecialRules,
		},
	}
}

func rejected(class string) response {
	return response{Accepted: false, ErrorClass: &class}
}

func classifyError(err error) string {
	message := strings.ToLower(err.Error())
	switch {
	case strings.Contains(message, "invalid mode"):
		return "invalid-mode"
	case strings.Contains(message, "invalid log-level"):
		return "invalid-log-level"
	case strings.Contains(message, "circular references"):
		return "sub-rule-cycle"
	case strings.Contains(message, "sub-rule") && strings.Contains(message, "not found"):
		return "sub-rule-not-found"
	case strings.Contains(message, "proxy") && strings.Contains(message, "not found"):
		return "proxy-not-found"
	case strings.Contains(message, "format invalid") || strings.Contains(message, "format error") || strings.Contains(message, "payload format"):
		return "rule-format"
	case strings.Contains(message, "unsupported rule type") || strings.Contains(message, "unsupported network type"):
		return "unsupported-rule"
	case strings.Contains(message, "payloadrule error") || strings.Contains(message, "invalid range") || strings.Contains(message, "must contain one rule"):
		return "invalid-rule-payload"
	case strings.Contains(message, "yaml") || strings.Contains(message, "unmarshal") || strings.Contains(message, "cannot decode"):
		return "yaml"
	default:
		return "other"
	}
}
