package dns

import (
	"context"
	"testing"

	D "github.com/miekg/dns"
)

type phase4F5TailscaleClient struct {
	marker string
}

func (c *phase4F5TailscaleClient) Address() string {
	return "fixture://" + c.marker
}

func (c *phase4F5TailscaleClient) ExchangeContext(_ context.Context, query *D.Msg) (*D.Msg, error) {
	response := query.Copy()
	response.Response = true
	response.Extra = append(response.Extra, &D.TXT{
		Hdr: D.RR_Header{Name: "marker.phase4f5.test.", Rrtype: D.TypeTXT, Class: D.ClassINET},
		Txt: []string{c.marker},
	})
	return response, nil
}

func (c *phase4F5TailscaleClient) ResetConnection() {}

func phase4F5Marker(t *testing.T, client *tailscaleDNSClient) string {
	t.Helper()
	query := new(D.Msg)
	query.SetQuestion("registry.phase4f5.test.", D.TypeA)
	response, err := client.ExchangeContext(context.Background(), query)
	if err != nil {
		t.Fatalf("Tailscale DNS exchange failed: %v", err)
	}
	marker, ok := response.Extra[len(response.Extra)-1].(*D.TXT)
	if !ok || len(marker.Txt) != 1 {
		t.Fatalf("unexpected marker response: %#v", response.Extra)
	}
	return marker.Txt[0]
}

func TestPhase4F5TailscaleRegistryContract(t *testing.T) {
	const name = "phase4f5-registry-contract"
	client := newTailscaleClient(name)
	query := new(D.Msg)
	query.SetQuestion("registry.phase4f5.test.", D.TypeA)
	if _, err := client.ExchangeContext(context.Background(), query); err == nil {
		t.Fatal("missing registration unexpectedly resolved")
	}

	unregisterFirst := RegisterTailscaleDnsClient(name, &phase4F5TailscaleClient{marker: "first"})
	if marker := phase4F5Marker(t, client); marker != "first" {
		t.Fatalf("first registration marker = %q", marker)
	}

	unregisterReplacement := RegisterTailscaleDnsClient(name, &phase4F5TailscaleClient{marker: "replacement"})
	if marker := phase4F5Marker(t, client); marker != "replacement" {
		t.Fatalf("replacement marker = %q", marker)
	}

	unregisterFirst()
	if marker := phase4F5Marker(t, client); marker != "replacement" {
		t.Fatalf("old unregister removed replacement; marker = %q", marker)
	}

	unregisterReplacement()
	if _, err := client.ExchangeContext(context.Background(), query); err == nil {
		t.Fatal("removed replacement unexpectedly remained registered")
	}
}
