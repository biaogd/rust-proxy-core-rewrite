package dns

import "testing"

func TestPhase4F6ClassicWrapperTransportIdentity(t *testing.T) {
	base := NameServer{
		Net:    "tcp",
		Addr:   "127.0.0.1:15353",
		Params: map[string]string{"ecs": "203.0.113.0/24"},
	}
	exact := NameServer{
		Net:    base.Net,
		Addr:   base.Addr,
		Params: map[string]string{"ecs": "203.0.113.0/24"},
	}
	if !base.Equal(exact) || !base.transportEqual(exact) {
		t.Fatal("exact wrapper identity did not reuse the wrapped client")
	}

	differentWrapper := NameServer{
		Net:    base.Net,
		Addr:   base.Addr,
		Params: map[string]string{"disable-ipv4": "true"},
	}
	if base.Equal(differentWrapper) {
		t.Fatal("different wrapper parameters unexpectedly had exact identity")
	}
	if !base.transportEqual(differentWrapper) {
		t.Fatal("wrapper-only parameters unexpectedly split raw transport identity")
	}

	differentTransportOption := NameServer{
		Net:    base.Net,
		Addr:   base.Addr,
		Params: map[string]string{"reuse": "false"},
	}
	if base.transportEqual(differentTransportOption) {
		t.Fatal("non-wrapper parameter unexpectedly shared raw transport identity")
	}

	differentProxy := base
	differentProxy.ProxyName = "proxy-outbound"
	if base.transportEqual(differentProxy) {
		t.Fatal("different proxy route unexpectedly shared raw transport identity")
	}
}
