package main

import (
	"encoding/hex"
	"encoding/json"
	"fmt"
	"net"
	"os"
	"strings"

	"github.com/insomniacslk/dhcp/dhcpv4"
)

var transactionID = dhcpv4.TransactionID{0x12, 0x34, 0x56, 0x78}

type observation struct {
	Discover string      `json:"discover"`
	Offers   []offerCase `json:"offers"`
}

type offerCase struct {
	Name           string `json:"name"`
	Wire           string `json:"wire"`
	Classification string `json:"classification"`
}

func main() {
	discovery, err := dhcpv4.NewDiscovery(
		net.HardwareAddr{0, 1, 2, 3, 4, 5},
		dhcpv4.WithBroadcast(true),
		dhcpv4.WithRequestedOptions(dhcpv4.OptionDomainNameServer),
		dhcpv4.WithTransactionID(transactionID),
	)
	if err != nil {
		panic(err)
	}
	offers := []offerCase{
		makeOffer("valid", transactionID, dhcpv4.MessageTypeOffer, true),
		makeOffer("missing-dns", transactionID, dhcpv4.MessageTypeOffer, false),
		makeMalformedDNSOffer(),
		makeOffer("wrong-type", transactionID, dhcpv4.MessageTypeAck, true),
		makeOffer("wrong-transaction", dhcpv4.TransactionID{1, 2, 3, 4}, dhcpv4.MessageTypeOffer, true),
	}
	if err := json.NewEncoder(os.Stdout).Encode(observation{
		Discover: hex.EncodeToString(discovery.ToBytes()),
		Offers:   offers,
	}); err != nil {
		panic(err)
	}
}

func makeMalformedDNSOffer() offerCase {
	packet, err := dhcpv4.New(
		dhcpv4.WithTransactionID(transactionID),
		dhcpv4.WithMessageType(dhcpv4.MessageTypeOffer),
		dhcpv4.WithOption(dhcpv4.OptGeneric(dhcpv4.OptionDomainNameServer, []byte{1, 1, 1})),
	)
	if err != nil {
		panic(err)
	}
	packet.OpCode = dhcpv4.OpcodeBootReply
	wire := packet.ToBytes()
	return offerCase{
		Name:           "malformed-dns",
		Wire:           hex.EncodeToString(wire),
		Classification: classify(wire),
	}
}

func makeOffer(name string, xid dhcpv4.TransactionID, messageType dhcpv4.MessageType, includeDNS bool) offerCase {
	modifiers := []dhcpv4.Modifier{
		dhcpv4.WithTransactionID(xid),
		dhcpv4.WithMessageType(messageType),
	}
	if includeDNS {
		modifiers = append(modifiers, dhcpv4.WithOption(dhcpv4.OptDNS(
			net.IPv4(1, 1, 1, 1), net.IPv4(8, 8, 8, 8),
		)))
	}
	packet, err := dhcpv4.New(modifiers...)
	if err != nil {
		panic(err)
	}
	packet.OpCode = dhcpv4.OpcodeBootReply
	wire := packet.ToBytes()
	return offerCase{
		Name:           name,
		Wire:           hex.EncodeToString(wire),
		Classification: classify(wire),
	}
}

func classify(wire []byte) string {
	packet, err := dhcpv4.FromBytes(wire)
	if err != nil || packet.MessageType() != dhcpv4.MessageTypeOffer || packet.TransactionID != transactionID {
		return "ignored"
	}
	servers := packet.DNS()
	if len(servers) == 0 {
		return "missing-dns"
	}
	rendered := make([]string, 0, len(servers))
	for _, server := range servers {
		rendered = append(rendered, server.String())
	}
	return fmt.Sprintf("servers:%s", strings.Join(rendered, ","))
}
