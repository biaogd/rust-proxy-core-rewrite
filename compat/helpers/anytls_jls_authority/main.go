// AnyTLS-over-JLS authority for Phase 6G-E differentials.
//
// Accepts JLS (replacing native TLS), then speaks the AnyTLS session protocol
// and echoes each stream — matching Go listener/anytls with jls-config enabled.
package main

import (
	"context"
	"crypto/sha256"
	"encoding/binary"
	"fmt"
	"net"
	"os"
	"sync/atomic"

	"github.com/metacubex/mihomo/common/buf"
	"github.com/metacubex/mihomo/transport/anytls/padding"
	"github.com/metacubex/mihomo/transport/anytls/session"
	"github.com/metacubex/mihomo/transport/jls"

	"github.com/metacubex/sing/common/bufio"
	M "github.com/metacubex/sing/common/metadata"
)

func main() {
	if len(os.Args) != 5 {
		panic("usage: anytls-jls-authority LISTEN ANYTLS_PASSWORD JLS_USERNAME JLS_PASSWORD")
	}
	listen := os.Args[1]
	anytlsPassword := os.Args[2]
	jlsUsername := os.Args[3]
	jlsPassword := os.Args[4]

	serverConfig, err := jls.NewServerConfig(
		"phase6g-jls.example",
		"127.0.0.1:9",
		[]jls.User{{Username: jlsUsername, Password: jlsPassword}},
		nil,
		0,
		func(ctx context.Context, network, address string) (net.Conn, error) {
			return (&net.Dialer{}).DialContext(ctx, network, address)
		},
	)
	if err != nil {
		panic(err)
	}

	passwordHash := sha256.Sum256([]byte(anytlsPassword))
	var paddingFactory atomic.Pointer[padding.PaddingFactory]
	padding.UpdatePaddingScheme(padding.DefaultPaddingScheme, &paddingFactory)

	listener, err := net.Listen("tcp", listen)
	if err != nil {
		panic(err)
	}
	defer listener.Close()
	fmt.Printf("READY %s\n", listener.Addr())
	_ = os.Stdout.Sync()

	for {
		raw, acceptErr := listener.Accept()
		if acceptErr != nil {
			panic(acceptErr)
		}
		go serve(raw, serverConfig, passwordHash, &paddingFactory)
	}
}

func serve(
	raw net.Conn,
	serverConfig *jls.ServerConfig,
	passwordHash [32]byte,
	paddingFactory *atomic.Pointer[padding.PaddingFactory],
) {
	defer raw.Close()
	jlsConn, err := jls.Server(context.Background(), raw, serverConfig)
	if err != nil {
		fmt.Fprintln(os.Stderr, "jls:", err)
		return
	}
	defer jlsConn.Close()

	b := buf.NewPacket()
	defer b.Release()
	if _, err := b.ReadOnceFrom(jlsConn); err != nil {
		return
	}
	conn := bufio.NewCachedConn(jlsConn, b)

	got, err := b.ReadBytes(32)
	if err != nil {
		return
	}
	var gotHash [32]byte
	copy(gotHash[:], got)
	if gotHash != passwordHash {
		return
	}
	lengthBytes, err := b.ReadBytes(2)
	if err != nil {
		return
	}
	paddingLen := binary.BigEndian.Uint16(lengthBytes)
	if paddingLen > 0 {
		if _, err := b.ReadBytes(int(paddingLen)); err != nil {
			return
		}
	}

	serverSession := session.NewServerSession(conn, func(stream *session.Stream) {
		defer stream.Close()
		if _, err := M.SocksaddrSerializer.ReadAddrPort(stream); err != nil {
			return
		}
		if err := stream.HandshakeSuccess(); err != nil {
			return
		}
		buf := make([]byte, 4096)
		for {
			n, err := stream.Read(buf)
			if n > 0 {
				if _, writeErr := stream.Write(buf[:n]); writeErr != nil {
					return
				}
			}
			if err != nil {
				return
			}
		}
	}, paddingFactory)
	serverSession.Run()
	serverSession.Close()
}
