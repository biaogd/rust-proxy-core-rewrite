// AnyTLS-over-ShadowTLS v3 authority for Phase 6G-E differentials.
//
// Accepts ShadowTLS (replacing native TLS), then speaks the AnyTLS session
// protocol and relays each stream to the requested destination — matching Go
// listener/anytls with shadow-tls enabled (no inner certificate TLS).
package main

import (
	"context"
	"crypto/sha256"
	"encoding/binary"
	"fmt"
	"io"
	"net"
	"os"
	"sync/atomic"

	"github.com/metacubex/mihomo/common/buf"
	"github.com/metacubex/mihomo/component/ca"
	"github.com/metacubex/mihomo/transport/anytls/padding"
	"github.com/metacubex/mihomo/transport/anytls/session"
	"github.com/metacubex/mihomo/transport/shadowtls"

	"github.com/metacubex/sing/common/bufio"
	M "github.com/metacubex/sing/common/metadata"
	"github.com/metacubex/tls"
)

func main() {
	if len(os.Args) != 4 {
		panic("usage: anytls-shadowtls-authority LISTEN ANYTLS_PASSWORD SHADOWTLS_PASSWORD")
	}
	listen := os.Args[1]
	anytlsPassword := os.Args[2]
	shadowPassword := os.Args[3]

	camouflageAddr, err := startCamouflageServer()
	if err != nil {
		panic(err)
	}
	serverConfig, err := newShadowTLSConfig(shadowPassword, camouflageAddr)
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
	serverConfig *shadowtls.ServerConfig,
	passwordHash [32]byte,
	paddingFactory *atomic.Pointer[padding.PaddingFactory],
) {
	defer raw.Close()
	shadowConn, err := shadowtls.Server(context.Background(), raw, serverConfig)
	if err != nil {
		fmt.Fprintln(os.Stderr, "shadowtls:", err)
		return
	}
	defer shadowConn.Close()

	b := buf.NewPacket()
	defer b.Release()
	if _, err := b.ReadOnceFrom(shadowConn); err != nil {
		return
	}
	conn := bufio.NewCachedConn(shadowConn, b)

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

	session := session.NewServerSession(conn, func(stream *session.Stream) {
		defer stream.Close()
		if _, err := M.SocksaddrSerializer.ReadAddrPort(stream); err != nil {
			return
		}
		if err := stream.HandshakeSuccess(); err != nil {
			return
		}
		// Differentials use synthetic hostnames; echo on the stream like the
		// Python AnyTLS authorities instead of dialing the requested name.
		// HTTP GET/HEAD (url-test / healthcheck) gets a 200 response.
		buf := make([]byte, 4096)
		first := true
		for {
			n, err := stream.Read(buf)
			if n > 0 {
				if first && (hasHTTPMethod(buf[:n], "GET") || hasHTTPMethod(buf[:n], "HEAD")) {
					_, _ = stream.Write([]byte("HTTP/1.1 200 OK\r\nContent-Length: 5\r\nConnection: close\r\n\r\nprobe"))
					return
				}
				first = false
				if _, writeErr := stream.Write(buf[:n]); writeErr != nil {
					return
				}
			}
			if err != nil {
				return
			}
		}
	}, paddingFactory)
	session.Run()
	session.Close()
}

func hasHTTPMethod(buf []byte, method string) bool {
	if len(buf) < len(method)+1 {
		return false
	}
	for i := 0; i < len(method); i++ {
		if buf[i] != method[i] {
			return false
		}
	}
	return buf[len(method)] == ' '
}

func startCamouflageServer() (string, error) {
	certificatePEM, privateKeyPEM, _, err := ca.NewRandomTLSKeyPair(ca.KeyPairTypeP256)
	if err != nil {
		return "", err
	}
	certificate, err := tls.X509KeyPair([]byte(certificatePEM), []byte(privateKeyPEM))
	if err != nil {
		return "", err
	}
	config := &tls.Config{
		Certificates: []tls.Certificate{certificate},
		NextProtos:   append([]string(nil), shadowtls.DefaultALPN...),
		MinVersion:   tls.VersionTLS12,
	}
	rawListener, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		return "", err
	}
	listener := tls.NewListener(rawListener, config)
	go func() {
		for {
			conn, acceptErr := listener.Accept()
			if acceptErr != nil {
				return
			}
			go func() {
				defer conn.Close()
				_, _ = io.Copy(conn, conn)
			}()
		}
	}()
	return listener.Addr().String(), nil
}

func newShadowTLSConfig(password, camouflageAddr string) (*shadowtls.ServerConfig, error) {
	handshake := shadowtls.HandshakeConfig{
		Server: camouflageAddr,
		DialContext: func(ctx context.Context, network, address string) (net.Conn, error) {
			return (&net.Dialer{}).DialContext(ctx, network, address)
		},
	}
	return shadowtls.NewServerConfig(
		3,
		password,
		[]shadowtls.User{{Name: "phase6g-e", Password: password}},
		handshake,
		nil,
		true,
		shadowtls.WildcardSNIOff,
	)
}

