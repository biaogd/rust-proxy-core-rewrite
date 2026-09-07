// Development-only Restls oracle. Never linked into the Rust product.
package main

import (
	"context"
	"crypto/sha256"
	"crypto/tls"
	"encoding/binary"
	"fmt"
	"io"
	"net"
	"os"
	"sync/atomic"
	"time"

	"github.com/metacubex/mihomo/transport/anytls/padding"
	"github.com/metacubex/mihomo/transport/anytls/session"
	restls "github.com/metacubex/restls-client-go"
	M "github.com/metacubex/sing/common/metadata"
)

func main() {
	if len(os.Args) != 4 && len(os.Args) != 5 {
		panic("usage: restls-authority CERT KEY SCRIPT [anytls]")
	}
	cert, err := tls.LoadX509KeyPair(os.Args[1], os.Args[2])
	if err != nil {
		panic(err)
	}
	target, err := tls.Listen("tcp", "127.0.0.1:0", &tls.Config{Certificates: []tls.Certificate{cert}, MinVersion: tls.VersionTLS13, MaxVersion: tls.VersionTLS13})
	if err != nil {
		panic(err)
	}
	defer target.Close()
	go func() {
		for {
			conn, err := target.Accept()
			if err != nil {
				return
			}
			go func() {
				defer conn.Close()
				_ = conn.SetDeadline(time.Now().Add(20 * time.Second))
				_, _ = io.Copy(io.Discard, conn)
			}()
		}
	}()
	listener, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		panic(err)
	}
	defer listener.Close()
	fmt.Printf("%s %s\n", listener.Addr(), target.Addr())
	for {
		raw, err := listener.Accept()
		if err != nil {
			return
		}
		go func() {
			defer raw.Close()
			_ = raw.SetDeadline(time.Now().Add(20 * time.Second))
			config := &restls.RestlsServerConfig{ServerHostname: target.Addr().String(), Password: "restls-test", RestlsScript: os.Args[3]}
			conn, err := restls.RestlsServer(context.Background(), raw, config)
			if err != nil {
				fmt.Fprintln(os.Stderr, err)
				return
			}
			defer conn.Close()
			if len(os.Args) == 5 {
				serveAnyTLS(conn)
			} else {
				_, err = io.Copy(conn, conn)
				if err != nil {
					fmt.Fprintln(os.Stderr, err)
				}
			}
		}()
	}
}

func serveAnyTLS(conn net.Conn) {
	hash := sha256.Sum256([]byte("phase6g-carrier-anytls"))
	var got [32]byte
	if _, err := io.ReadFull(conn, got[:]); err != nil || got != hash {
		return
	}
	var length [2]byte
	if _, err := io.ReadFull(conn, length[:]); err != nil {
		return
	}
	if _, err := io.CopyN(io.Discard, conn, int64(binary.BigEndian.Uint16(length[:]))); err != nil {
		return
	}
	var factory atomic.Pointer[padding.PaddingFactory]
	padding.UpdatePaddingScheme(padding.DefaultPaddingScheme, &factory)
	mux := session.NewServerSession(conn, func(stream *session.Stream) {
		defer stream.Close()
		if _, err := M.SocksaddrSerializer.ReadAddrPort(stream); err != nil {
			return
		}
		if err := stream.HandshakeSuccess(); err != nil {
			return
		}
		_, _ = io.Copy(stream, stream)
	}, &factory)
	mux.Run()
	mux.Close()
}
