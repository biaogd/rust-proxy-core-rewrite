// Development-only authority: SHA-2-only RSA auth and delayed channel confirms.
package main

import (
	"bytes"
	"crypto/ed25519"
	"crypto/rand"
	"flag"
	"fmt"
	"io"
	"net"
	"os"
	"strconv"
	"time"

	"github.com/metacubex/ssh"
)

func main() {
	listen := flag.String("listen", "127.0.0.1:0", "loopback listen address")
	keyFile := flag.String("authorized-key", "", "RSA public key")
	marker := flag.String("marker", "", "stalled channel marker")
	flag.Parse()
	keyBytes, err := os.ReadFile(*keyFile)
	if err != nil {
		panic(err)
	}
	key, _, _, _, err := ssh.ParseAuthorizedKey(keyBytes)
	if err != nil {
		panic(err)
	}
	_, private, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		panic(err)
	}
	signer, err := ssh.NewSignerFromKey(private)
	if err != nil {
		panic(err)
	}
	config := &ssh.ServerConfig{
		PublicKeyAuthAlgorithms: []string{ssh.KeyAlgoRSASHA512, ssh.KeyAlgoRSASHA256},
		PublicKeyCallback: func(c ssh.ConnMetadata, offered ssh.PublicKey) (*ssh.Permissions, error) {
			if c.User() == "alice" && bytes.Equal(offered.Marshal(), key.Marshal()) {
				return nil, nil
			}
			return nil, fmt.Errorf("unauthorized key")
		},
	}
	config.AddHostKey(signer)
	listener, err := net.Listen("tcp", *listen)
	if err != nil {
		panic(err)
	}
	fmt.Println(listener.Addr())
	for {
		conn, err := listener.Accept()
		if err != nil {
			return
		}
		go func() {
			defer conn.Close()
			server, channels, requests, err := ssh.NewServerConn(conn, config)
			if err != nil {
				fmt.Fprintln(os.Stderr, "handshake:", err)
				return
			}
			defer server.Close()
			go ssh.DiscardRequests(requests)
			for channel := range channels {
				go forward(channel, *marker)
			}
		}()
	}
}

func forward(request ssh.NewChannel, marker string) {
	var target struct {
		Host       string
		Port       uint32
		Origin     string
		OriginPort uint32
	}
	if request.ChannelType() != "direct-tcpip" || ssh.Unmarshal(request.ExtraData(), &target) != nil {
		_ = request.Reject(ssh.UnknownChannelType, "unsupported")
		return
	}
	if target.Port == 9 {
		_ = os.WriteFile(marker, []byte("waiting"), 0600)
		deadline := time.Now().Add(15 * time.Second)
		for time.Now().Before(deadline) {
			if _, err := os.Stat(marker + ".release"); err == nil {
				break
			}
			time.Sleep(10 * time.Millisecond)
		}
		_ = request.Reject(ssh.ConnectionFailed, "deliberately delayed")
		return
	}
	tcp, err := net.DialTimeout("tcp", net.JoinHostPort(target.Host, strconv.Itoa(int(target.Port))), 3*time.Second)
	if err != nil {
		_ = request.Reject(ssh.ConnectionFailed, "target refused")
		return
	}
	defer tcp.Close()
	channel, requests, err := request.Accept()
	if err != nil {
		return
	}
	defer channel.Close()
	go ssh.DiscardRequests(requests)
	done := make(chan struct{})
	go func() { _, _ = io.Copy(tcp, channel); _ = tcp.(*net.TCPConn).CloseWrite(); close(done) }()
	_, _ = io.Copy(channel, tcp)
	_ = channel.CloseWrite()
	<-done
}
