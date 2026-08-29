// Captures the first TLS ClientHello from a uTLS chrome dial and prints
// cipher suites + extension types as JSON for differential comparison.
package main

import (
	"encoding/binary"
	"encoding/json"
	"fmt"
	"io"
	"net"
	"os"
	"time"

	tlsC "github.com/metacubex/mihomo/component/tls"
	utls "github.com/metacubex/utls"
)

type helloShape struct {
	CipherSuites []string `json:"cipher_suites"`
	Extensions   []string `json:"extensions"`
	HasGrease    bool     `json:"has_grease"`
}

func isGrease(v uint16) bool {
	return v&0x0f0f == 0x0a0a
}

func normalizeGrease(v uint16) uint16 {
	if isGrease(v) {
		return 0x0a0a
	}
	return v
}

func hexU16(v uint16) string {
	return fmt.Sprintf("0x%04x", v)
}

func parseClientHello(record []byte) (helloShape, error) {
	if len(record) < 5 || record[0] != 22 {
		return helloShape{}, fmt.Errorf("not a handshake record")
	}
	length := int(binary.BigEndian.Uint16(record[3:5]))
	body := record[5:]
	if len(body) < length {
		return helloShape{}, fmt.Errorf("truncated record")
	}
	body = body[:length]
	if len(body) < 4 || body[0] != 1 {
		return helloShape{}, fmt.Errorf("not ClientHello")
	}
	msgLen := int(body[1])<<16 | int(body[2])<<8 | int(body[3])
	payload := body[4:]
	if len(payload) < msgLen {
		return helloShape{}, fmt.Errorf("truncated hello")
	}
	payload = payload[:msgLen]
	if len(payload) < 35 {
		return helloShape{}, fmt.Errorf("short hello")
	}
	offset := 2 + 32
	sidLen := int(payload[offset])
	offset += 1 + sidLen
	if len(payload) < offset+2 {
		return helloShape{}, fmt.Errorf("short cipher length")
	}
	csLen := int(binary.BigEndian.Uint16(payload[offset:]))
	offset += 2
	if len(payload) < offset+csLen+1 {
		return helloShape{}, fmt.Errorf("short ciphers")
	}
	var ciphers []string
	hasGrease := false
	for i := 0; i+1 < csLen; i += 2 {
		v := binary.BigEndian.Uint16(payload[offset+i:])
		if isGrease(v) {
			hasGrease = true
		}
		ciphers = append(ciphers, hexU16(normalizeGrease(v)))
	}
	offset += csLen
	compLen := int(payload[offset])
	offset += 1 + compLen
	if len(payload) < offset+2 {
		return helloShape{}, fmt.Errorf("short extensions length")
	}
	extLen := int(binary.BigEndian.Uint16(payload[offset:]))
	offset += 2
	end := offset + extLen
	if len(payload) < end {
		return helloShape{}, fmt.Errorf("short extensions")
	}
	var exts []string
	for offset+4 <= end {
		typ := binary.BigEndian.Uint16(payload[offset:])
		l := int(binary.BigEndian.Uint16(payload[offset+2:]))
		offset += 4
		if offset+l > end {
			break
		}
		if isGrease(typ) {
			hasGrease = true
			exts = append(exts, hexU16(0x0a0a))
		} else {
			exts = append(exts, hexU16(typ))
		}
		offset += l
	}
	return helloShape{CipherSuites: ciphers, Extensions: exts, HasGrease: hasGrease}, nil
}

func main() {
	fingerprint := "chrome"
	if len(os.Args) > 1 {
		fingerprint = os.Args[1]
	}

	ln, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		panic(err)
	}
	defer ln.Close()

	type result struct {
		shape helloShape
		err   error
	}
	done := make(chan result, 1)
	go func() {
		conn, err := ln.Accept()
		if err != nil {
			done <- result{err: err}
			return
		}
		defer conn.Close()
		_ = conn.SetReadDeadline(time.Now().Add(5 * time.Second))
		header := make([]byte, 5)
		if _, err := io.ReadFull(conn, header); err != nil {
			done <- result{err: err}
			return
		}
		length := int(binary.BigEndian.Uint16(header[3:5]))
		body := make([]byte, length)
		if _, err := io.ReadFull(conn, body); err != nil {
			done <- result{err: err}
			return
		}
		record := append(header, body...)
		shape, err := parseClientHello(record)
		done <- result{shape: shape, err: err}
	}()

	raw, err := net.DialTimeout("tcp", ln.Addr().String(), 2*time.Second)
	if err != nil {
		panic(err)
	}
	defer raw.Close()

	uconfig := &utls.Config{
		ServerName:         "phase6c-shadow-tls.example",
		InsecureSkipVerify: true,
		NextProtos:         []string{"h2", "http/1.1"},
		MinVersion:         utls.VersionTLS12,
	}
	id, ok := tlsC.GetFingerprint(fingerprint)
	if !ok {
		panic("unknown fingerprint")
	}
	uconn := utls.UClient(raw, uconfig, id)
	_ = uconn.Handshake()

	res := <-done
	if res.err != nil {
		panic(res.err)
	}
	enc := json.NewEncoder(os.Stdout)
	enc.SetIndent("", "  ")
	_ = enc.Encode(res.shape)
}
