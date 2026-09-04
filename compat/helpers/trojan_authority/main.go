package main

import (
	"bufio"
	"bytes"
	"crypto/sha1"
	"crypto/sha256"
	"crypto/tls"
	"encoding/base64"
	"encoding/binary"
	"encoding/hex"
	"flag"
	"fmt"
	"io"
	"net"
	"os"

	"github.com/gobwas/ws/wsutil"
	http "github.com/metacubex/http"
	"github.com/metacubex/http/http2"
)

type h2StreamConn struct {
	net.Conn
	reader io.Reader
	writer http.ResponseWriter
}

func (conn *h2StreamConn) Read(payload []byte) (int, error) { return conn.reader.Read(payload) }

func (conn *h2StreamConn) Write(payload []byte) (int, error) {
	written, err := conn.writer.Write(payload)
	if flusher, ok := conn.writer.(http.Flusher); ok {
		flusher.Flush()
	}
	return written, err
}

func (conn *h2StreamConn) Close() error { return nil }

type gunConn struct {
	net.Conn
	remaining int
}

func readUvarint(reader io.Reader) (uint64, int, error) {
	var value uint64
	for index := 0; index < 10; index++ {
		var one [1]byte
		if _, err := io.ReadFull(reader, one[:]); err != nil {
			return 0, 0, err
		}
		if index == 9 && one[0] > 1 {
			return 0, 0, fmt.Errorf("invalid Gun payload length")
		}
		value |= uint64(one[0]&0x7f) << (index * 7)
		if one[0] < 0x80 {
			return value, index + 1, nil
		}
	}
	return 0, 0, fmt.Errorf("invalid Gun payload length")
}

func (conn *gunConn) Read(payload []byte) (int, error) {
	if conn.remaining != 0 {
		length := len(payload)
		if length > conn.remaining {
			length = conn.remaining
		}
		read, err := conn.Conn.Read(payload[:length])
		conn.remaining -= read
		return read, err
	}
	var header [6]byte
	if _, err := io.ReadFull(conn.Conn, header[:]); err != nil {
		return 0, err
	}
	if header[0] != 0 || header[5] != 0x0a {
		return 0, fmt.Errorf("invalid Gun envelope")
	}
	payloadLength, varintLength, err := readUvarint(conn.Conn)
	if err != nil {
		return 0, err
	}
	grpcLength := binary.BigEndian.Uint32(header[1:5])
	if payloadLength > uint64(^uint(0)>>1) || uint64(grpcLength) != 1+uint64(varintLength)+payloadLength {
		return 0, fmt.Errorf("invalid Gun envelope length")
	}
	conn.remaining = int(payloadLength)
	return conn.Read(payload)
}

func (conn *gunConn) Write(payload []byte) (int, error) {
	var encodedLength [10]byte
	varintLength := binary.PutUvarint(encodedLength[:], uint64(len(payload)))
	grpcLength := 1 + varintLength + len(payload)
	if uint64(grpcLength) > uint64(^uint32(0)) {
		return 0, fmt.Errorf("Gun frame is too large")
	}
	frame := make([]byte, 5+grpcLength)
	binary.BigEndian.PutUint32(frame[1:5], uint32(grpcLength))
	frame[5] = 0x0a
	copy(frame[6:], encodedLength[:varintLength])
	copy(frame[6+varintLength:], payload)
	if _, err := conn.Conn.Write(frame); err != nil {
		return 0, err
	}
	return len(payload), nil
}

type websocketConn struct {
	net.Conn
	reader io.ReadWriter
	buffer bytes.Reader
}

func (conn *websocketConn) Read(payload []byte) (int, error) {
	for conn.buffer.Len() == 0 {
		message, _, err := wsutil.ReadClientData(conn.reader)
		if err != nil {
			return 0, err
		}
		conn.buffer.Reset(message)
	}
	return conn.buffer.Read(payload)
}

func (conn *websocketConn) Write(payload []byte) (int, error) {
	if err := wsutil.WriteServerBinary(conn.Conn, payload); err != nil {
		return 0, err
	}
	return len(payload), nil
}

type bufferedReadWriter struct {
	io.Reader
	io.Writer
}

func upgrade(connection net.Conn, expectedHost, expectedPath, expectedHeader string) (net.Conn, error) {
	reader := bufio.NewReader(connection)
	request, err := http.ReadRequest(reader)
	if err != nil {
		return nil, err
	}
	defer request.Body.Close()
	if request.Method != http.MethodGet || request.Header.Get("Upgrade") != "websocket" {
		return nil, fmt.Errorf("invalid upgrade")
	}
	if request.Host != expectedHost || request.URL.RequestURI() != expectedPath {
		return nil, fmt.Errorf("unexpected WS target %s %s", request.Host, request.URL.RequestURI())
	}
	if expectedHeader != "" && request.Header.Get("X-Trojan-Phase") != expectedHeader {
		return nil, fmt.Errorf("missing custom header")
	}
	key := request.Header.Get("Sec-WebSocket-Key")
	digest := sha1.Sum([]byte(key + "258EAFA5-E914-47DA-95CA-C5AB0DC85B11"))
	accept := base64.StdEncoding.EncodeToString(digest[:])
	if _, err := fmt.Fprintf(connection, "HTTP/1.1 101 Switching Protocols\r\nUpgrade: websocket\r\nConnection: Upgrade\r\nSec-WebSocket-Accept: %s\r\n\r\n", accept); err != nil {
		return nil, err
	}
	fmt.Printf("WS %s %s HEADER %s\n", request.Host, request.URL.RequestURI(), expectedHeader)
	return &websocketConn{Conn: connection, reader: bufferedReadWriter{Reader: reader, Writer: connection}}, nil
}

func readAddress(reader io.Reader) (string, []byte, error) {
	var atyp [1]byte
	if _, err := io.ReadFull(reader, atyp[:]); err != nil {
		return "", nil, err
	}
	encoded := []byte{atyp[0]}
	var host string
	switch atyp[0] {
	case 1:
		raw := make([]byte, 4)
		if _, err := io.ReadFull(reader, raw); err != nil {
			return "", nil, err
		}
		encoded = append(encoded, raw...)
		host = net.IP(raw).String()
	case 4:
		raw := make([]byte, 16)
		if _, err := io.ReadFull(reader, raw); err != nil {
			return "", nil, err
		}
		encoded = append(encoded, raw...)
		host = net.IP(raw).String()
	case 3:
		var length [1]byte
		if _, err := io.ReadFull(reader, length[:]); err != nil {
			return "", nil, err
		}
		raw := make([]byte, int(length[0]))
		if _, err := io.ReadFull(reader, raw); err != nil {
			return "", nil, err
		}
		encoded = append(encoded, length[0])
		encoded = append(encoded, raw...)
		host = string(raw)
	default:
		return "", nil, fmt.Errorf("invalid address type")
	}
	var port [2]byte
	if _, err := io.ReadFull(reader, port[:]); err != nil {
		return "", nil, err
	}
	encoded = append(encoded, port[:]...)
	return fmt.Sprintf("%s:%d", host, binary.BigEndian.Uint16(port[:])), encoded, nil
}

func handle(connection net.Conn, password string) {
	defer connection.Close()
	key := make([]byte, 56)
	if _, err := io.ReadFull(connection, key); err != nil {
		return
	}
	digest := sha256.Sum224([]byte(password))
	expected := make([]byte, 56)
	hex.Encode(expected, digest[:])
	var crlf [2]byte
	if _, err := io.ReadFull(connection, crlf[:]); err != nil || !bytes.Equal(key, expected) {
		return
	}
	var command [1]byte
	if _, err := io.ReadFull(connection, command[:]); err != nil {
		return
	}
	destination, _, err := readAddress(connection)
	if err != nil {
		return
	}
	if _, err = io.ReadFull(connection, crlf[:]); err != nil {
		return
	}
	fmt.Printf("COMMAND %d %s\n", command[0], destination)
	if command[0] == 1 {
		_, _ = io.Copy(connection, connection)
		return
	}
	if command[0] != 3 {
		return
	}
	for {
		destination, encoded, err := readAddress(connection)
		if err != nil {
			return
		}
		var length [2]byte
		if _, err = io.ReadFull(connection, length[:]); err != nil {
			return
		}
		size := int(binary.BigEndian.Uint16(length[:]))
		if size > 8192 {
			return
		}
		if _, err = io.ReadFull(connection, crlf[:]); err != nil {
			return
		}
		payload := make([]byte, size)
		if _, err = io.ReadFull(connection, payload); err != nil {
			return
		}
		fmt.Printf("PACKET %s %d\n", destination, size)
		frame := append(encoded, length[:]...)
		frame = append(frame, '\r', '\n')
		frame = append(frame, payload...)
		if _, err = connection.Write(frame); err != nil {
			return
		}
	}
}

func serveGRPC(connection net.Conn, password, expectedHost, expectedPath, expectedUserAgent string) {
	server := &http2.Server{}
	server.ServeConn(connection, &http2.ServeConnOpts{Handler: http.HandlerFunc(func(writer http.ResponseWriter, request *http.Request) {
		if request.Method != http.MethodPost || request.Host != expectedHost || request.URL.RequestURI() != expectedPath || request.Header.Get("Content-Type") != "application/grpc" || request.Header.Get("User-Agent") != expectedUserAgent {
			http.Error(writer, "invalid gRPC Trojan request", http.StatusBadRequest)
			return
		}
		fmt.Printf("GRPC POST %s %s application/grpc %s\n", request.Host, request.URL.RequestURI(), request.Header.Get("User-Agent"))
		writer.Header().Set("Content-Type", "application/grpc")
		writer.WriteHeader(http.StatusOK)
		if flusher, ok := writer.(http.Flusher); ok {
			flusher.Flush()
		}
		handle(&gunConn{Conn: &h2StreamConn{Conn: connection, reader: request.Body, writer: writer}}, password)
	})})
}

func main() {
	listen := flag.String("listen", "127.0.0.1:0", "listen address")
	certificate := flag.String("tls-cert", "", "TLS certificate")
	privateKey := flag.String("tls-key", "", "TLS key")
	password := flag.String("password", "", "Trojan password")
	host := flag.String("host", "", "expected WS host")
	path := flag.String("path", "/", "expected WS path")
	header := flag.String("header", "", "expected X-Trojan-Phase")
	transport := flag.String("transport", "ws", "ws or grpc")
	userAgent := flag.String("user-agent", "grpc-go/1.36.0", "expected gRPC User-Agent")
	flag.Parse()
	pair, err := tls.LoadX509KeyPair(*certificate, *privateKey)
	if err != nil {
		panic(err)
	}
	nextProtocol := "http/1.1"
	if *transport == "grpc" {
		nextProtocol = "h2"
	}
	listener, err := tls.Listen("tcp", *listen, &tls.Config{Certificates: []tls.Certificate{pair}, NextProtos: []string{nextProtocol}, MinVersion: tls.VersionTLS12})
	if err != nil {
		panic(err)
	}
	defer listener.Close()
	for {
		connection, err := listener.Accept()
		if err != nil {
			fmt.Fprintln(os.Stderr, err)
			return
		}
		go func() {
			if *transport == "grpc" {
				serveGRPC(connection, *password, *host, *path, *userAgent)
				return
			}
			wrapped, err := upgrade(connection, *host, *path, *header)
			if err != nil {
				connection.Close()
				return
			}
			handle(wrapped, *password)
		}()
	}
}
