package main

import (
	"bufio"
	"bytes"
	"crypto/sha1"
	"crypto/tls"
	"encoding/base64"
	"encoding/binary"
	"flag"
	"fmt"
	"io"
	"net"
	"net/http"
	"os"
	"strings"

	"github.com/gobwas/ws/wsutil"
	"github.com/gofrs/uuid/v5"
	"golang.org/x/net/http2"
)

type authority struct {
	expectedWSHost     string
	expectedWSPath     string
	expectedHeader     string
	expectedHTTPMethod string
	expectedHTTPHost   string
	expectedHTTPPath   string
	expectedHTTPHeader string
}

type websocketConn struct {
	net.Conn
	reader io.ReadWriter
	buffer bytes.Reader
}

type readerConn struct {
	net.Conn
	reader io.Reader
}

type bufferedReadWriter struct {
	io.Reader
	io.Writer
}

type prefixedConn struct {
	net.Conn
	prefix bytes.Reader
}

type h2StreamConn struct {
	net.Conn
	reader io.Reader
	writer http.ResponseWriter
}

func (conn *prefixedConn) Read(payload []byte) (int, error) {
	if conn.prefix.Len() != 0 {
		return conn.prefix.Read(payload)
	}
	return conn.Conn.Read(payload)
}

func (conn *h2StreamConn) Read(payload []byte) (int, error) {
	return conn.reader.Read(payload)
}

func (conn *h2StreamConn) Write(payload []byte) (int, error) {
	written, err := conn.writer.Write(payload)
	if flusher, ok := conn.writer.(http.Flusher); ok {
		flusher.Flush()
	}
	return written, err
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

func (a *authority) observe(format string, values ...any) {
	fmt.Printf("%s\n", fmt.Sprintf(format, values...))
}

func (a *authority) upgradeTransport(connection net.Conn) (net.Conn, string, string, error) {
	reader := bufio.NewReader(connection)
	request, err := http.ReadRequest(reader)
	if err != nil {
		return nil, "", "", err
	}
	defer request.Body.Close()
	if request.Method != http.MethodGet || request.Header.Get("Upgrade") != "websocket" {
		return nil, "", "", fmt.Errorf("invalid WebSocket upgrade")
	}
	if a.expectedWSHost != "" && request.Host != a.expectedWSHost {
		return nil, "", "", fmt.Errorf("unexpected WebSocket host %q", request.Host)
	}
	if a.expectedWSPath != "" && request.URL.RequestURI() != a.expectedWSPath {
		return nil, "", "", fmt.Errorf("unexpected WebSocket path %q", request.URL.RequestURI())
	}
	if a.expectedHeader != "" {
		name, value, ok := strings.Cut(a.expectedHeader, "=")
		if !ok || request.Header.Get(name) != value {
			return nil, "", "", fmt.Errorf("missing custom header %q", a.expectedHeader)
		}
		a.observe("HEADER %s=%s", name, value)
	}
	key := request.Header.Get("Sec-WebSocket-Key")
	if key == "" {
		return nil, "", "", fmt.Errorf("missing WebSocket key")
	}
	digest := sha1.Sum([]byte(key + "258EAFA5-E914-47DA-95CA-C5AB0DC85B11"))
	accept := base64.StdEncoding.EncodeToString(digest[:])
	if _, err = fmt.Fprintf(
		connection,
		"HTTP/1.1 101 Switching Protocols\r\nUpgrade: websocket\r\nConnection: Upgrade\r\nSec-WebSocket-Accept: %s\r\n\r\n",
		accept,
	); err != nil {
		return nil, "", "", err
	}
	return &websocketConn{
		Conn: connection,
		reader: bufferedReadWriter{
			Reader: reader,
			Writer: connection,
		},
	}, request.Host, request.URL.RequestURI(), nil
}

func (a *authority) httpTransport(connection net.Conn) (net.Conn, error) {
	reader := bufio.NewReader(connection)
	request, err := http.ReadRequest(reader)
	if err != nil {
		return nil, err
	}
	body, err := io.ReadAll(request.Body)
	_ = request.Body.Close()
	if err != nil {
		return nil, err
	}
	if a.expectedHTTPMethod != "" && request.Method != a.expectedHTTPMethod {
		return nil, fmt.Errorf("unexpected HTTP method %q", request.Method)
	}
	if a.expectedHTTPHost != "" && request.Host != a.expectedHTTPHost {
		return nil, fmt.Errorf("unexpected HTTP host %q", request.Host)
	}
	if a.expectedHTTPPath != "" && request.URL.RequestURI() != a.expectedHTTPPath {
		return nil, fmt.Errorf("unexpected HTTP path %q", request.URL.RequestURI())
	}
	headerValue := ""
	if a.expectedHTTPHeader != "" {
		name, value, found := strings.Cut(a.expectedHTTPHeader, "=")
		if !found || request.Header.Get(name) != value {
			return nil, fmt.Errorf("unexpected HTTP header %q", a.expectedHTTPHeader)
		}
		headerValue = name + "=" + request.Header.Get(name)
	}
	if _, err := fmt.Fprint(connection, "HTTP/1.1 200 OK\r\n\r\n"); err != nil {
		return nil, err
	}
	a.observe(
		"HTTP %s %s %s %s BODY %d",
		request.Method,
		request.Host,
		request.URL.RequestURI(),
		headerValue,
		len(body),
	)
	buffered := &readerConn{Conn: connection, reader: reader}
	prefixed := &prefixedConn{Conn: buffered}
	prefixed.prefix.Reset(body)
	return prefixed, nil
}

func (a *authority) serveH2(connection net.Conn) error {
	server := &http2.Server{}
	server.ServeConn(connection, &http2.ServeConnOpts{Handler: http.HandlerFunc(func(writer http.ResponseWriter, request *http.Request) {
		if request.Method != http.MethodPut ||
			(a.expectedHTTPHost != "" && request.Host != a.expectedHTTPHost) ||
			(a.expectedHTTPPath != "" && request.URL.RequestURI() != a.expectedHTTPPath) ||
			request.Header.Get("Accept-Encoding") != "identity" {
			http.Error(writer, "invalid h2 VLESS request", http.StatusBadRequest)
			return
		}
		a.observe("H2 PUT %s %s identity", request.Host, request.URL.RequestURI())
		writer.WriteHeader(http.StatusOK)
		if flusher, ok := writer.(http.Flusher); ok {
			flusher.Flush()
		}
		stream := &h2StreamConn{Conn: connection, reader: request.Body, writer: writer}
		a.handle(stream)
	})})
	return nil
}

func readExact(reader io.Reader, size int) ([]byte, error) {
	buffer := make([]byte, size)
	if _, err := io.ReadFull(reader, buffer); err != nil {
		return nil, err
	}
	return buffer, nil
}

func (a *authority) handle(connection net.Conn) {
	defer connection.Close()
	version, err := readExact(connection, 1)
	if err != nil {
		return
	}
	user, err := readExact(connection, 16)
	if err != nil {
		return
	}
	_ = user
	addonSize, err := readExact(connection, 1)
	if err != nil {
		return
	}
	addons, err := readExact(connection, int(addonSize[0]))
	if err != nil {
		return
	}
	command, err := readExact(connection, 1)
	if err != nil {
		return
	}
	portBytes, err := readExact(connection, 2)
	if err != nil {
		return
	}
	addressType, err := readExact(connection, 1)
	if err != nil {
		return
	}
	var host string
	switch addressType[0] {
	case 1:
		packed, err := readExact(connection, 4)
		if err != nil {
			return
		}
		host = net.IP(packed).String()
	case 3:
		packed, err := readExact(connection, 16)
		if err != nil {
			return
		}
		host = net.IP(packed).String()
	case 2:
		length, err := readExact(connection, 1)
		if err != nil {
			return
		}
		rawHost, err := readExact(connection, int(length[0]))
		if err != nil {
			return
		}
		host = string(rawHost)
	default:
		return
	}
	port := binary.BigEndian.Uint16(portBytes)
	a.observe("CONNECT %s:%d", host, port)
	if version[0] != 0 || command[0] != 1 || len(addons) != 0 {
		return
	}
	if _, err := connection.Write([]byte{0, 0}); err != nil {
		return
	}
	if host == "bad-handshake.phase6e" {
		_, _ = connection.Write([]byte{1, 0})
		return
	}
	_, _ = io.Copy(connection, connection)
}

func (a *authority) serve(connection net.Conn, transport string, tlsEnabled bool) {
	if tlsEnabled {
		if tlsConnection, ok := connection.(*tls.Conn); ok {
			if err := tlsConnection.Handshake(); err != nil {
				return
			}
			state := tlsConnection.ConnectionState()
			if state.ServerName != "" {
				a.observe("TLS %s", state.ServerName)
			} else {
				a.observe("TLS <none>")
			}
			if transport == "h2" {
				a.observe("ALPN %s", state.NegotiatedProtocol)
			}
		}
	}
	switch transport {
	case "h2":
		if err := a.serveH2(connection); err != nil {
			fmt.Fprintln(os.Stderr, err)
		}
		return
	case "http":
		wrapped, err := a.httpTransport(connection)
		if err != nil {
			fmt.Fprintln(os.Stderr, err)
			return
		}
		connection = wrapped
	case "ws":
		wrapped, host, path, err := a.upgradeTransport(connection)
		if err != nil {
			fmt.Fprintln(os.Stderr, err)
			return
		}
		a.observe("WS %s %s", host, path)
		connection = wrapped
	}
	a.handle(connection)
}

func main() {
	listen := flag.String("listen", "127.0.0.1:0", "TCP listen address")
	uuidText := flag.String("uuid", "", "accepted VLESS UUID")
	transport := flag.String("transport", "tcp", "tcp, ws, http, or h2")
	tlsCertificate := flag.String("tls-cert", "", "optional TLS certificate")
	tlsPrivateKey := flag.String("tls-key", "", "optional TLS private key")
	expectedWSHost := flag.String("expected-ws-host", "", "expected WebSocket Host")
	expectedWSPath := flag.String("expected-ws-path", "", "expected WebSocket request target")
	expectedHeader := flag.String("expected-header", "", "expected custom header as name=value")
	expectedHTTPMethod := flag.String("expected-http-method", "", "expected HTTP transport method")
	expectedHTTPHost := flag.String("expected-http-host", "", "expected HTTP transport authority")
	expectedHTTPPath := flag.String("expected-http-path", "", "expected HTTP transport request target")
	expectedHTTPHeader := flag.String("expected-http-header", "", "expected HTTP/1 header as name=value")
	flag.Parse()
	if *uuidText == "" {
		fmt.Fprintln(os.Stderr, "missing -uuid")
		os.Exit(2)
	}
	switch *transport {
	case "tcp", "ws", "http", "h2":
	default:
		fmt.Fprintln(os.Stderr, "invalid -transport")
		os.Exit(2)
	}
	if (*tlsCertificate == "") != (*tlsPrivateKey == "") {
		fmt.Fprintln(os.Stderr, "-tls-cert and -tls-key must be paired")
		os.Exit(2)
	}
	if _, err := uuid.FromString(*uuidText); err != nil {
		_ = uuid.NewV5(uuid.Nil, *uuidText)
	}

	auth := &authority{
		expectedWSHost:     *expectedWSHost,
		expectedWSPath:     *expectedWSPath,
		expectedHeader:     *expectedHeader,
		expectedHTTPMethod: *expectedHTTPMethod,
		expectedHTTPHost:   *expectedHTTPHost,
		expectedHTTPPath:   *expectedHTTPPath,
		expectedHTTPHeader: *expectedHTTPHeader,
	}
	listener, err := net.Listen("tcp", *listen)
	if err != nil {
		fmt.Fprintln(os.Stderr, err)
		os.Exit(1)
	}
	defer listener.Close()
	fmt.Printf("READY %s\n", listener.Addr().String())
	tlsEnabled := *tlsCertificate != ""
	if tlsEnabled {
		certificate, err := tls.LoadX509KeyPair(*tlsCertificate, *tlsPrivateKey)
		if err != nil {
			fmt.Fprintln(os.Stderr, err)
			os.Exit(1)
		}
		nextProtocol := "http/1.1"
		if *transport == "h2" {
			nextProtocol = "h2"
		}
		config := &tls.Config{
			Certificates: []tls.Certificate{certificate},
			NextProtos:   []string{nextProtocol},
			MinVersion:   tls.VersionTLS12,
		}
		listener = tls.NewListener(listener, config)
	}
	for {
		connection, err := listener.Accept()
		if err != nil {
			fmt.Fprintln(os.Stderr, err)
			return
		}
		go auth.serve(connection, *transport, tlsEnabled)
	}
}
