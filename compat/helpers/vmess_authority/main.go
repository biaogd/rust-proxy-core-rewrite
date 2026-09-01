package main

import (
	"bufio"
	"bytes"
	"context"
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
	"sync"
	"sync/atomic"
	"time"

	"github.com/gobwas/ws/wsutil"
	"github.com/metacubex/mihomo/transport/mekya"
	"github.com/metacubex/mihomo/transport/mkcp"
	vmess "github.com/metacubex/sing-vmess"
	"github.com/metacubex/sing-vmess/packetaddr"
	E "github.com/metacubex/sing/common/exceptions"
	M "github.com/metacubex/sing/common/metadata"
	N "github.com/metacubex/sing/common/network"
	"golang.org/x/net/http2"
)

type echoHandler struct {
	expectedHost     string
	expectedPort     uint
	packetMode       string
	streamBarrier    int64
	streamCount      atomic.Int64
	barrierReady     chan struct{}
	barrierOnce      sync.Once
	nextH2Connection atomic.Uint64
	output           sync.Mutex
}

type websocketConn struct {
	net.Conn
	reader io.ReadWriter
	buffer bytes.Reader
}

type bufferedReadWriter struct {
	io.Reader
	io.Writer
}

type readerConn struct {
	net.Conn
	reader io.Reader
}

type h2StreamConn struct {
	net.Conn
	reader io.Reader
	writer http.ResponseWriter
}

type gunConn struct {
	net.Conn
	remaining int
}

type h2FrameObservingConn struct {
	net.Conn
	handler     *echoHandler
	buffer      []byte
	prefaceRead bool
}

func (conn *h2FrameObservingConn) Read(payload []byte) (int, error) {
	read, err := conn.Conn.Read(payload)
	if read != 0 {
		conn.buffer = append(conn.buffer, payload[:read]...)
		conn.observeFrames()
	}
	return read, err
}

func (conn *h2FrameObservingConn) observeFrames() {
	if !conn.prefaceRead {
		const preface = "PRI * HTTP/2.0\r\n\r\nSM\r\n\r\n"
		if len(conn.buffer) < len(preface) {
			return
		}
		if string(conn.buffer[:len(preface)]) != preface {
			conn.buffer = nil
			return
		}
		conn.buffer = conn.buffer[len(preface):]
		conn.prefaceRead = true
	}
	for len(conn.buffer) >= 9 {
		length := int(conn.buffer[0])<<16 | int(conn.buffer[1])<<8 | int(conn.buffer[2])
		if len(conn.buffer) < 9+length {
			return
		}
		if conn.buffer[3] == 0x6 && conn.buffer[4]&0x1 == 0 {
			conn.handler.observe("H2-PING\n")
		}
		conn.buffer = conn.buffer[9+length:]
	}
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

func (conn *h2StreamConn) Close() error {
	if closer, ok := conn.reader.(io.Closer); ok {
		return closer.Close()
	}
	return nil
}

func readUvarint(reader io.Reader) (uint64, int, error) {
	var value uint64
	var one [1]byte
	for index := 0; index < 10; index++ {
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
	if payloadLength > uint64(^uint(0)>>1) ||
		uint64(grpcLength) != 1+uint64(varintLength)+payloadLength {
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

func (conn *readerConn) Read(payload []byte) (int, error) {
	return conn.reader.Read(payload)
}

type prefixedConn struct {
	net.Conn
	prefix bytes.Reader
}

func (conn *prefixedConn) Read(payload []byte) (int, error) {
	if conn.prefix.Len() != 0 {
		return conn.prefix.Read(payload)
	}
	return conn.Conn.Read(payload)
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

var _ vmess.Handler = (*echoHandler)(nil)

func (h *echoHandler) NewConnection(_ context.Context, conn net.Conn, metadata M.Metadata) error {
	defer conn.Close()
	destination := metadata.Destination
	host := destination.Fqdn
	if host == "" && destination.Addr.IsValid() {
		host = destination.Addr.String()
	}
	if h.expectedHost != "" && host != h.expectedHost {
		return fmt.Errorf("unexpected destination host %q", host)
	}
	if h.expectedPort != 0 && uint(destination.Port) != h.expectedPort {
		return fmt.Errorf("unexpected destination port %d", destination.Port)
	}
	h.output.Lock()
	fmt.Printf("CONNECT %s:%d\n", host, destination.Port)
	h.output.Unlock()
	if h.streamBarrier > 0 {
		if h.streamCount.Add(1) >= h.streamBarrier {
			h.barrierOnce.Do(func() { close(h.barrierReady) })
		}
		<-h.barrierReady
	}
	_, err := io.Copy(conn, conn)
	return err
}

func (h *echoHandler) NewPacketConnection(_ context.Context, conn N.PacketConn, _ M.Metadata) error {
	if h.packetMode == "reject" {
		return E.New("UDP is outside the selected authority mode")
	}
	defer conn.Close()
	packets, ok := conn.(net.PacketConn)
	if !ok {
		return E.New("VMess packet connection lacks net.PacketConn")
	}
	if h.packetMode == "packetaddr" {
		packets = packetaddr.NewConn(packets, M.Socksaddr{})
	}
	buffer := make([]byte, 65_535)
	for {
		length, address, err := packets.ReadFrom(buffer)
		if err != nil {
			return err
		}
		destination := M.SocksaddrFromNet(address)
		host := destination.Fqdn
		if host == "" && destination.Addr.IsValid() {
			host = destination.Addr.String()
		}
		h.output.Lock()
		fmt.Printf("PACKET %s %s:%d %d\n", h.packetMode, host, destination.Port, length)
		h.output.Unlock()
		if _, err := packets.WriteTo(buffer[:length], address); err != nil {
			return err
		}
	}
}

func (h *echoHandler) NewError(_ context.Context, err error) {
	h.output.Lock()
	fmt.Fprintln(os.Stderr, err)
	h.output.Unlock()
}

func (h *echoHandler) observe(format string, values ...any) {
	h.output.Lock()
	fmt.Printf(format, values...)
	h.output.Unlock()
}

func upgradeTransport(
	connection net.Conn,
	transport string,
	expectedHost string,
	expectedPath string,
	earlyDataHeader string,
	earlyDataPathPrefix string,
	preResponseBytes int,
) (net.Conn, string, string, string, int, error) {
	reader := bufio.NewReader(connection)
	request, err := http.ReadRequest(reader)
	if err != nil {
		return nil, "", "", "", 0, err
	}
	defer request.Body.Close()
	if request.Method != http.MethodGet || request.Header.Get("Upgrade") != "websocket" {
		return nil, "", "", "", 0, fmt.Errorf("invalid WebSocket upgrade")
	}
	if expectedHost != "" && request.Host != expectedHost {
		return nil, "", "", "", 0, fmt.Errorf("unexpected WebSocket host %q", request.Host)
	}
	earlyLocation := ""
	var earlyData []byte
	observedPath := request.URL.RequestURI()
	if earlyDataHeader != "" {
		encoded := request.Header.Get(earlyDataHeader)
		if encoded == "" {
			return nil, "", "", "", 0, fmt.Errorf("missing early-data header %q", earlyDataHeader)
		}
		earlyData, err = base64.RawURLEncoding.DecodeString(encoded)
		if err != nil {
			return nil, "", "", "", 0, fmt.Errorf("invalid early-data header: %w", err)
		}
		earlyLocation = earlyDataHeader
	} else if earlyDataPathPrefix != "" {
		if !strings.HasPrefix(request.URL.Path, earlyDataPathPrefix) {
			return nil, "", "", "", 0, fmt.Errorf("unexpected early-data path %q", request.URL.Path)
		}
		encoded := strings.TrimPrefix(request.URL.Path, earlyDataPathPrefix)
		if encoded == "" {
			return nil, "", "", "", 0, fmt.Errorf("missing path early data")
		}
		earlyData, err = base64.RawURLEncoding.DecodeString(encoded)
		if err != nil {
			return nil, "", "", "", 0, fmt.Errorf("invalid path early data: %w", err)
		}
		earlyLocation = "PATH"
		observedPath = earlyDataPathPrefix
		if request.URL.RawQuery != "" {
			observedPath += "?" + request.URL.RawQuery
		}
	}
	if expectedPath != "" && observedPath != expectedPath {
		return nil, "", "", "", 0, fmt.Errorf("unexpected WebSocket path %q", observedPath)
	}
	buffered := &readerConn{Conn: connection, reader: reader}
	reportedEarlyLength := len(earlyData)
	if preResponseBytes > 0 {
		prefix := make([]byte, preResponseBytes)
		if _, err := io.ReadFull(reader, prefix); err != nil {
			return nil, "", "", "", 0, fmt.Errorf("missing fast-open bytes: %w", err)
		}
		earlyData = append(earlyData, prefix...)
	}
	var wrapped net.Conn
	if transport == "upgrade" {
		if request.Header.Get("Sec-WebSocket-Key") != "" {
			return nil, "", "", "", 0, fmt.Errorf("raw Upgrade unexpectedly carried a WebSocket key")
		}
		_, err = fmt.Fprint(
			connection,
			"HTTP/1.1 101 Switching Protocols\r\nUpgrade: websocket\r\nConnection: Upgrade\r\n\r\n",
		)
		wrapped = buffered
	} else {
		key := request.Header.Get("Sec-WebSocket-Key")
		if key == "" {
			return nil, "", "", "", 0, fmt.Errorf("missing WebSocket key")
		}
		digest := sha1.Sum([]byte(key + "258EAFA5-E914-47DA-95CA-C5AB0DC85B11"))
		accept := base64.StdEncoding.EncodeToString(digest[:])
		_, err = fmt.Fprintf(
			connection,
			"HTTP/1.1 101 Switching Protocols\r\nUpgrade: websocket\r\nConnection: Upgrade\r\nSec-WebSocket-Accept: %s\r\n\r\n",
			accept,
		)
		wrapped = &websocketConn{
			Conn: connection,
			reader: bufferedReadWriter{
				Reader: reader,
				Writer: connection,
			},
		}
	}
	if err != nil {
		return nil, "", "", "", 0, err
	}
	if len(earlyData) != 0 {
		prefixed := &prefixedConn{Conn: wrapped}
		prefixed.prefix.Reset(earlyData)
		wrapped = prefixed
	}
	return wrapped, request.Host, observedPath, earlyLocation, reportedEarlyLength, nil
}

func httpTransport(
	connection net.Conn,
	handler *echoHandler,
	expectedMethod string,
	expectedHost string,
	expectedPath string,
	expectedHeader string,
) (net.Conn, error) {
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
	if expectedMethod != "" && request.Method != expectedMethod {
		return nil, fmt.Errorf("unexpected HTTP method %q", request.Method)
	}
	if expectedHost != "" && request.Host != expectedHost {
		return nil, fmt.Errorf("unexpected HTTP host %q", request.Host)
	}
	if expectedPath != "" && request.URL.RequestURI() != expectedPath {
		return nil, fmt.Errorf("unexpected HTTP path %q", request.URL.RequestURI())
	}
	headerValue := ""
	if expectedHeader != "" {
		name, value, found := strings.Cut(expectedHeader, "=")
		if !found || request.Header.Get(name) != value {
			return nil, fmt.Errorf("unexpected HTTP header %q", expectedHeader)
		}
		headerValue = name + "=" + request.Header.Get(name)
	}
	if _, err := fmt.Fprint(connection, "HTTP/1.1 200 OK\r\n\r\n"); err != nil {
		return nil, err
	}
	handler.observe(
		"HTTP %s %s %s %s BODY %d\n",
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

func serveH2(
	connection net.Conn,
	service *vmess.Service[string],
	handler *echoHandler,
	transport string,
	expectedHost string,
	expectedPath string,
	expectedUserAgent string,
) error {
	server := &http2.Server{}
	var connectionOnce sync.Once
	var connectionID uint64
	server.ServeConn(connection, &http2.ServeConnOpts{Handler: http.HandlerFunc(func(writer http.ResponseWriter, request *http.Request) {
		if transport == "grpc" {
			if request.Method != http.MethodPost ||
				(expectedHost != "" && request.Host != expectedHost) ||
				(expectedPath != "" && request.URL.RequestURI() != expectedPath) ||
				request.Header.Get("Content-Type") != "application/grpc" ||
				(expectedUserAgent != "" && request.Header.Get("User-Agent") != expectedUserAgent) {
				http.Error(writer, "invalid Gun VMess request", http.StatusBadRequest)
				return
			}
			connectionOnce.Do(func() {
				connectionID = handler.nextH2Connection.Add(1)
				handler.observe("GRPC-CONN %d\n", connectionID)
			})
			handler.observe(
				"GRPC POST %s %s application/grpc %s\n",
				request.Host,
				request.URL.RequestURI(),
				request.Header.Get("User-Agent"),
			)
			writer.Header().Set("Content-Type", "application/grpc")
		} else {
			if request.Method != http.MethodPut ||
				(expectedHost != "" && request.Host != expectedHost) ||
				(expectedPath != "" && request.URL.RequestURI() != expectedPath) ||
				request.Header.Get("Accept-Encoding") != "identity" {
				http.Error(writer, "invalid h2 VMess request", http.StatusBadRequest)
				return
			}
			handler.observe("H2 PUT %s %s identity\n", request.Host, request.URL.RequestURI())
		}
		writer.WriteHeader(http.StatusOK)
		if flusher, ok := writer.(http.Flusher); ok {
			flusher.Flush()
		}
		var stream net.Conn = &h2StreamConn{Conn: connection, reader: request.Body, writer: writer}
		if transport == "grpc" {
			stream = &gunConn{Conn: stream}
		}
		if err := service.NewConnection(request.Context(), stream, M.Metadata{}); err != nil {
			handler.NewError(request.Context(), err)
		}
	})})
	return nil
}

func serve(
	raw net.Conn,
	service *vmess.Service[string],
	handler *echoHandler,
	tlsConfig *tls.Config,
	transport string,
	expectedWSHost string,
	expectedWSPath string,
	earlyDataHeader string,
	earlyDataPathPrefix string,
	preResponseBytes int,
	expectedHTTPMethod string,
	expectedHTTPHost string,
	expectedHTTPPath string,
	expectedHTTPHeader string,
	expectedGrpcUserAgent string,
	observeH2Ping bool,
) {
	defer raw.Close()
	var connection net.Conn = raw
	if tlsConfig != nil {
		tlsConnection := tls.Server(raw, tlsConfig)
		if err := tlsConnection.Handshake(); err != nil {
			return
		}
		handler.observe("TLS %s\n", tlsConnection.ConnectionState().ServerName)
		if transport == "h2" || transport == "grpc" {
			handler.observe("ALPN %s\n", tlsConnection.ConnectionState().NegotiatedProtocol)
		}
		connection = tlsConnection
	} else if transport == "grpc" && observeH2Ping {
		connection = &h2FrameObservingConn{Conn: connection, handler: handler}
	}
	if transport == "h2" || transport == "grpc" {
		if err := serveH2(
			connection,
			service,
			handler,
			transport,
			expectedHTTPHost,
			expectedHTTPPath,
			expectedGrpcUserAgent,
		); err != nil {
			handler.NewError(context.Background(), err)
		}
		return
	}
	if transport == "http" {
		wrapped, err := httpTransport(
			connection,
			handler,
			expectedHTTPMethod,
			expectedHTTPHost,
			expectedHTTPPath,
			expectedHTTPHeader,
		)
		if err != nil {
			handler.NewError(context.Background(), err)
			return
		}
		connection = wrapped
	}
	if transport == "ws" || transport == "upgrade" {
		wrapped, host, path, earlyLocation, earlyLength, err := upgradeTransport(
			connection,
			transport,
			expectedWSHost,
			expectedWSPath,
			earlyDataHeader,
			earlyDataPathPrefix,
			preResponseBytes,
		)
		if err != nil {
			handler.NewError(context.Background(), err)
			return
		}
		label := "WS"
		if transport == "upgrade" {
			label = "UPGRADE"
		}
		handler.observe("%s %s %s\n", label, host, path)
		if earlyLength != 0 {
			handler.observe("EARLY %s %d\n", earlyLocation, earlyLength)
		}
		if preResponseBytes != 0 {
			handler.observe("FASTOPEN %d\n", preResponseBytes)
		}
		connection = wrapped
	}
	if err := service.NewConnection(context.Background(), connection, M.Metadata{}); err != nil {
		handler.NewError(context.Background(), err)
	}
}

func main() {
	listen := flag.String("listen", "127.0.0.1:0", "TCP listen address")
	uuid := flag.String("uuid", "", "accepted VMess UUID")
	alterID := flag.Int("alter-id", 0, "accepted VMess AlterID count")
	expectedHost := flag.String("expected-host", "", "expected target host")
	expectedPort := flag.Uint("expected-port", 0, "expected target port")
	packetMode := flag.String("packet-mode", "reject", "reject, standard, packetaddr, or xudp")
	transport := flag.String("transport", "tcp", "tcp, ws, upgrade, http, h2, grpc, mkcp, or mekya")
	mkcpSeed := flag.String("mkcp-seed", "", "optional mKCP AES-GCM seed")
	mkcpHeader := flag.String("mkcp-header", "", "optional mKCP camouflage header")
	mekyaALPN := flag.String("mekya-alpn", "h2", "Mekya TLS ALPN: h2 or http/1.1")
	tlsCertificate := flag.String("tls-cert", "", "optional TLS certificate")
	tlsPrivateKey := flag.String("tls-key", "", "optional TLS private key")
	expectedWSHost := flag.String("expected-ws-host", "", "expected WebSocket Host")
	expectedWSPath := flag.String("expected-ws-path", "", "expected WebSocket request target")
	earlyDataHeader := flag.String("early-data-header", "", "request header carrying base64url early data")
	earlyDataPathPrefix := flag.String("early-data-path-prefix", "", "URL path prefix before base64url early data")
	preResponseBytes := flag.Int("pre-response-bytes", 0, "bytes required before the Upgrade response")
	expectedHTTPMethod := flag.String("expected-http-method", "", "expected HTTP transport method")
	expectedHTTPHost := flag.String("expected-http-host", "", "expected HTTP transport authority")
	expectedHTTPPath := flag.String("expected-http-path", "", "expected HTTP transport request target")
	expectedHTTPHeader := flag.String("expected-http-header", "", "expected HTTP/1 header as name=value")
	expectedGrpcUserAgent := flag.String("expected-grpc-user-agent", "", "expected Gun User-Agent")
	streamBarrier := flag.Int64("stream-barrier", 0, "concurrent VMess streams required before echo")
	observeH2Ping := flag.Bool("observe-h2-ping", false, "report client HTTP/2 PING frames")
	flag.Parse()
	if *uuid == "" {
		fmt.Fprintln(os.Stderr, "missing -uuid")
		os.Exit(2)
	}

	switch *packetMode {
	case "reject", "standard", "packetaddr", "xudp":
	default:
		fmt.Fprintln(os.Stderr, "invalid -packet-mode")
		os.Exit(2)
	}
	if *transport != "tcp" && *transport != "ws" && *transport != "upgrade" && *transport != "http" && *transport != "h2" && *transport != "grpc" && *transport != "mkcp" && *transport != "mekya" {
		fmt.Fprintln(os.Stderr, "invalid -transport")
		os.Exit(2)
	}
	if *mekyaALPN != "h2" && *mekyaALPN != "http/1.1" {
		fmt.Fprintln(os.Stderr, "invalid -mekya-alpn")
		os.Exit(2)
	}
	if (*tlsCertificate == "") != (*tlsPrivateKey == "") {
		fmt.Fprintln(os.Stderr, "-tls-cert and -tls-key must be paired")
		os.Exit(2)
	}
	if *preResponseBytes < 0 || (*transport != "upgrade" && *preResponseBytes != 0) {
		fmt.Fprintln(os.Stderr, "invalid -pre-response-bytes")
		os.Exit(2)
	}
	if *streamBarrier < 0 || (*transport != "grpc" && *streamBarrier != 0) {
		fmt.Fprintln(os.Stderr, "invalid -stream-barrier")
		os.Exit(2)
	}
	if *observeH2Ping && *transport != "grpc" {
		fmt.Fprintln(os.Stderr, "-observe-h2-ping requires grpc transport")
		os.Exit(2)
	}
	var tlsConfig *tls.Config
	if *tlsCertificate != "" {
		keyPair, err := tls.LoadX509KeyPair(*tlsCertificate, *tlsPrivateKey)
		if err != nil {
			fmt.Fprintln(os.Stderr, err)
			os.Exit(1)
		}
		nextProtocol := "http/1.1"
		if *transport == "h2" || *transport == "grpc" {
			nextProtocol = "h2"
		} else if *transport == "mekya" {
			nextProtocol = *mekyaALPN
		}
		tlsConfig = &tls.Config{
			Certificates: []tls.Certificate{keyPair},
			NextProtos:   []string{nextProtocol},
			MinVersion:   tls.VersionTLS12,
		}
	}
	handler := &echoHandler{
		expectedHost:  *expectedHost,
		expectedPort:  *expectedPort,
		packetMode:    *packetMode,
		streamBarrier: *streamBarrier,
		barrierReady:  make(chan struct{}),
	}
	service := vmess.NewService[string](handler, vmess.ServiceWithDisableHeaderProtection())
	if err := service.UpdateUsers([]string{"phase6d"}, []string{*uuid}, []int{*alterID}); err != nil {
		fmt.Fprintln(os.Stderr, err)
		os.Exit(1)
	}
	if err := service.Start(); err != nil {
		fmt.Fprintln(os.Stderr, err)
		os.Exit(1)
	}
	defer service.Close()

	var listener net.Listener
	var err error
	serveTLSConfig := tlsConfig
	switch *transport {
	case "mkcp":
		packetConn, err := net.ListenPacket("udp", *listen)
		if err != nil {
			fmt.Fprintln(os.Stderr, err)
			os.Exit(1)
		}
		listener, err = mkcp.Listen(context.Background(), packetConn, mkcp.Config{Seed: *mkcpSeed, Header: *mkcpHeader})
		if err != nil {
			_ = packetConn.Close()
			fmt.Fprintln(os.Stderr, err)
			os.Exit(1)
		}
	case "mekya":
		outer, err := net.Listen("tcp", *listen)
		if err != nil {
			fmt.Fprintln(os.Stderr, err)
			os.Exit(1)
		}
		if tlsConfig != nil {
			outer = tls.NewListener(outer, tlsConfig)
		}
		listener, err = mekya.Listen(context.Background(), outer, mekya.Config{
			KCP:                            mkcp.Config{Seed: *mkcpSeed, Header: *mkcpHeader},
			H2PoolSize:                     2,
			MaxWriteDelay:                  20,
			MaxRequestSize:                 96000,
			PollingIntervalInitial:         20,
			MaxWriteSize:                   1 << 20,
			MaxWriteDurationMs:             int((5 * time.Second) / time.Millisecond),
			MaxSimultaneousWriteConnection: 16,
			PacketWritingBuffer:            1024,
		})
		if err != nil {
			_ = outer.Close()
			fmt.Fprintln(os.Stderr, err)
			os.Exit(1)
		}
		serveTLSConfig = nil
	default:
		listener, err = net.Listen("tcp", *listen)
		if err != nil {
			fmt.Fprintln(os.Stderr, err)
			os.Exit(1)
		}
	}
	defer listener.Close()
	fmt.Printf("READY %s\n", listener.Addr())
	for {
		conn, err := listener.Accept()
		if err != nil {
			fmt.Fprintln(os.Stderr, err)
			return
		}
		go serve(
			conn,
			service,
			handler,
			serveTLSConfig,
			*transport,
			*expectedWSHost,
			*expectedWSPath,
			*earlyDataHeader,
			*earlyDataPathPrefix,
			*preResponseBytes,
			*expectedHTTPMethod,
			*expectedHTTPHost,
			*expectedHTTPPath,
			*expectedHTTPHeader,
			*expectedGrpcUserAgent,
			*observeH2Ping,
		)
	}
}
