package main

import (
	"context"
	"encoding/base64"
	"encoding/binary"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net"
	"os"
	"sort"
	"sync"
	"sync/atomic"
	"time"

	"github.com/metacubex/http"
	"github.com/metacubex/quic-go"
	"github.com/metacubex/quic-go/http3"
	"github.com/metacubex/tls"
)

type mode string

const (
	modeH3Only     mode = "h3-only"
	modeH3Faster   mode = "h3-faster"
	modeH2Only     mode = "h2-only"
	modeCloseFirst mode = "close-first"
)

type requestObservation struct {
	Protocol                 string   `json:"protocol"`
	Method                   string   `json:"method"`
	AuthorityMatchesListener bool     `json:"authority_matches_listener"`
	Path                     string   `json:"path"`
	QueryKeys                []string `json:"query_keys"`
	Accept                   *string  `json:"accept"`
	DNSIDZero                bool     `json:"dns_id_zero"`
	RequestBodyEmpty         bool     `json:"request_body_empty"`
	Used0RTT                 bool     `json:"used_0rtt"`
	Valid                    bool     `json:"valid"`
}

type observation struct {
	H2Connections int                  `json:"h2_connections"`
	H3Connections int                  `json:"h3_connections"`
	Queries       int                  `json:"queries"`
	Requests      []requestObservation `json:"requests"`
}

type state struct {
	mu       sync.Mutex
	output   string
	listener string
	value    observation
	sequence atomic.Int64
}

func (s *state) update(fn func(*observation)) {
	s.mu.Lock()
	defer s.mu.Unlock()
	fn(&s.value)
	encoded, err := json.MarshalIndent(s.value, "", "  ")
	if err != nil {
		panic(err)
	}
	if err := os.WriteFile(s.output, encoded, 0o600); err != nil {
		panic(err)
	}
}

type connectionContextKey struct{}

type delayedListener struct {
	net.Listener
	delay time.Duration
}

func (l delayedListener) Accept() (net.Conn, error) {
	connection, err := l.Listener.Accept()
	if err != nil {
		return nil, err
	}
	if l.delay > 0 {
		time.Sleep(l.delay)
	}
	return connection, nil
}

func main() {
	if len(os.Args) != 5 {
		fatal(errors.New("usage: h3-authority CERT KEY OUTPUT MODE"))
	}
	selected := mode(os.Args[4])
	if selected != modeH3Only && selected != modeH3Faster && selected != modeH2Only && selected != modeCloseFirst {
		fatal(errors.New("invalid authority mode"))
	}
	certificate, err := tls.LoadX509KeyPair(os.Args[1], os.Args[2])
	if err != nil {
		fatal(err)
	}

	shared := &state{output: os.Args[3]}
	shared.update(func(*observation) {})
	if selected == modeH2Only {
		listener, err := net.Listen("tcp", "127.0.0.1:0")
		if err != nil {
			fatal(err)
		}
		shared.listener = listener.Addr().String()
		fmt.Println(listener.Addr().(*net.TCPAddr).Port)
		serveH2(listener, shared, os.Args[1], os.Args[2], 0)
		return
	}

	packet, err := net.ListenPacket("udp", "127.0.0.1:0")
	if err != nil {
		fatal(err)
	}
	address := packet.LocalAddr().String()
	shared.listener = address
	handler := handler(shared, selected == modeCloseFirst)
	h3Server := &http3.Server{
		Handler:    handler,
		TLSConfig:  &tls.Config{Certificates: []tls.Certificate{certificate}},
		QUICConfig: &quic.Config{Allow0RTT: true},
		ConnContext: func(ctx context.Context, connection *quic.Conn) context.Context {
			shared.update(func(value *observation) { value.H3Connections++ })
			return context.WithValue(ctx, connectionContextKey{}, connection)
		},
	}
	if selected == modeH3Faster {
		listener, err := net.Listen("tcp", address)
		if err != nil {
			fatal(err)
		}
		go serveH2(listener, shared, os.Args[1], os.Args[2], 400*time.Millisecond)
	}
	fmt.Println(packet.LocalAddr().(*net.UDPAddr).Port)
	if err := h3Server.Serve(packet); err != nil {
		fatal(err)
	}
}

func serveH2(listener net.Listener, shared *state, certPath, keyPath string, delay time.Duration) {
	server := &http.Server{
		Handler: handler(shared, false),
		ConnState: func(_ net.Conn, connectionState http.ConnState) {
			if connectionState == http.StateNew {
				shared.update(func(value *observation) { value.H2Connections++ })
			}
		},
	}
	if err := server.ServeTLS(delayedListener{Listener: listener, delay: delay}, certPath, keyPath); err != nil {
		fatal(err)
	}
}

func handler(shared *state, closeFirst bool) http.Handler {
	return http.HandlerFunc(func(writer http.ResponseWriter, request *http.Request) {
		body, _ := io.ReadAll(request.Body)
		queryKeys := make([]string, 0)
		for key := range request.URL.Query() {
			queryKeys = append(queryKeys, key)
		}
		sort.Strings(queryKeys)
		encoded := request.URL.Query().Get("dns")
		query, _ := base64.RawURLEncoding.DecodeString(encoded)
		acceptValue := request.Header.Get("Accept")
		var accept *string
		if acceptValue != "" {
			accept = &acceptValue
		}
		protocol := "h2"
		used0RTT := false
		var h3Connection *quic.Conn
		if request.ProtoMajor == 3 {
			protocol = "h3"
			h3Connection, _ = request.Context().Value(connectionContextKey{}).(*quic.Conn)
			if h3Connection != nil {
				used0RTT = h3Connection.ConnectionState().Used0RTT
			}
		}
		valid := request.Method == http.MethodGet &&
			request.Host == shared.listener &&
			request.URL.Path == "/dns-query" &&
			len(queryKeys) == 1 && queryKeys[0] == "dns" &&
			acceptValue == "application/dns-message" &&
			len(query) >= 12 && query[0] == 0 && query[1] == 0 && len(body) == 0
		shared.update(func(value *observation) {
			value.Requests = append(value.Requests, requestObservation{
				Protocol: protocol, Method: request.Method,
				AuthorityMatchesListener: request.Host == shared.listener,
				Path:                     request.URL.Path, QueryKeys: queryKeys, Accept: accept,
				DNSIDZero:        len(query) >= 2 && query[0] == 0 && query[1] == 0,
				RequestBodyEmpty: len(body) == 0, Used0RTT: used0RTT, Valid: valid,
			})
		})
		if !valid {
			writer.WriteHeader(http.StatusBadRequest)
			return
		}
		response, err := answer(query)
		if err != nil {
			writer.WriteHeader(http.StatusBadRequest)
			return
		}
		shared.update(func(value *observation) { value.Queries++ })
		writer.Header().Set("Content-Type", "application/dns-message")
		writer.WriteHeader(http.StatusOK)
		_, _ = writer.Write(response)
		if flusher, ok := writer.(http.Flusher); ok {
			flusher.Flush()
		}
		if closeFirst && shared.sequence.Add(1) == 1 && h3Connection != nil {
			go func() {
				time.Sleep(500 * time.Millisecond)
				_ = h3Connection.CloseWithError(0, "phase4e16 reconnect")
			}()
		}
	})
}

func answer(query []byte) ([]byte, error) {
	questionEnd, err := dnsQuestionEnd(query)
	if err != nil {
		return nil, err
	}
	response := append([]byte{}, query[:2]...)
	response = append(response, 0x81, 0x80, 0x00, 0x01, 0x00, 0x01, 0x00, 0x00, 0x00, 0x00)
	response = append(response, query[12:questionEnd]...)
	response = append(response,
		0xc0, 0x0c, 0x00, 0x01, 0x00, 0x01,
		0x00, 0x00, 0x00, 0x1e, 0x00, 0x04, 192, 0, 2, 42,
	)
	return response, nil
}

func dnsQuestionEnd(message []byte) (int, error) {
	if len(message) < 12 || binary.BigEndian.Uint16(message[4:6]) != 1 {
		return 0, errors.New("invalid DNS question")
	}
	for offset := 12; ; {
		if offset >= len(message) {
			return 0, errors.New("truncated DNS name")
		}
		length := int(message[offset])
		offset++
		if length == 0 {
			if offset+4 > len(message) {
				return 0, errors.New("truncated DNS question")
			}
			return offset + 4, nil
		}
		if length > 63 || offset+length > len(message) {
			return 0, errors.New("invalid DNS label")
		}
		offset += length
	}
}

func fatal(err error) {
	fmt.Fprintln(os.Stderr, err)
	os.Exit(1)
}
