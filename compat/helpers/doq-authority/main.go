package main

import (
	"context"
	"encoding/binary"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net"
	"os"
	"sync"
	"sync/atomic"
	"time"

	"github.com/metacubex/quic-go"
	"github.com/metacubex/tls"
)

type mode string

const (
	modeAnswer mode = "answer"
	modeEmpty  mode = "empty"
	modeDelay  mode = "delay"
	modeRetry  mode = "retry-twice"
)

type handshakeObservation struct {
	ALPN       string `json:"alpn"`
	ServerName string `json:"server_name"`
	Used0RTT   bool   `json:"used_0rtt"`
	DidResume  bool   `json:"did_resume"`
}

type frameObservation struct {
	ALPN           string `json:"alpn"`
	ServerName     string `json:"server_name"`
	DeclaredLength int    `json:"declared_length"`
	PayloadLength  int    `json:"payload_length"`
	TrailingBytes  int    `json:"trailing_bytes"`
	DNSIDZero      bool   `json:"dns_id_zero"`
	FINReceived    bool   `json:"fin_received"`
	Valid          bool   `json:"valid"`
}

type observation struct {
	Connections       int                    `json:"connections"`
	ActiveConnections int                    `json:"active_connections"`
	Streams           int                    `json:"streams"`
	ActiveStreams     int                    `json:"active_streams"`
	MaxInFlight       int                    `json:"max_in_flight"`
	Queries           int                    `json:"queries"`
	Handshakes        []handshakeObservation `json:"handshakes"`
	Frames            []frameObservation     `json:"frames"`
}

type state struct {
	mu       sync.Mutex
	output   string
	mode     mode
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

func main() {
	if len(os.Args) != 5 {
		fatal(errors.New("usage: doq-authority CERT KEY OUTPUT MODE"))
	}
	selected := mode(os.Args[4])
	if selected != modeAnswer && selected != modeEmpty && selected != modeDelay && selected != modeRetry {
		fatal(errors.New("invalid authority mode"))
	}
	certificate, err := tls.LoadX509KeyPair(os.Args[1], os.Args[2])
	if err != nil {
		fatal(err)
	}
	packet, err := net.ListenPacket("udp", "127.0.0.1:0")
	if err != nil {
		fatal(err)
	}
	listener, err := quic.Listen(packet, &tls.Config{
		Certificates: []tls.Certificate{certificate},
		NextProtos:   []string{"doq"},
	}, &quic.Config{})
	if err != nil {
		fatal(err)
	}
	shared := &state{
		output: os.Args[3],
		mode:   selected,
		value: observation{
			Frames:     []frameObservation{},
			Handshakes: []handshakeObservation{},
		},
	}
	shared.update(func(*observation) {})
	fmt.Println(packet.LocalAddr().(*net.UDPAddr).Port)
	for {
		connection, err := listener.Accept(context.Background())
		if err != nil {
			fatal(err)
		}
		connectionState := connection.ConnectionState()
		shared.update(func(value *observation) {
			value.Connections++
			value.ActiveConnections++
			value.Handshakes = append(value.Handshakes, handshakeObservation{
				ALPN:       connectionState.TLS.NegotiatedProtocol,
				ServerName: connectionState.TLS.ServerName,
				Used0RTT:   connectionState.Used0RTT,
				DidResume:  connectionState.TLS.DidResume,
			})
		})
		go serveConnection(connection, shared)
	}
}

func serveConnection(connection *quic.Conn, shared *state) {
	defer shared.update(func(value *observation) { value.ActiveConnections-- })
	connectionState := connection.ConnectionState()
	for {
		stream, err := connection.AcceptStream(context.Background())
		if err != nil {
			return
		}
		shared.update(func(value *observation) { value.Streams++ })
		go serveStream(connection, stream, connectionState.TLS.NegotiatedProtocol, connectionState.TLS.ServerName, shared)
	}
}

func serveStream(connection *quic.Conn, stream *quic.Stream, alpn, serverName string, shared *state) {
	request, readErr := io.ReadAll(stream)
	declaredLength := 0
	payloadLength := 0
	trailingBytes := 0
	dnsIDZero := false
	var query []byte
	if len(request) >= 2 {
		declaredLength = int(binary.BigEndian.Uint16(request[:2]))
		available := len(request) - 2
		payloadLength = declaredLength
		if payloadLength > available {
			payloadLength = available
		}
		trailingBytes = available - payloadLength
		query = request[2 : 2+payloadLength]
		dnsIDZero = len(query) >= 2 && query[0] == 0 && query[1] == 0
	}
	valid := readErr == nil && declaredLength >= 12 && payloadLength == declaredLength && trailingBytes == 0 && dnsIDZero
	shared.update(func(value *observation) {
		value.Frames = append(value.Frames, frameObservation{
			ALPN: alpn, ServerName: serverName, DeclaredLength: declaredLength,
			PayloadLength: payloadLength, TrailingBytes: trailingBytes,
			DNSIDZero: dnsIDZero, FINReceived: readErr == nil, Valid: valid,
		})
		if valid {
			value.Queries++
			value.ActiveStreams++
			if value.ActiveStreams > value.MaxInFlight {
				value.MaxInFlight = value.ActiveStreams
			}
		}
	})
	if !valid {
		stream.CancelWrite(1)
		return
	}
	defer shared.update(func(value *observation) { value.ActiveStreams-- })
	sequence := shared.sequence.Add(1)
	if shared.mode == modeRetry && (sequence == 2 || sequence == 3) {
		_ = connection.CloseWithError(0, "Phase 4E18 retry")
		return
	}
	if shared.mode == modeDelay {
		time.Sleep(250 * time.Millisecond)
	}
	if shared.mode == modeEmpty {
		_, _ = stream.Write([]byte{0, 0})
		_ = stream.Close()
		return
	}
	response, err := answer(query)
	if err != nil {
		stream.CancelWrite(1)
		return
	}
	framed := make([]byte, 2+len(response))
	binary.BigEndian.PutUint16(framed, uint16(len(response)))
	copy(framed[2:], response)
	_, _ = stream.Write(framed)
	_ = stream.Close()
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
