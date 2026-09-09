// Command ssr_stream_vector prints a deterministic SSR origin/plain stream
// ciphertext vector for Go↔Rust encode/decode contract checks (SSR-A).
//
// Usage:
//
//	go run ./compat/helpers/ssr_stream_vector -password p -cipher aes-128-cfb -iv hex -payload text
package main

import (
	"crypto/md5"
	"encoding/hex"
	"flag"
	"fmt"
	"os"

	"github.com/metacubex/mihomo/transport/shadowsocks/shadowstream"
)

func kdf(password string, keyLen int) []byte {
	var b, prev []byte
	h := md5.New()
	for len(b) < keyLen {
		h.Write(prev)
		h.Write([]byte(password))
		b = h.Sum(b)
		prev = b[len(b)-h.Size():]
		h.Reset()
	}
	return b[:keyLen]
}

func main() {
	password := flag.String("password", "phase7a-ssr-password", "")
	cipherName := flag.String("cipher", "aes-128-cfb", "")
	ivHex := flag.String("iv", "000102030405060708090a0b0c0d0e0f", "")
	payload := flag.String("payload", "ssr-contract", "")
	flag.Parse()

	iv, err := hex.DecodeString(*ivHex)
	if err != nil {
		fmt.Fprintln(os.Stderr, err)
		os.Exit(2)
	}
	var keyLen int
	var ciph shadowstream.Cipher
	switch *cipherName {
	case "aes-128-cfb":
		keyLen = 16
		ciph, err = shadowstream.AESCFB(kdf(*password, keyLen))
	case "aes-256-cfb":
		keyLen = 32
		ciph, err = shadowstream.AESCFB(kdf(*password, keyLen))
	default:
		fmt.Fprintln(os.Stderr, "unsupported cipher")
		os.Exit(2)
	}
	if err != nil {
		fmt.Fprintln(os.Stderr, err)
		os.Exit(2)
	}
	if len(iv) != ciph.IVSize() {
		fmt.Fprintf(os.Stderr, "iv length %d != %d\n", len(iv), ciph.IVSize())
		os.Exit(2)
	}
	plain := []byte(*payload)
	out := append([]byte{}, iv...)
	buf := append([]byte{}, plain...)
	ciph.Encrypter(iv).XORKeyStream(buf, buf)
	out = append(out, buf...)
	fmt.Println(hex.EncodeToString(out))
}
