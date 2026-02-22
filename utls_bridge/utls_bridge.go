// Package main implements a TLS sidecar process that provides
// Chrome-fingerprinted TLS connections for a Python MITM proxy.
//
// # Why a separate process?
//
// Python's ssl module produces a trivially detectable TLS fingerprint.
// Bot-detection systems (Akamai, Cloudflare, PerimeterX) compare the
// ClientHello against known browser fingerprints and block mismatches.
// This sidecar uses utls (https://github.com/refraction-networking/utls)
// with HelloChrome_Auto to replicate Chrome's exact ClientHello —
// including GREASE values, extension order, cipher suites, key-share
// groups (X25519MLKEM768), ECH, ALPS, and compress_certificate.
//
// # Architecture
//
// The Python proxy connects to this sidecar over a local TCP socket.
// Each connection carries exactly one command:
//
//	CONNECT host:port [socks5://proxy:port]\n
//	  → OK <negotiated-alpn>\n   (success — bidirectional pipe follows)
//	  → ERR <message>\n          (failure — connection closed)
//
//	PING\n   → PONG\n            (health check)
//	STATS\n  → {"active_conns":...}\n  (JSON metrics)
//
// After a successful CONNECT, the sidecar holds the TLS session open
// and pipes plaintext bytes between the Python proxy and the encrypted
// target.  The Python side sees a raw TCP stream and handles HTTP/1.1
// or HTTP/2 framing itself.
//
// ALPN is always [h2, http/1.1] (Chrome's default).  The OK response
// reports which protocol the target actually selected so the Python
// proxy can offer matching ALPN to the browser during its own MITM
// handshake.
//
// # Lifecycle
//
// The sidecar prints "READY <addr>\n" to stdout when the listener is
// ready.  The Python SidecarManager reads this line to learn the
// bound address.  On SIGTERM/SIGINT the sidecar stops accepting,
// drains active connections (up to 5 s), and exits.
//
// # Building
//
//	go build -o tls-sidecar .
//
// # Usage
//
//	./tls-sidecar --listen 127.0.0.1:0 --connect-timeout 30s
package main

import (
	"bufio"
	"context"
	"encoding/binary"
	"encoding/json"
	"errors"
	"flag"
	"fmt"
	"io"
	"log"
	"net"
	"os"
	"os/signal"
	"runtime"
	"strings"
	"sync"
	"sync/atomic"
	"syscall"
	"time"

	tls "github.com/refraction-networking/utls"
)

// ---------------------------------------------------------------------------
// Configuration
// ---------------------------------------------------------------------------

// Config holds all tunable parameters for the sidecar.
// Values are populated from command-line flags in main().
type Config struct {
	ListenAddr     string        // "host:port" to bind (port 0 = OS-assigned)
	ReadTimeout    time.Duration // max time to read the command line from Python
	WriteTimeout   time.Duration // max time to write a response line to Python
	ConnectTimeout time.Duration // TCP + SOCKS5 + TLS handshake budget
	IdleTimeout    time.Duration // inactivity timeout for the bidirectional pipe
	BufferSize     int           // size of the copy buffer (bytes)
	MaxConns       int64         // 0 = unlimited concurrent connections
	Insecure       bool          // skip TLS certificate verification
}

// ---------------------------------------------------------------------------
// Metrics — lock-free counters for operational visibility
// ---------------------------------------------------------------------------

// Metrics tracks operational counters using atomic integers.
// All fields are safe for concurrent access without locks.
type Metrics struct {
	ActiveConns   atomic.Int64 // currently open CONNECT pipes
	TotalConns    atomic.Int64 // lifetime CONNECT count
	TotalBytes    atomic.Int64 // total bytes piped (both directions)
	TLSHandshakes atomic.Int64 // successful TLS handshakes
	TLSErrors     atomic.Int64 // failed TLS handshakes
	SOCKSConns    atomic.Int64 // successful SOCKS5 connections
	StartTime     time.Time    // process start time (for uptime)
}

// StatsSnapshot is the JSON-serialisable form of Metrics,
// returned by the STATS command.
type StatsSnapshot struct {
	ActiveConns   int64   `json:"active_conns"`
	TotalConns    int64   `json:"total_conns"`
	TotalBytes    int64   `json:"total_bytes"`
	TLSHandshakes int64   `json:"tls_handshakes"`
	TLSErrors     int64   `json:"tls_errors"`
	SOCKSConns    int64   `json:"socks_conns"`
	UptimeSeconds float64 `json:"uptime_seconds"`
	Goroutines    int     `json:"goroutines"`
}

// Snapshot returns a point-in-time copy of all metrics.
func (m *Metrics) Snapshot() StatsSnapshot {
	return StatsSnapshot{
		ActiveConns:   m.ActiveConns.Load(),
		TotalConns:    m.TotalConns.Load(),
		TotalBytes:    m.TotalBytes.Load(),
		TLSHandshakes: m.TLSHandshakes.Load(),
		TLSErrors:     m.TLSErrors.Load(),
		SOCKSConns:    m.SOCKSConns.Load(),
		UptimeSeconds: time.Since(m.StartTime).Seconds(),
		Goroutines:    runtime.NumGoroutine(),
	}
}

// Global metrics instance, shared by all goroutines.
var metrics = Metrics{StartTime: time.Now()}

// ---------------------------------------------------------------------------
// SOCKS5 dialer
// ---------------------------------------------------------------------------

// dialSOCKS5 establishes a TCP connection through a SOCKS5 proxy to
// the target host and port.  Only the "no authentication" method
// (0x00) is supported.
//
// The context deadline is respected for both the proxy connection and
// the SOCKS5 handshake.  On success the returned net.Conn is ready for
// application-level I/O (TLS handshake in our case).
func dialSOCKS5(ctx context.Context, proxyAddr, targetHost string, targetPort int) (net.Conn, error) {
	// SOCKS5 uses a single byte for domain length — enforce the limit
	// early so we get a clear error instead of a truncated domain.
	if len(targetHost) > 255 {
		return nil, fmt.Errorf("socks5: domain too long (%d bytes, max 255)", len(targetHost))
	}

	// Derive dialer timeout from context deadline so the caller's
	// overall ConnectTimeout budget is respected end-to-end.
	d := net.Dialer{}
	if deadline, ok := ctx.Deadline(); ok {
		remaining := time.Until(deadline)
		if remaining <= 0 {
			return nil, context.DeadlineExceeded
		}
		d.Timeout = remaining
	} else {
		d.Timeout = 15 * time.Second
	}

	conn, err := d.DialContext(ctx, "tcp", proxyAddr)
	if err != nil {
		return nil, fmt.Errorf("socks5 dial %s: %w", proxyAddr, err)
	}
	// Apply context deadline to the SOCKS5 handshake reads/writes.
	if deadline, ok := ctx.Deadline(); ok {
		conn.SetDeadline(deadline)
	}

	// --- Greeting: offer "no auth" (method 0x00) ---
	if _, err := conn.Write([]byte{0x05, 0x01, 0x00}); err != nil {
		conn.Close()
		return nil, fmt.Errorf("socks5 handshake write: %w", err)
	}

	resp := make([]byte, 2)
	if _, err := io.ReadFull(conn, resp); err != nil {
		conn.Close()
		return nil, fmt.Errorf("socks5 handshake read: %w", err)
	}
	if resp[0] != 0x05 || resp[1] == 0xFF {
		conn.Close()
		return nil, errors.New("socks5: no acceptable auth method")
	}

	// --- CONNECT request: domain-name address type (0x03) ---
	domain := []byte(targetHost)
	req := make([]byte, 0, 7+len(domain))
	req = append(req, 0x05, 0x01, 0x00, 0x03, byte(len(domain)))
	req = append(req, domain...)
	portBytes := make([]byte, 2)
	binary.BigEndian.PutUint16(portBytes, uint16(targetPort))
	req = append(req, portBytes...)

	if _, err := conn.Write(req); err != nil {
		conn.Close()
		return nil, fmt.Errorf("socks5 connect write: %w", err)
	}

	// --- CONNECT response ---
	respHdr := make([]byte, 4)
	if _, err := io.ReadFull(conn, respHdr); err != nil {
		conn.Close()
		return nil, fmt.Errorf("socks5 connect read: %w", err)
	}
	if respHdr[1] != 0x00 {
		conn.Close()
		// Full SOCKS5 error code map (RFC 1928 §6)
		errMsgs := map[byte]string{
			1: "general failure",
			2: "not allowed by ruleset",
			3: "network unreachable",
			4: "host unreachable",
			5: "connection refused",
			6: "TTL expired",
			7: "command not supported",
			8: "address type not supported",
		}
		msg := errMsgs[respHdr[1]]
		if msg == "" {
			msg = fmt.Sprintf("unknown error code %d", respHdr[1])
		}
		return nil, fmt.Errorf("socks5: %s", msg)
	}

	// --- Drain the bound address field ---
	// The proxy tells us its outbound address/port, which we don't
	// need but must read to leave the stream in a clean state.
	var drainErr error
	switch respHdr[3] {
		case 0x01: // IPv4 (4 bytes) + port (2 bytes)
			_, drainErr = io.ReadFull(conn, make([]byte, 6))
		case 0x03: // Domain: 1-byte length + domain + 2-byte port
			lenBuf := make([]byte, 1)
			if _, drainErr = io.ReadFull(conn, lenBuf); drainErr == nil {
				_, drainErr = io.ReadFull(conn, make([]byte, int(lenBuf[0])+2))
			}
		case 0x04: // IPv6 (16 bytes) + port (2 bytes)
			_, drainErr = io.ReadFull(conn, make([]byte, 18))
		default:
			drainErr = fmt.Errorf("unknown address type 0x%02x", respHdr[3])
	}
	if drainErr != nil {
		conn.Close()
		return nil, fmt.Errorf("socks5 drain bound addr: %w", drainErr)
	}

	// Clear the handshake deadline — the connection is now ready for
	// the caller's TLS handshake, which sets its own deadlines.
	conn.SetDeadline(time.Time{})
	metrics.SOCKSConns.Add(1)
	return conn, nil
}

// ---------------------------------------------------------------------------
// Chrome TLS handshake
// ---------------------------------------------------------------------------

// chromeHandshake wraps an existing TCP connection in a utls.UConn
// configured to replicate Chrome's ClientHello byte-for-byte.
//
// HelloChrome_Auto tracks the latest stable Chrome release, including
// GREASE values, extension ordering, cipher suites, key-share groups
// (X25519MLKEM768 as of Chrome 131+), ECH, ALPS, and
// compress_certificate.
//
// ALPN is always [h2, http/1.1] — Chrome's default.  We intentionally
// do NOT modify the ALPN list because changing it would alter the
// JA3/JA4 fingerprint hash, defeating the whole purpose.
//
// Returns the utls connection, the negotiated ALPN string, and any
// error.  On error the connection is closed and the caller must NOT
// close it again (utls.UConn.Close releases internal state).
func chromeHandshake(ctx context.Context, conn net.Conn, hostname string, insecure bool) (*tls.UConn, string, error) {
	uconn := tls.UClient(conn, &tls.Config{
		ServerName:         hostname,
		InsecureSkipVerify: insecure,
	}, tls.HelloChrome_Auto)

	if deadline, ok := ctx.Deadline(); ok {
		uconn.SetDeadline(deadline)
	}

	if err := uconn.Handshake(); err != nil {
		metrics.TLSErrors.Add(1)
		uconn.Close() // releases utls internal state + underlying conn
		return nil, "", fmt.Errorf("tls handshake %s: %w", hostname, err)
	}
	metrics.TLSHandshakes.Add(1)

	// Clear the handshake deadline — the pipe sets per-read deadlines.
	uconn.SetDeadline(time.Time{})

	alpn := uconn.ConnectionState().NegotiatedProtocol
	if alpn == "" {
		alpn = "http/1.1" // no ALPN negotiated → assume HTTP/1.1
	}
	return uconn, alpn, nil
}

// ---------------------------------------------------------------------------
// Connection handler — dispatches CONNECT / PING / STATS
// ---------------------------------------------------------------------------

// maxCommandLineLen caps the maximum length of a command line to
// prevent a malicious client from forcing unbounded memory allocation.
// ReadSlice will return bufio.ErrBufferFull if the line exceeds the
// buffer size; we use a slightly larger buffer here so legitimate
// CONNECT commands (which include a hostname and optional SOCKS URL)
// always fit.
const maxCommandLineLen = 65536

// handleConn reads a single command from the local connection and
// dispatches to the appropriate handler.
//
// Only CONNECT commands contribute to the active/total connection
// metrics.  PING and STATS are lightweight control-plane operations
// that don't inflate the counters.
func handleConn(conn net.Conn, cfg Config) {
	// Read the command line with a capped buffer to prevent unbounded
	// allocation from a malicious or misbehaving client.
	conn.SetReadDeadline(time.Now().Add(cfg.ReadTimeout))
	reader := bufio.NewReaderSize(conn, maxCommandLineLen)
	line, err := reader.ReadString('\n')
	if err != nil {
		// If the line is too long, ReadString will still return what
		// it has plus the error — we just reject it.
		conn.Close()
		return
	}
	conn.SetReadDeadline(time.Time{})

	// FIX: Enforce a hard length limit.  bufio.ReadString will
	// allocate beyond the buffer size if no newline is found within
	// the buffer.  This prevents a client from sending megabytes of
	// data without a newline.
	if len(line) > maxCommandLineLen {
		writeResp(conn, cfg, "ERR command line too long\n")
		conn.Close()
		return
	}

	line = strings.TrimSpace(line)
	fields := strings.Fields(line)
	if len(fields) == 0 {
		conn.Close()
		return
	}

	switch strings.ToUpper(fields[0]) {
		case "PING":
			writeResp(conn, cfg, "PONG\n")
			conn.Close()

		case "STATS":
			data, _ := json.Marshal(metrics.Snapshot())
			writeResp(conn, cfg, string(data)+"\n")
			conn.Close()

		case "CONNECT":
			// Only CONNECT increments metrics — PING/STATS are control
			// plane and shouldn't inflate the connection counters.
			metrics.ActiveConns.Add(1)
			metrics.TotalConns.Add(1)
			doConnect(conn, reader, fields, cfg)
			// doConnect closes conn via pipe() or on error path
			metrics.ActiveConns.Add(-1)

		default:
			writeResp(conn, cfg, fmt.Sprintf("ERR unknown command: %s\n", fields[0]))
			conn.Close()
	}
}

// doConnect handles the CONNECT command:
//  1. Parse target host:port and optional SOCKS5 proxy URL
//  2. Establish TCP connection (direct or via SOCKS5)
//  3. Perform Chrome-fingerprinted TLS handshake
//  4. Report negotiated ALPN to the Python side
//  5. Enter bidirectional plaintext pipe
func doConnect(conn net.Conn, reader *bufio.Reader, fields []string, cfg Config) {
	if len(fields) < 2 {
		writeResp(conn, cfg, "ERR CONNECT requires host:port\n")
		conn.Close()
		return
	}

	target := fields[1]
	host, portStr, err := net.SplitHostPort(target)
	if err != nil {
		// No port specified — default to 443 (HTTPS)
		host = target
		portStr = "443"
	}
	port := 443
	if p, err := net.LookupPort("tcp", portStr); err == nil {
		port = p
	}

	// Optional SOCKS5 proxy: "CONNECT host:port socks5://proxy:port"
	var socksProxy string
	if len(fields) >= 3 {
		socksProxy = strings.TrimPrefix(fields[2], "socks5://")
		socksProxy = strings.TrimPrefix(socksProxy, "socks://")
	}

	ctx, cancel := context.WithTimeout(context.Background(), cfg.ConnectTimeout)
	defer cancel()

	// --- TCP connection (direct or SOCKS5) ---
	var targetConn net.Conn
	if socksProxy != "" {
		targetConn, err = dialSOCKS5(ctx, socksProxy, host, port)
	} else {
		targetConn, err = (&net.Dialer{}).DialContext(ctx, "tcp", net.JoinHostPort(host, portStr))
	}
	if err != nil {
		writeResp(conn, cfg, fmt.Sprintf("ERR %s\n", err))
		conn.Close()
		return
	}

	// --- TLS handshake ---
	// Note: chromeHandshake closes targetConn (via uconn.Close()) on
	// failure, so we must NOT double-close it in the error path.
	tlsConn, alpn, err := chromeHandshake(ctx, targetConn, host, cfg.Insecure)
	if err != nil {
		writeResp(conn, cfg, fmt.Sprintf("ERR %s\n", err))
		conn.Close()
		return
	}

	// --- Report success + negotiated protocol ---
	if err := writeResp(conn, cfg, fmt.Sprintf("OK %s\n", alpn)); err != nil {
		tlsConn.Close()
		conn.Close()
		return
	}

	// --- Flush buffered data ---
	// The bufio.Reader may have consumed bytes past the command line
	// (e.g. if the Python side pipelined data immediately after the
	// newline).  Forward those bytes to the target before entering
	// the pipe.
	if reader.Buffered() > 0 {
		buf := make([]byte, reader.Buffered())
		n, _ := reader.Read(buf)
		if n > 0 {
			if _, err := tlsConn.Write(buf[:n]); err != nil {
				tlsConn.Close()
				conn.Close()
				return
			}
		}
	}

	// pipe() closes both connections when done.
	pipe(conn, tlsConn, cfg)
}

// writeResp writes a response string to the connection with a write
// deadline.  Returns an error if the write fails (e.g. client gone).
func writeResp(conn net.Conn, cfg Config, msg string) error {
	conn.SetWriteDeadline(time.Now().Add(cfg.WriteTimeout))
	_, err := conn.Write([]byte(msg))
	conn.SetWriteDeadline(time.Time{})
	return err
}

// ---------------------------------------------------------------------------
// Bidirectional pipe
// ---------------------------------------------------------------------------

// pipe copies data between client (Python proxy) and target (TLS to
// origin) in both directions concurrently.
//
// When either direction encounters an error or EOF:
//  1. It signals the teardown channel
//  2. The main goroutine closes BOTH connections
//  3. This causes the other direction's Read() to unblock with an error
//  4. Both goroutines exit and wg.Wait() returns
//
// The close-both-on-first-error strategy ensures we never leave one
// goroutine hanging indefinitely waiting for data that will never come.
func pipe(client, target net.Conn, cfg Config) {
	teardown := make(chan struct{}, 1)

	var wg sync.WaitGroup
	wg.Add(2)

	cp := func(dst, src net.Conn) {
		defer wg.Done()
		buf := make([]byte, cfg.BufferSize)
		for {
			// Per-read idle timeout: if no data arrives within
			// IdleTimeout, the connection is considered stale.
			src.SetReadDeadline(time.Now().Add(cfg.IdleTimeout))
			n, err := src.Read(buf)
			if n > 0 {
				metrics.TotalBytes.Add(int64(n))
				// Write deadline prevents a slow/stuck peer from
				// blocking the copy loop indefinitely.
				dst.SetWriteDeadline(time.Now().Add(10 * time.Second))
				if _, werr := dst.Write(buf[:n]); werr != nil {
					break
				}
			}
			if err != nil {
				break
			}
		}
		// Signal teardown (non-blocking — first writer wins).
		select {
			case teardown <- struct{}{}:
			default:
		}
	}

	go cp(target, client) // client → target
	go cp(client, target) // target → client

	// Wait for the first direction to finish, then close both to
	// unblock the other.
	<-teardown
	client.Close()
	target.Close()

	// Wait for both goroutines to exit.  Because we closed both
	// connections above, any blocked Read/Write will return an error
	// promptly.  The 10-second timeout is a defensive measure against
	// edge cases where Close() doesn't unblock a syscall (observed
	// rarely on some kernels with SO_LINGER).
	done := make(chan struct{})
	go func() {
		wg.Wait()
		close(done)
	}()
	select {
		case <-done:
			// Clean exit
		case <-time.After(10 * time.Second):
			log.Printf("[WARN] pipe goroutine drain timed out (10s)")
	}
}

// ---------------------------------------------------------------------------
// Stats logging
// ---------------------------------------------------------------------------

// statsLoop periodically logs operational metrics to stderr.
// Respects the provided context for clean shutdown.
func statsLoop(ctx context.Context, interval time.Duration) {
	t := time.NewTicker(interval)
	defer t.Stop()
	for {
		select {
			case <-ctx.Done():
				return
			case <-t.C:
				s := metrics.Snapshot()
				log.Printf("[STATS] active=%d total=%d tls=%d tls_err=%d socks=%d bytes=%d gr=%d",
					   s.ActiveConns, s.TotalConns, s.TLSHandshakes, s.TLSErrors,
	       s.SOCKSConns, s.TotalBytes, s.Goroutines)
		}
	}
}

// ---------------------------------------------------------------------------
// Main
// ---------------------------------------------------------------------------

func main() {
	// --- CLI flags ---
	addr := flag.String("listen", "127.0.0.1:0", "Listen address (port 0 = OS-assigned)")
	connectTimeout := flag.Duration("connect-timeout", 30*time.Second, "TCP+SOCKS+TLS timeout")
	idleTimeout := flag.Duration("idle-timeout", 90*time.Second, "Pipe idle timeout")
	bufSize := flag.Int("buffer", 65536, "Copy buffer size in bytes")
	maxConns := flag.Int64("max-conns", 0, "Max concurrent connections (0 = unlimited)")
	statsInterval := flag.Duration("stats-interval", 60*time.Second, "Stats log interval (0 = disabled)")
	insecure := flag.Bool("insecure", false, "Skip TLS certificate verification (development only)")
	flag.Parse()

	cfg := Config{
		ListenAddr:     *addr,
		ReadTimeout:    5 * time.Second,
		WriteTimeout:   5 * time.Second,
		ConnectTimeout: *connectTimeout,
		IdleTimeout:    *idleTimeout,
		BufferSize:     *bufSize,
		MaxConns:       *maxConns,
		Insecure:       *insecure,
	}

	// --- Start listener ---
	ln, err := net.Listen("tcp", cfg.ListenAddr)
	if err != nil {
		// The Python SidecarManager looks for "ERROR" on stdout to
		// detect startup failures.
		fmt.Printf("ERROR %v\n", err)
		os.Stdout.Sync()
		os.Exit(1)
	}

	boundAddr := ln.Addr().String()

	// The Python SidecarManager reads this line to learn our address.
	// Must be flushed immediately so the parent process doesn't block.
	fmt.Printf("READY %s\n", boundAddr)
	os.Stdout.Sync()

	log.Printf("TLS sidecar on %s (Chrome fingerprint, utls)", boundAddr)

	// --- Graceful shutdown on SIGTERM/SIGINT ---
	ctx, stop := signal.NotifyContext(context.Background(), syscall.SIGINT, syscall.SIGTERM)
	defer stop()
	go func() {
		<-ctx.Done()
		log.Println("Shutting down...")
		ln.Close() // causes Accept() to return an error
	}()

	// --- Background stats logging ---
	if *statsInterval > 0 {
		go statsLoop(ctx, *statsInterval)
	}

	// --- Accept loop ---
	for {
		conn, err := ln.Accept()
		if err != nil {
			if ctx.Err() != nil {
				break // shutdown signal received
			}
			log.Printf("[ERR] accept: %v", err)
			continue
		}
		if cfg.MaxConns > 0 && metrics.ActiveConns.Load() >= cfg.MaxConns {
			writeResp(conn, cfg, "ERR max connections reached\n")
			conn.Close()
			continue
		}
		go handleConn(conn, cfg)
	}

	// --- Drain active connections ---
	log.Printf("Draining %d active connections...", metrics.ActiveConns.Load())
	deadline := time.After(5 * time.Second)
	for metrics.ActiveConns.Load() > 0 {
		select {
			case <-deadline:
				log.Printf("Force exit with %d active connections", metrics.ActiveConns.Load())
				return
			case <-time.After(100 * time.Millisecond):
		}
	}
	log.Println("Clean shutdown")
}
