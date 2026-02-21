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

// ==========================================================================
// Protocol:
//
//   CONNECT host:port [socks5://proxy:port]\n
//     → OK <negotiated-alpn>\n | ERR msg\n
//     → then bidirectional plaintext pipe
//
//   PING\n  → PONG\n
//   STATS\n → {"active_conns":...}\n
//
// The sidecar always uses Chrome's full ALPN list (h2 + http/1.1) to
// preserve fingerprint fidelity. The OK response reports which protocol
// the target actually selected so the proxy can offer matching ALPN to
// the browser during the MITM TLS handshake.
//
// Lifecycle:
//   Prints "READY <addr>\n" to stdout when listener is up.
//   SIGTERM/SIGINT → drain → exit.
// ==========================================================================

// ---------------------------------------------------------------------------
// Configuration
// ---------------------------------------------------------------------------

type Config struct {
	ListenAddr     string
	ReadTimeout    time.Duration
	WriteTimeout   time.Duration
	ConnectTimeout time.Duration
	IdleTimeout    time.Duration
	BufferSize     int
	MaxConns       int64
	Insecure       bool
}

// ---------------------------------------------------------------------------
// Metrics
// ---------------------------------------------------------------------------

type Metrics struct {
	ActiveConns   atomic.Int64
	TotalConns    atomic.Int64
	TotalBytes    atomic.Int64
	TLSHandshakes atomic.Int64
	TLSErrors     atomic.Int64
	SOCKSConns    atomic.Int64
	StartTime     time.Time
}

type StatsSnapshot struct {
	ActiveConns   int64   `json:"active_conns"`
	TotalConns    int64   `json:"total_conns"`
	TotalBytes    int64   `json:"total_bytes"`
	TLSHandshakes int64  `json:"tls_handshakes"`
	TLSErrors     int64   `json:"tls_errors"`
	SOCKSConns    int64   `json:"socks_conns"`
	UptimeSeconds float64 `json:"uptime_seconds"`
	Goroutines    int     `json:"goroutines"`
}

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

var metrics = Metrics{StartTime: time.Now()}

// ---------------------------------------------------------------------------
// SOCKS5 dialer
// ---------------------------------------------------------------------------

func dialSOCKS5(ctx context.Context, proxyAddr, targetHost string, targetPort int) (net.Conn, error) {
	// Validate domain length (SOCKS5 uses a single byte for length)
	if len(targetHost) > 255 {
		return nil, fmt.Errorf("socks5: domain too long (%d bytes, max 255)", len(targetHost))
	}

	// Derive timeout from context instead of hardcoding
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
	if deadline, ok := ctx.Deadline(); ok {
		conn.SetDeadline(deadline)
	}

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

	respHdr := make([]byte, 4)
	if _, err := io.ReadFull(conn, respHdr); err != nil {
		conn.Close()
		return nil, fmt.Errorf("socks5 connect read: %w", err)
	}
	if respHdr[1] != 0x00 {
		conn.Close()
		errMsgs := map[byte]string{
			1: "general failure", 2: "not allowed", 3: "network unreachable",
			4: "host unreachable", 5: "connection refused", 6: "TTL expired",
		}
		msg := errMsgs[respHdr[1]]
		if msg == "" {
			msg = fmt.Sprintf("error code %d", respHdr[1])
		}
		return nil, fmt.Errorf("socks5: %s", msg)
	}

	// Drain bound address — check errors to avoid corrupted state
	var drainErr error
	switch respHdr[3] {
	case 0x01: // IPv4 + port
		_, drainErr = io.ReadFull(conn, make([]byte, 6))
	case 0x03: // domain + port
		lenBuf := make([]byte, 1)
		if _, drainErr = io.ReadFull(conn, lenBuf); drainErr == nil {
			_, drainErr = io.ReadFull(conn, make([]byte, int(lenBuf[0])+2))
		}
	case 0x04: // IPv6 + port
		_, drainErr = io.ReadFull(conn, make([]byte, 18))
	default:
		drainErr = fmt.Errorf("unknown address type 0x%02x", respHdr[3])
	}
	if drainErr != nil {
		conn.Close()
		return nil, fmt.Errorf("socks5 drain bound addr: %w", drainErr)
	}

	conn.SetDeadline(time.Time{})
	metrics.SOCKSConns.Add(1)
	return conn, nil
}

// ---------------------------------------------------------------------------
// Chrome TLS handshake
// ---------------------------------------------------------------------------

func chromeHandshake(ctx context.Context, conn net.Conn, hostname string, insecure bool) (*tls.UConn, string, error) {
	// HelloChrome_Auto replicates the latest stable Chrome ClientHello
	// byte-for-byte: GREASE, extension order, cipher suites, groups
	// (incl X25519MLKEM768), ECH, ALPS, compress_certificate.
	//
	// ALPN is always h2 + http/1.1 (Chrome's default). We do NOT
	// modify it — changing ALPN would alter the fingerprint hash.
	uconn := tls.UClient(conn, &tls.Config{
		ServerName:         hostname,
		InsecureSkipVerify: insecure,
	}, tls.HelloChrome_Auto)

	if deadline, ok := ctx.Deadline(); ok {
		uconn.SetDeadline(deadline)
	}

	if err := uconn.Handshake(); err != nil {
		metrics.TLSErrors.Add(1)
		uconn.Close() // Clean up utls internal state
		return nil, "", fmt.Errorf("tls handshake %s: %w", hostname, err)
	}
	metrics.TLSHandshakes.Add(1)
	uconn.SetDeadline(time.Time{})

	alpn := uconn.ConnectionState().NegotiatedProtocol
	if alpn == "" {
		alpn = "http/1.1"
	}
	return uconn, alpn, nil
}

// ---------------------------------------------------------------------------
// Connection handler — dispatches CONNECT / PING / STATS
// ---------------------------------------------------------------------------

func handleConn(conn net.Conn, cfg Config) {
	// Read the command line FIRST to determine the type.
	// Only CONNECT increments active/total counters.
	// This prevents PING/STATS from corrupting the metrics.
	conn.SetReadDeadline(time.Now().Add(cfg.ReadTimeout))
	reader := bufio.NewReaderSize(conn, 512)
	line, err := reader.ReadString('\n')
	if err != nil {
		conn.Close()
		return
	}
	conn.SetReadDeadline(time.Time{})
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
		metrics.ActiveConns.Add(1)
		metrics.TotalConns.Add(1)
		doConnect(conn, reader, fields, cfg)
		// doConnect closes conn via pipe() or on error
		metrics.ActiveConns.Add(-1)

	default:
		writeResp(conn, cfg, fmt.Sprintf("ERR unknown command: %s\n", fields[0]))
		conn.Close()
	}
}

func doConnect(conn net.Conn, reader *bufio.Reader, fields []string, cfg Config) {
	if len(fields) < 2 {
		writeResp(conn, cfg, "ERR CONNECT requires host:port\n")
		conn.Close()
		return
	}

	target := fields[1]
	host, portStr, err := net.SplitHostPort(target)
	if err != nil {
		host = target
		portStr = "443"
	}
	port := 443
	if p, err := net.LookupPort("tcp", portStr); err == nil {
		port = p
	}

	var socksProxy string
	if len(fields) >= 3 {
		socksProxy = strings.TrimPrefix(fields[2], "socks5://")
		socksProxy = strings.TrimPrefix(socksProxy, "socks://")
	}

	ctx, cancel := context.WithTimeout(context.Background(), cfg.ConnectTimeout)
	defer cancel()

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

	// chromeHandshake closes the underlying conn (via uconn.Close()) on
	// failure, so we must NOT call targetConn.Close() again here.
	tlsConn, alpn, err := chromeHandshake(ctx, targetConn, host, cfg.Insecure)
	if err != nil {
		writeResp(conn, cfg, fmt.Sprintf("ERR %s\n", err))
		conn.Close()
		return
	}

	if err := writeResp(conn, cfg, fmt.Sprintf("OK %s\n", alpn)); err != nil {
		tlsConn.Close()
		conn.Close()
		return
	}

	// Flush any data the bufio.Reader consumed past the command line
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

	// pipe() closes both connections when done
	pipe(conn, tlsConn, cfg)
}

func writeResp(conn net.Conn, cfg Config, msg string) error {
	conn.SetWriteDeadline(time.Now().Add(cfg.WriteTimeout))
	_, err := conn.Write([]byte(msg))
	conn.SetWriteDeadline(time.Time{})
	return err
}

// ---------------------------------------------------------------------------
// Bidirectional pipe
// ---------------------------------------------------------------------------

func pipe(client, target net.Conn, cfg Config) {
	// When one direction finishes (EOF, error, write failure), we
	// immediately close both connections so the other direction's
	// Read() unblocks instantly instead of waiting for IdleTimeout.
	teardown := make(chan struct{}, 1)

	var wg sync.WaitGroup
	wg.Add(2)

	cp := func(dst, src net.Conn) {
		defer wg.Done()
		buf := make([]byte, cfg.BufferSize)
		for {
			src.SetReadDeadline(time.Now().Add(cfg.IdleTimeout))
			n, err := src.Read(buf)
			if n > 0 {
				metrics.TotalBytes.Add(int64(n))
				dst.SetWriteDeadline(time.Now().Add(10 * time.Second))
				if _, werr := dst.Write(buf[:n]); werr != nil {
					break
				}
			}
			if err != nil {
				break
			}
		}
		select {
		case teardown <- struct{}{}:
		default:
		}
	}

	go cp(target, client)
	go cp(client, target)

	<-teardown
	client.Close()
	target.Close()
	wg.Wait()
}

// ---------------------------------------------------------------------------
// Stats logging
// ---------------------------------------------------------------------------

func statsLoop(interval time.Duration) {
	t := time.NewTicker(interval)
	defer t.Stop()
	for range t.C {
		s := metrics.Snapshot()
		log.Printf("[STATS] active=%d total=%d tls=%d tls_err=%d socks=%d bytes=%d gr=%d",
			s.ActiveConns, s.TotalConns, s.TLSHandshakes, s.TLSErrors,
			s.SOCKSConns, s.TotalBytes, s.Goroutines)
	}
}

// ---------------------------------------------------------------------------
// Main
// ---------------------------------------------------------------------------

func main() {
	addr := flag.String("listen", "127.0.0.1:0", "Listen address (port 0 = OS-assigned)")
	connectTimeout := flag.Duration("connect-timeout", 30*time.Second, "TCP+SOCKS+TLS timeout")
	idleTimeout := flag.Duration("idle-timeout", 90*time.Second, "Pipe idle timeout")
	bufSize := flag.Int("buffer", 65536, "Copy buffer size")
	maxConns := flag.Int64("max-conns", 0, "Max concurrent conns (0=unlimited)")
	statsInterval := flag.Duration("stats-interval", 60*time.Second, "Stats log interval")
	insecure := flag.Bool("insecure", false, "Skip TLS certificate verification")
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

	ln, err := net.Listen("tcp", cfg.ListenAddr)
	if err != nil {
		fmt.Printf("ERROR %v\n", err)
		os.Stdout.Sync()
		os.Exit(1)
	}

	boundAddr := ln.Addr().String()
	fmt.Printf("READY %s\n", boundAddr)
	os.Stdout.Sync()

	log.Printf("TLS sidecar on %s (Chrome fingerprint, utls)", boundAddr)

	ctx, stop := signal.NotifyContext(context.Background(), syscall.SIGINT, syscall.SIGTERM)
	defer stop()
	go func() { <-ctx.Done(); log.Println("Shutting down..."); ln.Close() }()

	if *statsInterval > 0 {
		go statsLoop(*statsInterval)
	}

	for {
		conn, err := ln.Accept()
		if err != nil {
			if ctx.Err() != nil {
				break
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

	log.Printf("Draining %d active connections...", metrics.ActiveConns.Load())
	dl := time.After(5 * time.Second)
	for metrics.ActiveConns.Load() > 0 {
		select {
		case <-dl:
			log.Printf("Force exit with %d active", metrics.ActiveConns.Load())
			return
		case <-time.After(100 * time.Millisecond):
		}
	}
	log.Println("Clean shutdown")
}