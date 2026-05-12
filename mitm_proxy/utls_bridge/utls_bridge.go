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
	"net/url"
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
	ListenAddr		string        // "host:port" to bind (port 0 = OS-assigned)
	ReadTimeout		time.Duration // max time to read the command line from Python
	WriteTimeout	time.Duration // max time to write a response line to Python
	ConnectTimeout	time.Duration // TCP + SOCKS5 + TLS handshake budget
	IdleTimeout		time.Duration // inactivity timeout for the bidirectional pipe
	BufferSize		int           // size of the copy buffer (bytes)
	MaxConns		int64         // 0 = unlimited concurrent connections
	Insecure		bool          // skip TLS certificate verification
	ShutdownCh		<-chan struct{} // closed on SIGTERM/SIGINT to interrupt active pipes
	PipeWriteTimeout	time.Duration
}

var sessionCache = tls.NewLRUClientSessionCache(256)

// ---------------------------------------------------------------------------
// Buffer pool — avoids per-connection heap allocation under load
// ---------------------------------------------------------------------------

// bufPool recycles copy buffers used by the bidirectional pipe.
//
// Each CONNECT session needs two buffers (one per direction), each
// cfg.BufferSize bytes (default 64 KB).  Under high concurrency
// (hundreds of active connections) the allocation pressure is
// significant: 200 connections × 2 × 64 KB = 25 MB of short-lived
// buffers that churn through the GC.
//
// sync.Pool amortises this by reusing buffers across connections.
// The pool is lazily sized: it starts empty and grows as connections
// arrive, then shrinks naturally as the GC reclaims idle entries.
//
// We store *[]byte (pointer to slice) because sync.Pool works best
// with pointer types — storing a bare []byte would cause an allocation
// for the interface conversion on every Put.
var bufPool sync.Pool

// getBuf returns a buffer of at least `size` bytes from the pool,
// allocating a new one if the pool is empty or the pooled buffer is
// too small.
func getBuf(size int) *[]byte {
	if v := bufPool.Get(); v != nil {
		bp := v.(*[]byte)
		if cap(*bp) >= size {
			*bp = (*bp)[:size]
			return bp
		}
		// Pooled buffer is too small (config changed?), discard it
	}
	buf := make([]byte, size)
	return &buf
}

// putBuf returns a buffer to the pool for reuse.
func putBuf(bp *[]byte) {
	bufPool.Put(bp)
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
// Structured logging — emitted in a form the Python sidecar manager
// re-emits as native LogRecords (preserving level + caller info).
// ---------------------------------------------------------------------------

// logf emits a log line carrying level, caller function, caller line,
// and message — pipe-separated so the Python side can parse it back into
// a LogRecord whose funcName/lineno match the Go call site.
//
// Format:  LOG|<LEVEL>|<func>|<line>|<message>
//
// Pipe is chosen as the separator because Go log messages here never
// contain it.  runtime.Caller(1) captures the immediate caller (the
// actual log site, not this helper).  The package prefix is trimmed so
// "main.dialSOCKS5" becomes "dialSOCKS5", matching what Python's
// formatter would render for a real Python function.
//
// Newlines in the message are flattened to spaces so each LOG line on
// stderr corresponds to exactly one Python LogRecord.
func logf(level, format string, args ...any) {
	fn, line := "?", 0
	if pc, _, ln, ok := runtime.Caller(1); ok {
		line = ln
		if f := runtime.FuncForPC(pc); f != nil {
			name := f.Name()
			if i := strings.LastIndex(name, "."); i >= 0 {
				name = name[i+1:]
			}
			fn = name
		}
	}
	msg := fmt.Sprintf(format, args...)
	msg = strings.ReplaceAll(msg, "\n", " ")
	log.Printf("LOG|%s|%s|%d|%s", level, fn, line, msg)
}

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

	logf("DEBUG", "socks5: dialing proxy %s for target %s:%d", proxyAddr, targetHost, targetPort)
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
		logf("WARN", "socks5: proxy %s rejected auth method for %s:%d", proxyAddr, targetHost, targetPort)
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
		logf("WARN", "socks5: proxy %s CONNECT to %s:%d failed: %s (code=0x%02x)",
			proxyAddr, targetHost, targetPort, msg, respHdr[1])
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
	logf("DEBUG", "socks5: tunnel established via %s to %s:%d", proxyAddr, targetHost, targetPort)
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
	logf("DEBUG", "tls: starting Chrome handshake with %s", hostname)
	uconn := tls.UClient(conn, &tls.Config{
		ServerName:         hostname,
		InsecureSkipVerify: insecure,
		ClientSessionCache: sessionCache,
	}, tls.HelloChrome_Auto)

	if deadline, ok := ctx.Deadline(); ok {
		uconn.SetDeadline(deadline)
	}

	if err := uconn.Handshake(); err != nil {
		metrics.TLSErrors.Add(1)
		logf("WARN", "tls: handshake failed with %s: %v", hostname, err)
		uconn.Close() // releases utls internal state + underlying conn
		return nil, "", fmt.Errorf("tls handshake %s: %w", hostname, err)
	}
	metrics.TLSHandshakes.Add(1)

	// Clear the handshake deadline — the pipe sets per-read deadlines.
	uconn.SetDeadline(time.Time{})

	state := uconn.ConnectionState()
	alpn := state.NegotiatedProtocol
	if alpn == "" {
		alpn = "http/1.1" // no ALPN negotiated → assume HTTP/1.1
	}
	logf("DEBUG", "tls: handshake complete with %s: alpn=%s resumed=%v version=0x%04x cipher=0x%04x",
		hostname, alpn, state.DidResume, state.Version, state.CipherSuite)
	return uconn, alpn, nil
}

// ---------------------------------------------------------------------------
// Connection handler — dispatches CONNECT / PING / STATS
// ---------------------------------------------------------------------------

// maxCommandLineLen caps the maximum length of a command line to
// prevent a malicious client from forcing unbounded memory allocation.
// ReadSlice will return bufio.ErrBufferFull if the line exceeds the
// buffer size.
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
	lineBytes, err := reader.ReadSlice('\n')
	if err != nil {
		// ErrBufferFull means line exceeded maxCommandLineLen — reject.
		// Any other error (EOF, timeout) also means we can't proceed.
		if errors.Is(err, bufio.ErrBufferFull) {
			logf("WARN", "handleConn: command line exceeded %d bytes from %s", maxCommandLineLen, conn.RemoteAddr())
			writeResp(conn, cfg, "ERR command line too long\n")
		} else {
			logf("DEBUG", "handleConn: read error from %s: %v", conn.RemoteAddr(), err)
		}
		conn.Close()
		return
	}
	conn.SetReadDeadline(time.Time{})

	line := strings.TrimSpace(string(lineBytes))
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
			logf("WARN", "handleConn: unknown command %q from %s", fields[0], conn.RemoteAddr())
			writeResp(conn, cfg, fmt.Sprintf("ERR unknown command: %s\n", fields[0]))
			conn.Close()
	}
}

// parseTarget parses a CONNECT target into host and numeric port.
// Returns an error if the port is invalid rather than falling through
// silently to a default.
func parseTarget(target string) (host string, port int, err error) {
    host, portStr, err := net.SplitHostPort(target)
    if err != nil {
        // No port — default to 443. Strip brackets for bare IPv6 like "[::1]".
        host = strings.TrimSuffix(strings.TrimPrefix(target, "["), "]")
        if host == "" {
            return "", 0, fmt.Errorf("empty hostname in target %q", target)
        }
        return host, 443, nil
    }
    if host == "" {
        return "", 0, fmt.Errorf("empty hostname in target %q", target)
    }
    port, err = net.LookupPort("tcp", portStr)
    if err != nil {
        return "", 0, fmt.Errorf("invalid port %q: %w", portStr, err)
    }
    return host, port, nil
}

// parseSOCKS5Proxy parses a SOCKS5 proxy URL string into a host:port
// address.  Supports "socks5://host:port" and "socks://host:port".
// Returns an error for malformed URLs or URLs containing userinfo
// (authentication is not supported).
func parseSOCKS5Proxy(raw string) (string, error) {
	u, err := url.Parse(raw)
	if err != nil {
		return "", fmt.Errorf("invalid proxy URL %q: %w", raw, err)
	}
	if u.Scheme != "socks5" && u.Scheme != "socks" {
		return "", fmt.Errorf("unsupported proxy scheme %q (want socks5)", u.Scheme)
	}
	if u.User != nil {
		return "", fmt.Errorf("socks5 authentication not supported")
	}
	hostport := u.Host
	if hostport == "" {
		return "", fmt.Errorf("proxy URL %q has no host", raw)
	}
	// Ensure we have a port
	if _, _, err := net.SplitHostPort(hostport); err != nil {
		return "", fmt.Errorf("proxy URL %q missing port: %w", raw, err)
	}
	return hostport, nil
}

// doConnect handles the CONNECT command:
//  1. Parse target host:port and optional SOCKS5 proxy URL
//  2. Establish TCP connection (direct or via SOCKS5)
//  3. Perform Chrome-fingerprinted TLS handshake
//  4. Report negotiated ALPN to the Python side
//  5. Enter bidirectional plaintext pipe
func doConnect(conn net.Conn, reader *bufio.Reader, fields []string, cfg Config) {
    defer func() {
        if conn != nil {
            conn.Close()
        }
    }()

    if len(fields) < 2 {
        writeResp(conn, cfg, "ERR CONNECT requires host:port\n")
        return
    }

    target := fields[1]
    host, port, err := parseTarget(target)
    if err != nil {
        writeResp(conn, cfg, fmt.Sprintf("ERR %s\n", err))
        return
    }

    var socksProxy string
    if len(fields) >= 3 {
        socksProxy, err = parseSOCKS5Proxy(fields[2])
        if err != nil {
            writeResp(conn, cfg, fmt.Sprintf("ERR %s\n", err))
            return
        }
    }

    ctx, cancel := context.WithTimeout(context.Background(), cfg.ConnectTimeout)
    defer cancel()

    var targetConn net.Conn
    if socksProxy != "" {
        logf("INFO", "connect: %s via socks5://%s", target, socksProxy)
        targetConn, err = dialSOCKS5(ctx, socksProxy, host, port)
    } else {
        logf("INFO", "connect: %s (direct)", target)
        targetConn, err = (&net.Dialer{}).DialContext(ctx, "tcp",
            net.JoinHostPort(host, fmt.Sprintf("%d", port)))
    }
    if err != nil {
        logf("WARN", "connect: dial %s failed: %v", target, err)
        writeResp(conn, cfg, fmt.Sprintf("ERR %s\n", err))
        return
    }

    tlsConn, alpn, err := chromeHandshake(ctx, targetConn, host, cfg.Insecure)
    if err != nil {
        logf("WARN", "connect: TLS failed for %s: %v", target, err)
        writeResp(conn, cfg, fmt.Sprintf("ERR %s\n", err))
        return  // chromeHandshake already closed targetConn
    }
    defer func() {
        if tlsConn != nil {
            tlsConn.Close()
        }
    }()

    if err := writeResp(conn, cfg, fmt.Sprintf("OK %s\n", alpn)); err != nil {
        logf("WARN", "connect: failed to send OK to client for %s: %v", target, err)
        return
    }

    if reader.Buffered() > 0 {
        buf := make([]byte, reader.Buffered())
        n, _ := reader.Read(buf)
        if n > 0 {
            logf("DEBUG", "connect: flushing %d buffered bytes to %s", n, target)
            if _, err := tlsConn.Write(buf[:n]); err != nil {
                logf("WARN", "connect: flush to %s failed: %v", target, err)
                return
            }
        }
    }

    // Transfer ownership to pipe() — nil out so defers don't close.
    c, t := conn, tlsConn
    conn, tlsConn = nil, nil
    logf("INFO", "connect: pipe started for %s (alpn=%s active=%d)",
        target, alpn, metrics.ActiveConns.Load())
    pipe(c, t, cfg)
    logf("INFO", "connect: pipe closed for %s (active=%d)",
        target, metrics.ActiveConns.Load()-1)
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
// Buffers are obtained from a sync.Pool to avoid per-connection heap
// allocation.  Under steady-state load (e.g. 200 concurrent
// connections), the pool recycles buffers and the allocator is never
// hit.  During ramp-up, fresh buffers are allocated and added to the
// pool as connections close.
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

	cp := func(dst, src net.Conn, label string) {
		defer wg.Done()

		bp := getBuf(cfg.BufferSize)
		defer putBuf(bp)
		buf := *bp

		for {
			// Per-read idle timeout: if no data arrives within
			// IdleTimeout, the connection is considered stale.
			src.SetReadDeadline(time.Now().Add(cfg.IdleTimeout))
			n, err := src.Read(buf)
			if n > 0 {
				metrics.TotalBytes.Add(int64(n))
				// Write deadline prevents a slow/stuck peer from
				// blocking the copy loop indefinitely.
				dst.SetWriteDeadline(time.Now().Add(cfg.PipeWriteTimeout))
				if _, werr := dst.Write(buf[:n]); werr != nil {
					logf("DEBUG", "pipe: write error [%s]: %v", label, werr)
					break
				}
			}
			if err != nil {
				if !errors.Is(err, io.EOF) && !errors.Is(err, net.ErrClosed) {
					logf("DEBUG", "pipe: read error [%s]: %v", label, err)
				}
				break
			}
		}
		// Signal teardown (non-blocking — first writer wins).
		select {
		case teardown <- struct{}{}:
		default:
		}
	}

	go cp(target, client, "client>target") // client → target
	go cp(client, target, "target>client") // target → client

	// Wait for the first direction to finish OR a shutdown signal.
	// On shutdown, closing the connections unblocks the cp goroutines'
	// Read calls, allowing them to exit and the drain to complete
	// within the 5s deadline.
	select {
	case <-teardown:
		// Normal path — one direction finished.
	case <-cfg.ShutdownCh:
		// Shutdown requested — break out of the pipe immediately.
		logf("INFO", "shutdown: closing active pipe")
	}

	// Use TCP half-close where available to avoid racing
	// Close() with an in-flight Write().  CloseWrite signals EOF to
	// the peer's Read without aborting an in-flight Write on our side.
	if tc, ok := client.(*net.TCPConn); ok {
		tc.CloseWrite()
	}
	if tc, ok := target.(interface{ CloseWrite() error }); ok {
		tc.CloseWrite()
	}

	// Now fully close both connections.
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
		logf("WARN", "pipe goroutine drain timed out (10s)")
	}
}

// ---------------------------------------------------------------------------
// Stats logging
// ---------------------------------------------------------------------------

// statsLoop periodically logs operational metrics to stderr.
// Respects the provided context for clean shutdown.
// func statsLoop(ctx context.Context, interval time.Duration) {
// 	t := time.NewTicker(interval)
// 	defer t.Stop()
// 	for {
// 		select {
// 		case <-ctx.Done():
// 			return
// 		case <-t.C:
// 			s := metrics.Snapshot()
// 			// FIX #11: Consistent formatting (tabs vs spaces fixed).
// 			log.Printf("[STATS] active=%d total=%d tls=%d tls_err=%d socks=%d bytes=%d gr=%d",
// 				s.ActiveConns, s.TotalConns, s.TLSHandshakes, s.TLSErrors,
// 				s.SOCKSConns, s.TotalBytes, s.Goroutines)
// 		}
// 	}
// }

// ---------------------------------------------------------------------------
// Main
// ---------------------------------------------------------------------------

func main() {
	// --- CLI flags ---
	addr := flag.String("listen", "tls-sidecar", "Abstract namespace socket name")
	connectTimeout := flag.Duration("connect-timeout", 30*time.Second, "TCP+SOCKS+TLS timeout")
	idleTimeout := flag.Duration("idle-timeout", 90*time.Second, "Pipe idle timeout")
	bufSize := flag.Int("buffer", 65536, "Copy buffer size in bytes")
	maxConns := flag.Int64("max-conns", 0, "Max concurrent connections (0 = unlimited)")
	// statsInterval := flag.Duration("stats-interval", 60*time.Second, "Stats log interval (0 = disabled)")
	insecure := flag.Bool("insecure", false, "Skip TLS certificate verification (development only)")
	flag.Parse()
	log.SetFlags(0)

	// Shutdown channel — closed when SIGTERM/SIGINT is received.
	// Passed to pipe() via Config so active sessions can be interrupted.
	shutdownCh := make(chan struct{})

	var wg sync.WaitGroup

	cfg := Config{
		ListenAddr:		*addr,
		ReadTimeout:	5 * time.Second,
		WriteTimeout:	5 * time.Second,
		ConnectTimeout:	*connectTimeout,
		IdleTimeout:	*idleTimeout,
		BufferSize:		*bufSize,
		MaxConns:		*maxConns,
		Insecure:		*insecure,
		ShutdownCh:		shutdownCh,
		PipeWriteTimeout:	10 * time.Second,
	}

	if cfg.Insecure {
		logf("WARN", "*** TLS CERTIFICATE VERIFICATION DISABLED (--insecure) ***")
	}

	sockName := "\x00" + cfg.ListenAddr
	ln, err := net.Listen("unix", sockName)
	if err != nil {
		fmt.Printf("ERROR %v\n", err)
		os.Stdout.Sync()
		os.Exit(1)
	}

	// Go's UnixAddr.String() returns @name for abstract sockets
	boundAddr := ln.Addr().String()
	fmt.Printf("READY %s\n", boundAddr)
	os.Stdout.Sync()

	logf("INFO", "TLS sidecar on %s (abstract UDS, Chrome fingerprint, utls)", boundAddr)

	// --- Graceful shutdown on SIGTERM/SIGINT ---
	ctx, stop := signal.NotifyContext(context.Background(), syscall.SIGINT, syscall.SIGTERM)
	defer stop()
	go func() {
		<-ctx.Done()
		logf("INFO", "Shutting down...")
		close(shutdownCh) // interrupt active pipe sessions (FIX #9)
		ln.Close()        // causes Accept() to return an error
	}()

	// --- Background stats logging ---
	// if *statsInterval > 0 {
	// 	go statsLoop(ctx, *statsInterval)
	// }

	var connSem chan struct{}
	if cfg.MaxConns > 0 {
		connSem = make(chan struct{}, cfg.MaxConns)
	}

	// --- Accept loop ---
	for {
		conn, err := ln.Accept()
		if err != nil {
			if ctx.Err() != nil {
				break // shutdown signal received
			}
			logf("ERROR", "accept: %v", err)
			continue
		}

		if connSem != nil {
			// Non-blocking acquire: reject immediately if at capacity.
			select {
				case connSem <- struct{}{}:
					// Acquired — will be released when handleConn returns.
				default:
					logf("WARN", "accept: max connections (%d) reached, rejecting %s",
						cfg.MaxConns, conn.RemoteAddr())
					writeResp(conn, cfg, "ERR max connections reached\n")
					conn.Close()
					continue
			}
			wg.Add(1)
			go func() {
				defer wg.Done()
				defer func() { <-connSem }() // release semaphore slot
				handleConn(conn, cfg)
			}()
		} else {
			wg.Add(1)
			go func() {
				defer wg.Done()
				handleConn(conn, cfg)
			}()
		}
	}

	// --- Drain active connections ---
	logf("INFO", "Draining %d active connections...", metrics.ActiveConns.Load())
	done := make(chan struct{})
	go func() {
		wg.Wait()
		close(done)
	}()
	select {
	case <-done:
		logf("INFO", "Clean shutdown")
	case <-time.After(5 * time.Second):
		logf("WARN", "Force exit with %d active connections", metrics.ActiveConns.Load())
	}
}
