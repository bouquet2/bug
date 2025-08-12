package main

import (
    "context"
    "errors"
    "fmt"
    "io"
    "net"
    "strconv"
    "sync"
    "time"

    "github.com/rs/zerolog/log"
)

// startStreams starts all configured TCP/UDP stream forwarders and returns closers to stop them
func startStreams(config *Config) []io.Closer {
    var closers []io.Closer

    if len(config.Streams) == 0 {
        return closers
    }

    log.Info().Msgf("Setting up %d stream(s)", len(config.Streams))

    for _, stream := range config.Streams {
        protocol := stream.Protocol
        if protocol == "" {
            // Default to tcp for streams if unspecified
            protocol = "tcp"
        }

        // Determine load balancer
        lbType := stream.Lb
        if lbType == "" {
            lbType = config.Bug.Lb
        }

        // Build backends list from all rules
        var backends []BackendRef
        for _, rule := range stream.Rules {
            for _, be := range rule.BackendRefs {
                backends = append(backends, be)
            }
        }
        if len(backends) == 0 {
            log.Warn().Str("stream", stream.Name).Msg("No backends configured for stream; skipping")
            continue
        }

        switch protocol {
        case "tcp":
            closer, err := startTCPStream(stream, backends, lbType)
            if err != nil {
                log.Error().Err(err).Str("stream", stream.Name).Msg("Failed to start TCP stream")
                continue
            }
            closers = append(closers, closer)
        case "udp":
            closer, err := startUDPStream(stream, backends, lbType)
            if err != nil {
                log.Error().Err(err).Str("stream", stream.Name).Msg("Failed to start UDP stream")
                continue
            }
            closers = append(closers, closer)
        default:
            log.Error().Str("stream", stream.Name).Str("protocol", protocol).Msg("Unsupported stream protocol; expected tcp or udp")
        }
    }

    return closers
}

// roundRobinSelector selects backends in round-robin order
type roundRobinSelector struct {
    backends []BackendRef
    index    int
    mu       sync.Mutex
}

func newRoundRobinSelector(backends []BackendRef) *roundRobinSelector {
    return &roundRobinSelector{backends: append([]BackendRef(nil), backends...)}
}

func (r *roundRobinSelector) next() BackendRef {
    r.mu.Lock()
    defer r.mu.Unlock()
    if len(r.backends) == 0 {
        return BackendRef{}
    }
    be := r.backends[r.index%len(r.backends)]
    r.index = (r.index + 1) % len(r.backends)
    return be
}

// noneSelector always returns the first backend
type noneSelector struct{ backend BackendRef }

func (n *noneSelector) next() BackendRef { return n.backend }

// TCP implementation

type tcpStreamServer struct {
    listener net.Listener
    cancel   context.CancelFunc
    done     chan struct{}
}

func (s *tcpStreamServer) Close() error {
    s.cancel()
    if s.listener != nil {
        _ = s.listener.Close()
    }
    <-s.done
    return nil
}

func startTCPStream(stream Stream, backends []BackendRef, lbType string) (io.Closer, error) {
    addr := net.JoinHostPort(stream.Listen.Ip, strconv.Itoa(stream.Listen.Port))
    listener, err := net.Listen("tcp", addr)
    if err != nil {
        return nil, err
    }

    // Choose selector
    var selector interface{ next() BackendRef }
    if len(backends) > 1 && lbType == "roundrobin" {
        selector = newRoundRobinSelector(backends)
        log.Debug().Str("stream", stream.Name).Int("backends", len(backends)).Msg("TCP stream using roundrobin LB")
    } else {
        selector = &noneSelector{backend: backends[0]}
        log.Debug().Str("stream", stream.Name).Msg("TCP stream using single backend")
    }

    ctx, cancel := context.WithCancel(context.Background())
    done := make(chan struct{})

    go func() {
        defer close(done)
        for {
            conn, err := listener.Accept()
            if err != nil {
                if errors.Is(err, net.ErrClosed) || ctx.Err() != nil {
                    return
                }
                log.Error().Err(err).Str("stream", stream.Name).Msg("TCP accept error")
                // brief delay to avoid hot loop on repeated errors
                time.Sleep(100 * time.Millisecond)
                continue
            }

            backend := selector.next()
            backendAddr := net.JoinHostPort(backend.IP, strconv.Itoa(backend.Port))

            go func(clientConn net.Conn) {
                defer clientConn.Close()
                upstream, err := net.DialTimeout("tcp", backendAddr, 10*time.Second)
                if err != nil {
                    log.Error().Err(err).Str("backend", backendAddr).Str("stream", stream.Name).Msg("Failed to connect to backend")
                    return
                }
                defer upstream.Close()

                // Bi-directional copy
                var wg sync.WaitGroup
                wg.Add(2)
                go func() {
                    defer wg.Done()
                    _, _ = io.Copy(upstream, clientConn)
                }()
                go func() {
                    defer wg.Done()
                    _, _ = io.Copy(clientConn, upstream)
                }()
                wg.Wait()
            }(conn)
        }
    }()

    log.Info().Str("stream", stream.Name).Str("addr", addr).Msg("TCP stream listening")
    return &tcpStreamServer{listener: listener, cancel: cancel, done: done}, nil
}

// UDP implementation

type udpStreamServer struct {
    conn   *net.UDPConn
    cancel context.CancelFunc
    done   chan struct{}
}

func (s *udpStreamServer) Close() error {
    s.cancel()
    if s.conn != nil {
        _ = s.conn.Close()
    }
    <-s.done
    return nil
}

func startUDPStream(stream Stream, backends []BackendRef, lbType string) (io.Closer, error) {
    laddr := &net.UDPAddr{IP: net.ParseIP(stream.Listen.Ip), Port: stream.Listen.Port}
    if laddr.IP == nil {
        // Support empty/any address
        if stream.Listen.Ip == "" || stream.Listen.Ip == "0.0.0.0" {
            laddr.IP = net.IPv4zero
        } else {
            return nil, fmt.Errorf("invalid UDP listen IP: %s", stream.Listen.Ip)
        }
    }

    conn, err := net.ListenUDP("udp", laddr)
    if err != nil {
        return nil, err
    }

    // Selector
    var selector interface{ next() BackendRef }
    if len(backends) > 1 && lbType == "roundrobin" {
        selector = newRoundRobinSelector(backends)
        log.Debug().Str("stream", stream.Name).Int("backends", len(backends)).Msg("UDP stream using roundrobin LB")
    } else {
        selector = &noneSelector{backend: backends[0]}
        log.Debug().Str("stream", stream.Name).Msg("UDP stream using single backend")
    }

    ctx, cancel := context.WithCancel(context.Background())
    done := make(chan struct{})

    // Map client -> backend connection
    type clientBinding struct {
        backendConn *net.UDPConn
        lastSeen    time.Time
        cancel      context.CancelFunc
    }
    bindings := make(map[string]*clientBinding)
    var mu sync.Mutex

    // Cleaner goroutine to prune idle bindings
    go func() {
        ticker := time.NewTicker(30 * time.Second)
        defer ticker.Stop()
        for {
            select {
            case <-ctx.Done():
                return
            case <-ticker.C:
                cutoff := time.Now().Add(-2 * time.Minute)
                mu.Lock()
                for k, b := range bindings {
                    if b.lastSeen.Before(cutoff) {
                        b.cancel()
                        _ = b.backendConn.Close()
                        delete(bindings, k)
                    }
                }
                mu.Unlock()
            }
        }
    }()

    go func() {
        defer close(done)
        buf := make([]byte, 64*1024)
        for {
            n, clientAddr, err := conn.ReadFromUDP(buf)
            if err != nil {
                if ctx.Err() != nil {
                    return
                }
                log.Error().Err(err).Str("stream", stream.Name).Msg("UDP read error")
                continue
            }

            key := clientAddr.String()

            mu.Lock()
            binding, ok := bindings[key]
            if !ok {
                // Create new backend connection for this client
                be := selector.next()
                raddr := &net.UDPAddr{IP: net.ParseIP(be.IP), Port: be.Port}
                backendConn, err := net.DialUDP("udp", nil, raddr)
                if err != nil {
                    mu.Unlock()
                    log.Error().Err(err).Str("backend", raddr.String()).Str("stream", stream.Name).Msg("Failed to dial UDP backend")
                    continue
                }
                // Per-client context
                cctx, ccancel := context.WithCancel(ctx)
                binding = &clientBinding{backendConn: backendConn, lastSeen: time.Now(), cancel: ccancel}
                bindings[key] = binding

                // Start reader from backend to client
                go func(cctx context.Context, backendConn *net.UDPConn, client *net.UDPAddr) {
                    replyBuf := make([]byte, 64*1024)
                    for {
                        backendConn.SetReadDeadline(time.Now().Add(2 * time.Minute))
                        n, _, err := backendConn.ReadFromUDP(replyBuf)
                        if err != nil {
                            if ne, ok := err.(net.Error); ok && ne.Timeout() {
                                // idle timeout
                                return
                            }
                            if cctx.Err() != nil {
                                return
                            }
                            log.Error().Err(err).Str("stream", stream.Name).Msg("UDP backend read error")
                            return
                        }
                        if _, err := conn.WriteToUDP(replyBuf[:n], client); err != nil {
                            log.Error().Err(err).Str("stream", stream.Name).Msg("UDP write to client error")
                            return
                        }
                    }
                }(cctx, backendConn, clientAddr)
            }
            binding.lastSeen = time.Now()
            backendConn := binding.backendConn
            mu.Unlock()

            // Forward packet to backend
            if _, err := backendConn.Write(buf[:n]); err != nil {
                log.Error().Err(err).Str("stream", stream.Name).Msg("UDP write to backend error")
                // On write failure, drop binding
                mu.Lock()
                if b := bindings[key]; b != nil {
                    b.cancel()
                    _ = b.backendConn.Close()
                    delete(bindings, key)
                }
                mu.Unlock()
                continue
            }
        }
    }()

    addr := net.JoinHostPort(stream.Listen.Ip, strconv.Itoa(stream.Listen.Port))
    log.Info().Str("stream", stream.Name).Str("addr", addr).Msg("UDP stream listening")
    return &udpStreamServer{conn: conn, cancel: cancel, done: done}, nil
}
