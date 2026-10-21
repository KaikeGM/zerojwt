package main

import (
	"bytes"
	"context"
	"flag"
	"fmt"
	"log"
	"os"
	"os/signal"
	"runtime"
	"sync"
	"syscall"
	"time"

	"github.com/KaikeGM/zerojwt/v2"
	"github.com/panjf2000/gnet/v2"
)

// AuthServer implements gnet.EventHandler using zerojwt/v2 primitives.
type AuthServer struct {
	*gnet.BuiltinEventEngine
	verifier      *zerojwt.Verifier
	workers       *zerojwt.WorkerScratchGroup
	numEventLoops int
	loopMap       sync.Map
	mapMu         sync.Mutex
	nextWorkerID  int
	eng           gnet.Engine
	ready         chan struct{}
}

// NewAuthServer initializes the server with worker-pinned Scratch pools.
func NewAuthServer(secret []byte, numLoops int) (*AuthServer, error) {
	if numLoops <= 0 {
		numLoops = runtime.NumCPU()
	}

	v, err := zerojwt.New(secret)
	if err != nil {
		return nil, fmt.Errorf("failed to create zerojwt verifier: %w", err)
	}

	return &AuthServer{
		verifier:      v,
		workers:       zerojwt.NewWorkerScratchGroup(v, numLoops),
		numEventLoops: numLoops,
		ready:         make(chan struct{}),
	}, nil
}

// WaitReady blocks until the gnet engine has booted and is accepting connections.
func (s *AuthServer) WaitReady() {
	<-s.ready
}

// Stop gracefully terminates the gnet engine.
func (s *AuthServer) Stop() error {
	return s.eng.Stop(context.Background())
}

// OnBoot captures the engine reference upon startup.
func (s *AuthServer) OnBoot(eng gnet.Engine) gnet.Action {
	s.eng = eng
	select {
	case <-s.ready:
	default:
		close(s.ready)
	}
	log.Printf("[zerojwt-gnet] Server booted with %d eventloops and cache-padded scratch workers", s.numEventLoops)
	return gnet.None
}

// OnOpen pins each connection to its respective EventLoop worker Scratch.
func (s *AuthServer) OnOpen(c gnet.Conn) (out []byte, action gnet.Action) {
	el := c.EventLoop()
	val, ok := s.loopMap.Load(el)
	var workerID int
	if ok {
		workerID = val.(int)
	} else {
		s.mapMu.Lock()
		val, ok = s.loopMap.Load(el)
		if ok {
			workerID = val.(int)
		} else {
			workerID = s.nextWorkerID
			s.nextWorkerID = (s.nextWorkerID + 1) % s.numEventLoops
			s.loopMap.Store(el, workerID)
		}
		s.mapMu.Unlock()
	}
	c.SetContext(workerID)
	return nil, gnet.None
}

// OnTraffic handles inbound TCP packets with 0 heap allocations.
func (s *AuthServer) OnTraffic(c gnet.Conn) gnet.Action {
	workerID := c.Context().(int)
	scratch := s.workers.For(workerID)

	for {
		buffered := c.InboundBuffered()
		if buffered == 0 {
			break
		}

		buf, err := c.Peek(buffered)
		if err != nil || len(buf) == 0 {
			break
		}

		idx := bytes.IndexByte(buf, '\n')
		if idx < 0 {
			// Incomplete line, wait for more TCP packets
			break
		}

		line := buf[:idx]

		// Strip trailing CR if CRLF
		if len(line) > 0 && line[len(line)-1] == '\r' {
			line = line[:len(line)-1]
		}

		// Handle command before discarding bytes to prevent use-after-free
		s.handleCommand(c, line, scratch)
		_, _ = c.Discard(idx + 1)
	}

	return gnet.None
}

func (s *AuthServer) handleCommand(c gnet.Conn, line []byte, scratch *zerojwt.Scratch) {
	now := time.Now().Unix()

	// 1. PING -> PONG
	if bytes.Equal(line, []byte("PING")) {
		_, _ = c.Write([]byte("PONG\n"))
		return
	}

	// 2. LOGIN <username> -> Emits JWT using SignToIOV + c.Writev (Zero-Alloc Vectorized Write)
	if bytes.HasPrefix(line, []byte("LOGIN ")) {
		username := string(line[6:])
		if len(username) == 0 {
			_, _ = c.Write([]byte("ERR: empty username\n"))
			return
		}

		var dst [512]byte
		var iov [2][]byte
		err := s.verifier.SignClaimsToIOVWithScratch(dst[:0], zerojwt.StandardClaims{
			Subject:   username,
			Username:  username,
			IssuedAt:  now,
			ExpiresAt: now + 3600,
		}, &iov, scratch)
		if err != nil {
			_, _ = c.Write([]byte("ERR: token signing failed\n"))
			return
		}

		// Vectorized write: Header (37B) + Payload.Signature + Newline without copying
		var batch = [4][]byte{
			[]byte("OK "),
			iov[0],
			iov[1],
			[]byte("\n"),
		}
		_, _ = c.Writev(batch[:])
		return
	}

	// 3. AUTH <token> -> Verifies token using worker-pinned scratch
	if bytes.HasPrefix(line, []byte("AUTH ")) {
		token := line[5:]
		var claims zerojwt.Claims
		if err := s.verifier.VerifyWithScratch(token, now, &claims, scratch); err != nil {
			_, _ = c.Write([]byte("ERR: invalid or expired token\n"))
			return
		}

		var resp [256]byte
		n := copy(resp[:], "OK sub=")
		n += copy(resp[n:], claims.Subject())
		resp[n] = '\n'
		n++
		_, _ = c.Write(resp[:n])
		return
	}

	// 4. SPLIT <token> -> Simulates circular ring buffer boundary using VerifySplit
	if bytes.HasPrefix(line, []byte("SPLIT ")) {
		token := line[6:]
		if len(token) < 4 {
			_, _ = c.Write([]byte("ERR: token too short\n"))
			return
		}

		// Split arbitrarily down the middle to simulate ring wrap-around
		splitPoint := len(token) / 2
		head := token[:splitPoint]
		tail := token[splitPoint:]

		var claims zerojwt.Claims
		if err := s.verifier.VerifySplitWithScratch(head, tail, now, &claims, scratch); err != nil {
			_, _ = c.Write([]byte("ERR: split verification failed\n"))
			return
		}

		var resp [256]byte
		n := copy(resp[:], "OK split_sub=")
		n += copy(resp[n:], claims.Subject())
		resp[n] = '\n'
		n++
		_, _ = c.Write(resp[:n])
		return
	}

	_, _ = c.Write([]byte("ERR: unknown command\n"))
}

func main() {
	port := flag.Int("port", 9000, "TCP port to bind")
	loops := flag.Int("loops", runtime.NumCPU(), "Number of event-loop worker goroutines")
	secretStr := flag.String("secret", "super-secret-key-that-is-at-least-32-bytes-long!", "HS256 secret key")
	flag.Parse()

	server, err := NewAuthServer([]byte(*secretStr), *loops)
	if err != nil {
		log.Fatalf("Server initialization failed: %v", err)
	}

	addr := fmt.Sprintf("tcp://0.0.0.0:%d", *port)
	log.Printf("Starting zerojwt-gnet server on %s with %d loops...", addr, *loops)

	// Run gnet in background and wait for OS signal
	go func() {
		err := gnet.Run(server, addr,
			gnet.WithMulticore(true),
			gnet.WithNumEventLoop(*loops),
			gnet.WithReusePort(true),
			gnet.WithTCPNoDelay(gnet.TCPNoDelay),
		)
		if err != nil {
			log.Fatalf("gnet engine exited with error: %v", err)
		}
	}()

	sigCh := make(chan os.Signal, 1)
	signal.Notify(sigCh, os.Interrupt, syscall.SIGTERM)
	<-sigCh

	log.Println("Shutting down zerojwt-gnet server...")
}
