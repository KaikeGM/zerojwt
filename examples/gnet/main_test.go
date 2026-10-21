package main

import (
	"bufio"
	"bytes"
	"fmt"
	"net"
	"sync"
	"testing"
	"time"

	"github.com/panjf2000/gnet/v2"
)

func getFreePort(t *testing.T) int {
	l, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatalf("failed to listen on random port: %v", err)
	}
	defer l.Close()
	return l.Addr().(*net.TCPAddr).Port
}

func TestGnetZeroJWTServer(t *testing.T) {
	secret := []byte("01234567890123456789012345678901") // 32 bytes
	port := getFreePort(t)
	loops := 4

	srv, err := NewAuthServer(secret, loops)
	if err != nil {
		t.Fatalf("NewAuthServer failed: %v", err)
	}

	addr := fmt.Sprintf("tcp://127.0.0.1:%d", port)
	tcpAddr := fmt.Sprintf("127.0.0.1:%d", port)

	// Run gnet in background
	errCh := make(chan error, 1)
	go func() {
		err := gnet.Run(srv, addr,
			gnet.WithMulticore(true),
			gnet.WithNumEventLoop(loops),
			gnet.WithReusePort(true),
			gnet.WithTCPNoDelay(gnet.TCPNoDelay),
		)
		errCh <- err
	}()

	srv.WaitReady()
	// Allow small window for OS to bind socket
	time.Sleep(50 * time.Millisecond)

	defer func() {
		_ = srv.Stop()
	}()

	// 1. Test PING
	conn, err := net.Dial("tcp", tcpAddr)
	if err != nil {
		t.Fatalf("net.Dial failed: %v", err)
	}
	defer conn.Close()

	reader := bufio.NewReader(conn)
	_, _ = conn.Write([]byte("PING\n"))
	resp, err := reader.ReadString('\n')
	if err != nil || resp != "PONG\n" {
		t.Fatalf("PING failed: got %q, err: %v", resp, err)
	}

	// 2. Test LOGIN (SignToIOV + Writev)
	_, _ = conn.Write([]byte("LOGIN alice\n"))
	resp, err = reader.ReadString('\n')
	if err != nil {
		t.Fatalf("LOGIN read failed: %v", err)
	}
	if !bytes.HasPrefix([]byte(resp), []byte("OK ")) {
		t.Fatalf("LOGIN expected OK, got: %q", resp)
	}
	token := bytes.TrimSpace([]byte(resp)[3:])
	if len(token) == 0 {
		t.Fatalf("LOGIN token is empty")
	}

	// 3. Test AUTH (WorkerScratchGroup + Verify)
	_, _ = conn.Write(append([]byte("AUTH "), append(token, '\n')...))
	resp, err = reader.ReadString('\n')
	if err != nil || resp != "OK sub=alice\n" {
		t.Fatalf("AUTH failed: got %q, err: %v", resp, err)
	}

	// 4. Test SPLIT (VerifySplit)
	_, _ = conn.Write(append([]byte("SPLIT "), append(token, '\n')...))
	resp, err = reader.ReadString('\n')
	if err != nil || resp != "OK split_sub=alice\n" {
		t.Fatalf("SPLIT failed: got %q, err: %v", resp, err)
	}

	// 5. Test invalid token
	_, _ = conn.Write([]byte("AUTH invalid.token.value\n"))
	resp, err = reader.ReadString('\n')
	if err != nil || resp != "ERR: invalid or expired token\n" {
		t.Fatalf("AUTH invalid token expected error, got %q", resp)
	}

	// 6. Test short token on SPLIT
	_, _ = conn.Write([]byte("SPLIT ab\n"))
	resp, err = reader.ReadString('\n')
	if err != nil || resp != "ERR: token too short\n" {
		t.Fatalf("SPLIT short token expected error, got %q", resp)
	}

	// 7. Test invalid split token
	_, _ = conn.Write([]byte("SPLIT invalid.split.token\n"))
	resp, err = reader.ReadString('\n')
	if err != nil || resp != "ERR: split verification failed\n" {
		t.Fatalf("SPLIT invalid token expected error, got %q", resp)
	}

	// 8. Test empty username on LOGIN
	_, _ = conn.Write([]byte("LOGIN \n"))
	resp, err = reader.ReadString('\n')
	if err != nil || resp != "ERR: empty username\n" {
		t.Fatalf("LOGIN empty username expected error, got %q", resp)
	}

	// 9. Test unknown command
	_, _ = conn.Write([]byte("FOOBAR\n"))
	resp, err = reader.ReadString('\n')
	if err != nil || resp != "ERR: unknown command\n" {
		t.Fatalf("Unknown command expected error, got %q", resp)
	}

	// 10. Test SPLIT_ITER (IterSplitWithScratch)
	_, _ = conn.Write(append([]byte("SPLIT_ITER "), append(token, '\n')...))
	resp, err = reader.ReadString('\n')
	if err != nil || resp != "OK iter_sub=alice\n" {
		t.Fatalf("SPLIT_ITER failed: got %q, err: %v", resp, err)
	}

	// Test short token on SPLIT_ITER
	_, _ = conn.Write([]byte("SPLIT_ITER ab\n"))
	resp, err = reader.ReadString('\n')
	if err != nil || resp != "ERR: token too short\n" {
		t.Fatalf("SPLIT_ITER short token expected error, got %q", resp)
	}

	// Test invalid token on SPLIT_ITER
	_, _ = conn.Write([]byte("SPLIT_ITER invalid.split.token\n"))
	resp, err = reader.ReadString('\n')
	if err != nil || resp != "ERR: split iteration failed\n" {
		t.Fatalf("SPLIT_ITER invalid token expected error, got %q", resp)
	}

	// 11. Test ROTATE (UpdateKeysFromJWKS)
	_, _ = conn.Write([]byte("ROTATE invalid-jwks\n"))
	resp, err = reader.ReadString('\n')
	if err != nil || resp != "ERR: rotation failed\n" {
		t.Fatalf("ROTATE invalid JWKS expected error, got %q", resp)
	}

	validJWKS := `{"keys":[{"kty":"oct","kid":"key-2","k":"MDEyMzQ1Njc4OTAxMjM0NTY3ODkwMTIzNDU2Nzg5MDE"}]}`
	_, _ = conn.Write([]byte("ROTATE " + validJWKS + "\n"))
	resp, err = reader.ReadString('\n')
	if err != nil || resp != "OK keys_rotated\n" {
		t.Fatalf("ROTATE valid JWKS failed, got %q", resp)
	}

	// 12. High-concurrency test across multiple goroutines to verify WorkerScratchGroup & false sharing immunity
	var wg sync.WaitGroup
	numClients := 10
	iterations := 100

	for i := 0; i < numClients; i++ {
		wg.Add(1)
		go func(clientID int) {
			defer wg.Done()
			c, err := net.Dial("tcp", tcpAddr)
			if err != nil {
				t.Errorf("client %d dial failed: %v", clientID, err)
				return
			}
			defer c.Close()

			r := bufio.NewReader(c)
			username := fmt.Sprintf("user_%d", clientID)

			for j := 0; j < iterations; j++ {
				// Login
				_, _ = c.Write([]byte(fmt.Sprintf("LOGIN %s\n", username)))
				lResp, err := r.ReadString('\n')
				if err != nil || !bytes.HasPrefix([]byte(lResp), []byte("OK ")) {
					t.Errorf("client %d login failed: %v, resp: %s", clientID, err, lResp)
					return
				}
				tok := bytes.TrimSpace([]byte(lResp)[3:])

				// Auth
				_, _ = c.Write(append([]byte("AUTH "), append(tok, '\n')...))
				aResp, err := r.ReadString('\n')
				expectedSub := fmt.Sprintf("OK sub=%s\n", username)
				if err != nil || aResp != expectedSub {
					t.Errorf("client %d auth failed: %v, expected %q, got %q", clientID, err, expectedSub, aResp)
					return
				}

				// Split Auth
				_, _ = c.Write(append([]byte("SPLIT "), append(tok, '\n')...))
				sResp, err := r.ReadString('\n')
				expectedSplit := fmt.Sprintf("OK split_sub=%s\n", username)
				if err != nil || sResp != expectedSplit {
					t.Errorf("client %d split auth failed: %v, expected %q, got %q", clientID, err, expectedSplit, sResp)
					return
				}
			}
		}(i)
	}

	wg.Wait()
}

func BenchmarkGnet_AUTH(b *testing.B) {
	secret := []byte("01234567890123456789012345678901")
	l, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		b.Fatalf("listen failed: %v", err)
	}
	port := l.Addr().(*net.TCPAddr).Port
	_ = l.Close()

	srv, err := NewAuthServer(secret, 4)
	if err != nil {
		b.Fatalf("NewAuthServer failed: %v", err)
	}

	addr := fmt.Sprintf("tcp://127.0.0.1:%d", port)
	tcpAddr := fmt.Sprintf("127.0.0.1:%d", port)

	go func() {
		_ = gnet.Run(srv, addr,
			gnet.WithMulticore(true),
			gnet.WithNumEventLoop(4),
			gnet.WithReusePort(true),
			gnet.WithTCPNoDelay(gnet.TCPNoDelay),
		)
	}()

	srv.WaitReady()
	time.Sleep(50 * time.Millisecond)
	defer func() { _ = srv.Stop() }()

	conn, err := net.Dial("tcp", tcpAddr)
	if err != nil {
		b.Fatalf("dial failed: %v", err)
	}
	defer conn.Close()
	r := bufio.NewReader(conn)

	// Obtain token
	_, _ = conn.Write([]byte("LOGIN benchmark_user\n"))
	lResp, err := r.ReadString('\n')
	if err != nil {
		b.Fatalf("login failed: %v", err)
	}
	tok := bytes.TrimSpace([]byte(lResp)[3:])
	cmd := append([]byte("AUTH "), append(tok, '\n')...)

	b.ResetTimer()
	b.ReportAllocs()

	for i := 0; i < b.N; i++ {
		_, _ = conn.Write(cmd)
		_, _ = r.ReadString('\n')
	}
}
