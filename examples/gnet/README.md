# High-Performance Event-Driven JWT Gateway (`zerojwt/v2` + `gnet`)

**English** | [Português](README_pt-BR.md)

This practical example demonstrates how to build an ultra-high-performance TCP Authentication Gateway integrating **`zerojwt/v2`** with the event-driven network framework **`gnet`**.

---

## Architectural Pillars

```
+----------------------------------------------------------------------------------------------------+
|                                    zerojwt/v2 + gnet Architecture                                  |
+----------------------------------------------------------------------------------------------------+
|                                                                                                    |
|  [ Inbound TCP Packet via gnet.Conn ]                                                              |
|                     |                                                                              |
|                     v                                                                              |
|       +----------------------------+                                                               |
|       |  OnTraffic(c gnet.Conn)    |                                                               |
|       +----------------------------+                                                               |
|                     |                                                                              |
|      +--------------+--------------+                                                               |
|      |                             |                                                               |
|      v                             v                                                               |
| [ Single Buffer Token ]    [ Split RingBuffer Token (head + tail) ]                                |
|      |                             |                                                               |
|      |                             v                                                               |
|      |                 zerojwt.VerifySplitWithScratch(head, tail, ...)                             |
|      |                 (Base64URL decoding with 4-byte stack quantum boundary seam stitching)      |
|      |                             |                                                               |
|      +--------------+--------------+                                                               |
|                     |                                                                              |
|                     v                                                                              |
|     [ WorkerScratchGroup.For(workerID) ]                                                           |
|     - Scratch pinned per EventLoop worker                                                          |
|     - PaddedScratch: Strict 64-byte CPU cache-line alignment                                       |
|     - 0 CAS atomic lock contention (eliminates sync.Pool)                                          |
|     - 0 false sharing across CPU cores                                                             |
|     - 0 heap allocations (0 B/op, 0 allocs/op)                                                     |
|                     |                                                                              |
|                     v                                                                              |
|  [ Token Emission: SignToIOV + c.Writev ]                                                          |
|     - iov[0] points to static pre-encoded header ("eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9.")        |
|     - iov[1] points to payload.signature generated directly in stack/scratch                      |
|     - Transmitted via unix.Writev / c.Writev without copying header into dst                       |
|                                                                                                    |
+----------------------------------------------------------------------------------------------------+
```

---

## Supported Protocol

The server accepts newline-delimited text commands (`\n`):

| Command | Description | zerojwt/v2 Primitive Used |
| :--- | :--- | :--- |
| `PING` | Basic health check | Immediate response: `PONG\n` |
| `LOGIN <user>` | Issues a signed JWT token for the user | `SignClaimsToIOVWithScratch` + `c.Writev` |
| `AUTH <token>` | Validates the incoming token | `VerifyWithScratch` |
| `SPLIT <token>` | Simulates ring-buffer fragmented token | `VerifySplitWithScratch` |
| `SPLIT_ITER <token>` | Iterates claims across fragmented ring buffer | `IterSplitWithScratch` |
| `ROTATE <jwks_json>` | Hot-swaps keys in live traffic without downtime | `UpdateKeysFromJWKS` |

---

## How to Run

### 1. Start the Server

```bash
go run main.go -port 9000 -loops 4
```

### 2. Test via Netcat / Telnet

```bash
# 1. Health check
echo "PING" | nc 127.0.0.1 9000

# 2. Login and retrieve token (vectorized via Writev)
TOKEN=$(echo "LOGIN alice" | nc 127.0.0.1 9000 | cut -d' ' -f2)

# 3. Authenticate with worker-pinned Scratch
echo "AUTH $TOKEN" | nc 127.0.0.1 9000

# 4. Partitioned verification (simulating ring-buffer boundary wrap-around)
echo "SPLIT $TOKEN" | nc 127.0.0.1 9000
```

### 3. Run Test Suite with Race Detector

```bash
go test -v -race .
```
