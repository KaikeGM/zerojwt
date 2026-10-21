# Gateway JWT Orientado a Eventos de Alta Performance (`zerojwt/v2` + `gnet`)

[English](README.md) | **Português**

Este exemplo prático demonstra como construir um Gateway de Autenticação TCP de ultra-alta performance integrando o **`zerojwt/v2`** com a biblioteca de rede orientada a eventos **`gnet`**.

---

## Pilares de Arquitetura

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
|      |                 (Decodificação Base64 com costura quântica de 4B na stack)                  |
|      |                             |                                                               |
|      +--------------+--------------+                                                               |
|                     |                                                                              |
|                     v                                                                              |
|     [ WorkerScratchGroup.For(workerID) ]                                                           |
|     - Scratch fixado por EventLoop                                                                 |
|     - PaddedScratch: Alinhamento estrito de 64 bytes (L1/L2 Cache Line)                            |
|     - 0 contenção de CAS (elimina sync.Pool)                                                       |
|     - 0 false sharing entre núcleos de CPU                                                         |
|     - 0 alocações na heap (0 B/op, 0 allocs/op)                                                     |
|                     |                                                                              |
|                     v                                                                              |
|  [ Emissão de Token: SignToIOV + c.Writev ]                                                        |
|     - iov[0] aponta para cabeçalho estático ("eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9.")              |
|     - iov[1] aponta para payload.assinatura gerados em stack/scratch                               |
|     - Transmissão via unix.Writev / c.Writev sem copiar cabeçalho para dst                         |
|                                                                                                    |
+----------------------------------------------------------------------------------------------------+
```

---

## Protocolo Suportado

O servidor aceita comandos em texto delimitados por `\n`:

| Comando | Descrição | Primitiva zerojwt/v2 Utilizada |
| :--- | :--- | :--- |
| `PING` | Health check básico | Resposta imediata `PONG\n` |
| `LOGIN <user>` | Gera um token JWT assinado para o usuário | `SignClaimsToIOVWithScratch` + `c.Writev` |
| `AUTH <token>` | Valida o token recebido | `VerifyWithScratch` |
| `SPLIT <token>` | Simula token particionado no anel circular | `VerifySplitWithScratch` |
| `SPLIT_ITER <token>` | Itera sobre as claims no anel circular fragmentado | `IterSplitWithScratch` |
| `ROTATE <jwks_json>` | Troca de chaves a quente sem downtime | `UpdateKeysFromJWKS` |

---

## Como Executar

### 1. Executar o Servidor

```bash
go run main.go -port 9000 -loops 4
```

### 2. Testar via Netcat / Telnet

```bash
# 1. Health check
echo "PING" | nc 127.0.0.1 9000

# 2. Login e obtenção de token (vetorizado via Writev)
TOKEN=$(echo "LOGIN alice" | nc 127.0.0.1 9000 | cut -d' ' -f2)

# 3. Autenticação com Scratch fixado no worker
echo "AUTH $TOKEN" | nc 127.0.0.1 9000

# 4. Verificação particionada (simulando quebra de anel circular)
echo "SPLIT $TOKEN" | nc 127.0.0.1 9000
```

### 3. Executar a Suíte de Testes com Race Detector

```bash
go test -v -race .
```
