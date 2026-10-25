# ⚡ zerojwt v2 (`github.com/KaikeGM/zerojwt/v2`)

[English](README.md) | **Português**

Assinatura, verificação e streaming de propriedades JSON de JWT de ultra-alta performance e zero alocações em Go 1.23+.

[![Go Reference](https://pkg.go.dev/badge/github.com/KaikeGM/zerojwt/v2.svg)](https://pkg.go.dev/github.com/KaikeGM/zerojwt/v2)
[![Coverage: 100%](https://img.shields.io/badge/coverage-100%25-brightgreen.svg)](#)
[![Allocations: 0](https://img.shields.io/badge/allocations-0_allocs%2Fop-blue.svg)](#)
[![License: MIT](https://img.shields.io/badge/License-MIT-yellow.svg)](../LICENSE)

---

## 📑 Sumário

- [O que há de novo na v2](#o-que-há-de-novo-na-v2)
- [Benchmarks](#benchmarks)
- [Arquitetura e Modelo de Memória](#arquitetura-e-modelo-de-memória)
- [Instalação](#instalação)
- [Início Rápido](#início-rápido)
- [Algoritmos Criptográficos](#algoritmos-criptográficos)
  - [Simétrico: HS256, HS384, HS512](#1-simétrico-hmac-hs256-hs384-hs512)
  - [Assimétrico: EdDSA (Ed25519)](#2-assimétrico-eddsa-ed25519--rfc-8037)
  - [Assimétrico: ES256, ES384, ES512 (ECDSA)](#3-assimétrico-es256-es384-es512-ecdsa--rfc-7518)
  - [Assimétrico: RS256 (RSA PKCS#1 v1.5)](#4-assimétrico-rs256-rsa-pkcs1-v15--rfc-7518)
- [Validação RFC 7519 e Claims](#validação-rfc-7519-e-claims)
  - [Struct Única e Unificada Claims](#struct-única-e-unificada-claims)
  - [Tolerância de Desvio de Relógio (Leeway)](#tolerância-de-desvio-de-relógio-leeway)
  - [Validação de Emissor (iss) e Audiência (aud)](#validação-de-emissor-iss-e-audiência-aud)
  - [Identificador JWT (jti) e Prevenção contra Replay](#identificador-jwt-jti-e-prevenção-contra-replay)
- [Claims Customizadas e SignBuilder Fluente](#claims-customizadas-e-signbuilder-fluente)
  - [SignBuilder Fluente (0 allocs/op)](#signbuilder-fluente-0-allocsop)
  - [Escape Genérico de Strings JSON (0 allocs/op)](#escape-genérico-de-strings-json-0-allocsop)
  - [Iterador Atômico de Claims (Go 1.23 iter.Seq2 & IterSplit)](#iterador-atômico-de-claims-go-123-iterseq2--itersplit)
- [Primitivas de Rede para Arquiteturas Orientadas a Eventos (gnet, evio, epoll)](#primitivas-de-rede-para-arquiteturas-orientadas-a-eventos-gnet-evio-epoll)
  - [Validação em Buffer Circular Fragmentado (VerifySplit)](#1-validação-em-buffer-circular-fragmentado-verifysplit)
  - [Workspaces com Afinidade de Worker e Padding de Cache (WorkerScratchGroup)](#2-workspaces-com-afinidade-de-worker-e-padding-de-cache-workerscratchgroup)
  - [Assinatura Vetorizada Scatter/Gather (SignToIOV)](#3-assinatura-vetorizada-scattergather-signtoiov)
  - [Exemplo Completo de Gateway](#exemplo-completo-de-gateway)
- [Rotação de Chaves e Parser Nativo de JWKS (RFC 7517)](#rotação-de-chaves-e-parser-nativo-de-jwks-rfc-7517)
  - [Registro Estático de Múltiplas Chaves](#1-registro-estático-de-múltiplas-chaves-kid)
  - [Rotação Dinâmica Lock-Free (UpdateKeys)](#2-rotação-dinâmica-lock-free-updatekeys)
  - [Parser Nativo de JWKS RFC 7517 (UpdateKeysFromJWKS)](#3-parser-nativo-de-jwks-rfc-7517-updatekeysfromjwks)
- [Middlewares HTTP de Alta Performance](#middlewares-http-de-alta-performance)
  - [ProtectFunc (0 allocs/op)](#1-protectfunc-o-mais-rápido-zero-alocação)
  - [Middleware net/http Padrão](#2-middleware-nethttp-padrão)
  - [VerifyBearer](#3-verifybearer)
  - [ForwardAuth Pronto para Uso para Nginx e Traefik](#4-forwardauth-pronto-para-uso-para-nginx-e-traefik)
- [Endurecimento de Segurança e Higiene de Memória](#endurecimento-de-segurança-e-higiene-de-memória)
- [Otimização Guiada por Perfil (PGO)](#otimização-guiada-por-perfil-pgo)
- [Referência de Erros Sentinela](#referência-de-erros-sentinela)
- [Guia de Migração da v1 para a v2](#guia-de-migração-da-v1-para-a-v2)
- [Licença](#licença)

---

## O que há de novo na v2

O `zerojwt/v2` representa a evolução unificada e blindada do `zerojwt`, eliminando a dicotomia histórica de dois verificadores da v1 e garantindo **0 alocações na heap (0 B/op, 0 allocs/op)** em todos os fluxos de assinatura e verificação HS256 e Ed25519.

### Principais Pilares Arquiteturais

1. **Struct `Claims` Única e Unificada (1016 Bytes, Zero Alocações)**
   - Substitui os tipos separados `Claims` e `ClaimsLarge` da v1 por uma struct unificada.
   - Conformidade estrita com o **OIDC Core 1.0 §2**: Buffer do Subject (`sub`) expandido para 256 bytes (suportando até 255 caracteres ASCII).
   - Alinhamento de palavra de 8 bytes na CPU (56 bytes de flags/tamanhos, 6 bytes de padding explícito, buffers contíguos para `sub` [256B], `iss` [256B], `aud` [256B], `user` [128B] e `jti` [64B]).
   - Validado via `unsafe.Sizeof(Claims{}) == 1016` e `unsafe.Alignof(Claims{}) == 8`.

2. **Construtor Seguro por Padrão**
   - `New(secret, ...Options)` é estritamente seguro por padrão:
     - **RFC 7518 §3.2**: Rejeita chaves menores que o tamanho de hash do algoritmo (32 bytes para HS256, 48 para HS384, 64 para HS512) com `ErrInvalidConfig` (ou alias `ErrInsecureSecret`).
     - **OIDC Core 1.0 §3.1.3.7 / RFC 9068 §2.2**: Rejeita tokens sem a claim `exp` com `ErrMissingExp`.
   - Opções explícitas de opt-out para migração legada: `Options{AllowShortSecret: true, AllowMissingExp: true}`.

3. **Validação Cruzada de Pares de Chaves no Boot**
   - `NewEd25519Verifier`: Valida que `priv.Public()` corresponde à `pub` com `ErrMismatchedKeyPair`.
   - `NewES256Verifier`: Valida que `priv.PublicKey` corresponde à `pub`, e checa os limites do escalar $1 \le D < N$ conforme RFC 7518 §3.4.

4. **Contrato Idiomático de Append com Rollback Zero-Alloc**
   - Métodos de assinatura (`Sign`, `SignClaims`, `SignBuilder`) retornam `([]byte, error)`.
   - Segue o padrão idiomático `append` do Go: adiciona os bytes do token ao `dst` fornecido pelo chamador.
   - Em caso de erro, `dst` é revertido ao seu tamanho original, preservando a capacidade pré-alocada sem corromper a saída parcial.

5. **Função Genérica `AppendEscapedJSON[S ~string | ~[]byte]`**
   - Escapa strings de usuário ou slices de bytes para strings JSON sem conversões intermediárias.
   - UUIDs dinâmicos de 36 bytes são formatados nos tokens com **0 alocações na heap**.

6. **Iterador Atômico de Claims (`Iter`)**
   - Utiliza os iteradores padrão do Go 1.23 (`iter.Seq2[JSONProp, error]`).
   - Garantia de atomicidade: claims são emitidas **se e somente se** o token for 100% criptograficamente verificado e estruturalmente válido. Qualquer defeito de assinatura ou cabeçalho aborta a iteração antes de emitir qualquer claim.

7. **Primitivas de Rede para Arquiteturas Orientadas a Eventos (`gnet`, `evio`, `epoll`)**
   - **`VerifySplit(head, tail, now, &claims)`**: Valida tokens fragmentados na borda de buffers circulares descontínuos com 0 alocações via costura quântica de Base64 (~11.3 ns de sobrecarga).
   - **`WorkerScratchGroup`**: Array de workspaces fixados por worker com padding explícito de linha de cache de 64 bytes (`PaddedScratch`), eliminando contenção de CAS de `sync.Pool` e invalidações de cache L1/L2 (*false sharing*) (~158.4 ns/op paralelo).
   - **`SignToIOV(dst, pl, &iov)`**: Assinatura scatter/gather vetorizada para `unix.Writev` / `gnet.Conn.Writev`. Ignora a cópia do cabeçalho de 37 bytes e transmite diretamente via `[2][]byte`.

8. **100.0% de Cobertura de Instruções & Zero Race Conditions**
   - Todos os branches, erros sentinela, rotação de chaves, tokens particionados e vetores IOV verificados com 100.0% de cobertura.
   - Testado e limpo sob `go test -race` e `go vet`.

---

## Benchmarks

Medido em Linux amd64 (11th Gen Intel Core i5-1135G7 @ 2.40GHz, Go 1.24):

### API Padrão

| Benchmark | Descrição | Latência | Memória / op | Alocs / op |
| :--- | :--- | :---: | :---: | :---: |
| `BenchmarkVerifyHS256` | Verificação HS256 em núcleo único | **706.6 ns/op** | **0 B/op** | **0 allocs/op** |
| `BenchmarkVerifyLargeSubject` | Subject com 250 bytes (limite OIDC) | **1170.0 ns/op** | **0 B/op** | **0 allocs/op** |
| `BenchmarkSignHS256` | Assinatura de payload bruto | **348.2 ns/op** | **0 B/op** | **0 allocs/op** |
| `BenchmarkSignClaims` | Assinatura de claims registradas padrão | **417.2 ns/op** | **0 B/op** | **0 allocs/op** |
| `BenchmarkSignBuilder` | Construtor fluente dinâmico | **464.0 ns/op** | **0 B/op** | **0 allocs/op** |

### Primitivas de Rede e Event-Driven (`gnet`, `evio`, `epoll`)

| Benchmark | Descrição | Latência | Memória / op | Alocs / op |
| :--- | :--- | :---: | :---: | :---: |
| `BenchmarkVerifyHS256_Contiguous` | Baseline em buffer contíguo | **556.9 ns/op** | **0 B/op** | **0 allocs/op** |
| `BenchmarkVerifyHS256_VerifySplit` | Token fragmentado entre `head` e `tail` do anel | **564.8 ns/op** | **0 B/op** | **0 allocs/op** |
| `BenchmarkVerifyParallel_SyncPool` | Alta concorrência via `sync.Pool` | **162.2 ns/op** | **0 B/op** | **0 allocs/op** |
| `BenchmarkVerifyParallel_WorkerScratchGroup` | Alta concorrência com worker fixado e cache alinhado (64B) | **158.4 ns/op** | **0 B/op** | **0 allocs/op** |
| `BenchmarkSignHS256_Standard` | Emissão de token em buffer único | **349.5 ns/op** | **0 B/op** | **0 allocs/op** |
| `BenchmarkSignHS256_SignToIOV` | Emissão vetorial scatter/gather para `unix.Writev` / `Conn.Writev` | **355.8 ns/op** | **0 B/op** | **0 allocs/op** |

---

## Arquitetura e Modelo de Memória

```
+----------------------------------------------------------------------------------------------------+
|                                  Modelo de Memória zerojwt v2                                      |
+----------------------------------------------------------------------------------------------------+
|                                                                                                    |
|  [ Stack / Frame Local ]                                                                           |
|  +----------------------------------------------------------------------------------------------+  |
|  | Struct Claims (1016 Bytes, Alinhamento de Palavra de 8 Bytes)                                |  |
|  | - Claims Int64: iat, nbf, exp (24 bytes)                                                     |  |
|  | - Comprimentos e Flags: subLen, issLen, audLen, userLen, jtiLen, presentFlags (32 bytes)     |  |
|  | - Padding Explícito: 6 bytes (alinhamento em 8 bytes)                                        |  |
|  | - Buffers Contíguos: sub [256B], iss [256B], aud [256B], user [128B], jti [64B]              |  |
|  +----------------------------------------------------------------------------------------------+  |
|                                                  ^                                                 |
|                                                  | (Decodifica direto nos campos da pilha)         |
|                                                  |                                                 |
|  [ Workspace Scratch (3512 Bytes, Gerenciado por Worker ou Pool) ]                                 |
|  +----------------------------------------------------------------------------------------------+  |
|  | - Hashers HMAC pré-inicializados e versão de chaves (mac, keyMacs, keyVersion [8B])          |  |
|  | - Buffer de Assinatura: sigBuf [512B] (suporta RSA-2048/3072/4096, ES512)                    |  |
|  | - Buffer de Checksum: sumBuf [64B]                                                           |  |
|  | - Buffer de Decodificação DER: derBuf [144B] (P-256, P-384, P-521 formato longo DER)         |  |
|  | - Buffer Scratch de Cabeçalho: hdrArr [128B] / hdrBuf                                        |  |
|  | - Buffer Scratch de Payload: payloadArr [1024B] / payloadBuf                                 |  |
|  | - Buffer de Montagem de Assinatura: signArr [1544B] (Base64 Header + '.' + Payload)          |  |
|  +----------------------------------------------------------------------------------------------+  |
|                                                                                                    |
|  -> Zero alocações dinâmicas na heap                                                               |
|  -> Zero uso de reflexão (reflect)                                                                 |
|  -> Zero pausas do Garbage Collector em caminhos críticos                                          |
|                                                                                                    |
+----------------------------------------------------------------------------------------------------+
```

---

## Instalação

```bash
go get github.com/KaikeGM/zerojwt/v2
```

Requer **Go 1.23.0** ou superior.

---

## Início Rápido

### Assinatura e Verificação Básica (HS256)

> [!TIP]
> **Configuração Zero & Pool Automático de Workspaces:**
> Os métodos padrão (`v.Verify`, `v.VerifyNow`, `v.VerifyBearerNow`, `v.Sign`, `v.SignClaims`) gerenciam automaticamente os workspaces pré-alocados através de um `sync.Pool` lock-free embutido, com garantia de **`0 B/op` e `0 allocs/op`**.
> Você **não precisa** instanciar `Scratch` nem gerenciar pools manualmente. Primitivas avançadas como `Scratch` e `WorkerScratchGroup` são otimizações estritamente opcionais para arquiteturas orientadas a eventos de baixíssima latência (`gnet`, `evio`, `epoll`).

```go
package main

import (
	"fmt"
	"time"

	"github.com/KaikeGM/zerojwt/v2"
)

func main() {
	secret := []byte("sua-chave-ultra-segura-de-32-bytes!")
	
	// Construtor seguro por padrão (exige chave >= 32B e exp presente)
	v, err := zerojwt.New(secret)
	if err != nil {
		panic(err)
	}

	now := time.Now().Unix()

	// 1. Assinar claims padrão (0 alocações na heap)
	token, err := v.SignClaims(nil, zerojwt.StandardClaims{
		Subject:   "usr_9847239847",
		Username:  "alex_dev",
		IssuedAt:  now,
		ExpiresAt: now + 3600, // Obrigatório por padrão
	})
	if err != nil {
		panic(err)
	}

	// 2. Verificar na struct Claims pré-alocada na pilha (0 alocações na heap)
	// Você pode usar v.Verify(token, now, &claims) ou o prático v.VerifyNow(token, &claims):
	var claims zerojwt.Claims
	if err := v.VerifyNow(token, &claims); err != nil {
		panic(err)
	}

	fmt.Printf("Autenticado: %s (%s)\n", claims.Subject(), claims.Username())
}
```

---

## Algoritmos Criptográficos

### 1. Simétrico HMAC: HS256, HS384, HS512

O `zerojwt/v2` valida as chaves HMAC na inicialização contra os limites mínimos de tamanho da RFC 7518 §3.2:

```go
// HS256: segredo >= 32 bytes
v256, err := zerojwt.New(secret32)

// HS384: segredo >= 48 bytes
v384, err := zerojwt.New(secret48, zerojwt.Options{
    Algorithm: zerojwt.AlgHS384,
})

// HS512: segredo >= 64 bytes
v512, err := zerojwt.New(secret64, zerojwt.Options{
    Algorithm: zerojwt.AlgHS512,
})
```

### 2. Assimétrico: EdDSA (Ed25519 / RFC 8037)

Verificação assimétrica ultra-rápida (~1.8 µs/op) com zero alocações e checagem cruzada do par de chaves no boot:

```go
pub, priv, err := ed25519.GenerateKey(rand.Reader)
if err != nil {
    panic(err)
}

// Emissor + Verificador completo (valida se priv.Public() == pub)
v, err := zerojwt.NewEd25519Verifier(pub, priv)

// Apenas Verificador (chave pública)
vVerifOnly, err := zerojwt.NewEd25519Verifier(pub, nil)
```

### 3. Assimétrico: ES256, ES384, ES512 (ECDSA / RFC 7518)

Valida chaves NIST P-256, P-384 e P-521 com conversão estrita IEEE P1363 <-> ASN.1 DER, validação cruzada do par de chaves e checagem de limites escalares $1 \le D < N$:

```go
// ES256 (NIST P-256 com SHA-256)
priv256, _ := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
v256, err := zerojwt.NewES256Verifier(&priv256.PublicKey, priv256)

// ES384 (NIST P-384 com SHA-384)
priv384, _ := ecdsa.GenerateKey(elliptic.P384(), rand.Reader)
v384, err := zerojwt.NewES384Verifier(&priv384.PublicKey, priv384)

// ES512 (NIST P-521 com SHA-512, suporte a coordenadas de 66B e DER longo)
priv521, _ := ecdsa.GenerateKey(elliptic.P521(), rand.Reader)
v521, err := zerojwt.NewES512Verifier(&priv521.PublicKey, priv521)
```

### 4. Assimétrico: RS256 (RSA PKCS#1 v1.5 / RFC 7518)

Verificação assimétrica ultra-rápida (~28 µs/op com expoente público curto $e = 65537$), oferecendo compatibilidade nativa imediata com Auth0, Keycloak, Microsoft Entra ID, Google e AWS Cognito:

```go
privRSA, _ := rsa.GenerateKey(rand.Reader, 2048)

// Emissor + Verificador completo (validação cruzada priv.PublicKey == pub e priv.Validate())
vRSA, err := zerojwt.NewRS256Verifier(&privRSA.PublicKey, privRSA)

// Somente Verificador (apenas chave pública: impõe módulo de 2048-4096 bits, N ímpar, e >= 65537)
vRSAOnly, err := zerojwt.NewRS256Verifier(&privRSA.PublicKey, nil)
```

---

## Validação RFC 7519 e Claims

### Struct Única e Unificada Claims

Na v2, `Claims` e `ClaimsLarge` foram fundidas em uma única struct de 1016 bytes:

```go
var claims zerojwt.Claims
if err := v.Verify(token, now, &claims); err != nil {
    // trata o erro
}

// Métodos de Acesso a Claims Padrão (Zero Alocações: retornam []byte)
fmt.Printf("sub: %s\n", claims.Subject())        // []byte de até 256 bytes (OIDC Core §2)
fmt.Printf("user: %s\n", claims.Username())      // []byte de até 128 bytes
fmt.Printf("iss: %s\n", claims.Issuer())         // []byte de até 256 bytes
fmt.Printf("aud: %s\n", claims.Audience())       // []byte de até 256 bytes
fmt.Printf("jti: %s\n", claims.JTI())            // []byte de até 64 bytes
fmt.Println("exp:", claims.ExpiresAt)            // timestamp Unix int64
fmt.Println("iat:", claims.IssuedAt)             // timestamp Unix int64
fmt.Println("nbf:", claims.NotBefore)            // timestamp Unix int64
fmt.Println("subID:", claims.SubjectID)          // int64 (parseado se sub for numérico)

// Flags de Presença (Campos Booleanos Diretos)
if claims.HasExp { /* exp estava presente no token */ }
if claims.HasIss { /* iss estava presente no token */ }
if claims.HasAud { /* aud estava presente no token */ }
if claims.HasSub { /* sub estava presente no token */ }
if claims.HasJti { /* jti estava presente no token */ }
```

### Tolerância de Desvio de Relógio (Leeway)

```go
v, err := zerojwt.New(secret, zerojwt.Options{
    Leeway: 60 * time.Second, // Tolera até 1 minuto de drift no relógio do servidor
})
```

### Validação de Emissor (iss) e Audiência (aud)

```go
v, err := zerojwt.New(secret, zerojwt.Options{
    ExpectedIssuer:   "https://auth.minhaempresa.com",
    ExpectedAudience: "https://api.minhaempresa.com",
})
```

### Identificador JWT (jti) e Prevenção contra Replay

```go
// Lê o jti com zero alocações para checar em cache / bloom filter / bitset
if claims.HasJti {
    jti := claims.JTI()
    if isReplayed(jti) {
        return ErrInvalidToken
    }
}
```

---

## Claims Customizadas e SignBuilder Fluente

### SignBuilder Fluente (0 allocs/op)

```go
sb := v.NewSigner(nil)
token, err := sb.SetSubject("usr_12345").
    SetClaimString("role", "admin").
    SetClaimInt("tenant_id", 42).
    SetClaimBool("is_active", true).
    SetExpiresAt(now + 3600).
    Sign()
if err != nil {
    panic(err)
}
```

### Escape Genérico de Strings JSON (0 allocs/op)

A função `AppendEscapedJSON` formata strings ou fatias de bytes em JSON válido sem alocações intermediárias:

```go
buf := make([]byte, 0, 128)
buf = append(buf, `{"uuid":`...)
buf = zerojwt.AppendEscapedJSON(buf, "550e8400-e29b-41d4-a716-446655440000")
buf = append(buf, '}')
```

### Iterador Atômico de Claims (Go 1.23 `iter.Seq2` & `IterSplit`)

Itera sobre todas as propriedades JSON padrão e customizadas no payload verificado com zero alocações na heap usando `IterWithScratch` e `IterSplitWithScratch`:

```go
// Caminho de zero alocações (0 B/op, 0 allocs/op com scratch reutilizável/por worker):
scratch := workers.For(workerID) // ou v.NewScratch()

// Token contíguo:
for prop, err := range v.IterWithScratch(token, now, scratch) {
    if err != nil {
        panic(err) // Aborta se a assinatura ou validação temporal falhar
    }
    fmt.Printf("Claim %s = %s (isString: %v)\n", prop.Key, prop.Val, prop.IsStr)
}

// Token fragmentado em buffer circular (head + tail):
for prop, err := range v.IterSplitWithScratch(head, tail, now, scratch) {
    if err != nil {
        panic(err)
    }
    fmt.Printf("Claim Fragmentada %s = %s\n", prop.Key, prop.Val)
}
```

> [!NOTE]
> Por conveniência, `v.Iter(token, now)` e `v.IterSplit(head, tail, now)` também são fornecidos sem exigir um ponteiro de scratch explícito; eles adquirem workspaces dinamicamente via `sync.Pool` (~3 allocs/op no Go 1.23; 0 no Go 1.24+). Use `IterWithScratch` / `IterSplitWithScratch` para garantir 0 alocações na heap em todas as versões do Go (Go 1.23+).

---

## Primitivas de Rede para Arquiteturas Orientadas a Eventos (`gnet`, `evio`, `epoll`)

Desenvolvidas especificamente para event loops onde pacotes TCP chegam fragmentados em anéis circulares e threads de trabalho não podem disputar locks.

### 1. Validação em Buffer Circular Fragmentado (`VerifySplit`)

Quando um pacote TCP faz a volta no buffer de anel (`ring.Buffer.Peek(n)` do `gnet`), o token é dividido entre `head` e `tail`:

```go
// Streaming HMAC direto + costura quântica Base64 de 4B na pilha
// Sobrecarga de apenas ~7.9 ns em relação a buffer contíguo, com 0 B/op e 0 allocs/op!
var claims zerojwt.Claims
if err := v.VerifySplitWithScratch(head, tail, now, &claims, scratch); err != nil {
    // trata o erro
}
```

### 2. Workspaces com Afinidade de Worker e Padding de Cache (`WorkerScratchGroup`)

Elimina a contenção de CAS atômico (`LOCK CMPXCHG`) do `sync.Pool` e o *false sharing* de cache L1/L2 entre núcleos:

```go
// Pré-aloca 1 Scratch por eventloop, alinhado em linha de cache L1/L2 de 64 bytes
workers := zerojwt.NewWorkerScratchGroup(v, runtime.NumCPU())

// No callback do eventloop (resolução O(1), zero locks):
scratch := workers.For(workerID)
if err := v.VerifyWithScratch(token, now, &claims, scratch); err != nil {
    // trata o erro
}
```

### 3. Assinatura Vetorizada Scatter/Gather (`SignToIOV`)

Gera um vetor de I/O de 2 posições pronto para `unix.Writev` / `gnet.Conn.Writev`:

```go
var dst [512]byte
var iov [2][]byte

// iov[0] -> Aponta para o cabeçalho estático pré-codificado ("eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9.")
// iov[1] -> Aponta para payload.assinatura gerados diretamente em dst
err := v.SignClaimsToIOVWithScratch(dst[:0], zerojwt.StandardClaims{
    Subject:   "usr_123",
    ExpiresAt: now + 3600,
}, &iov, scratch)

// Envia direto ao socket do kernel sem copiar os 37 bytes de cabeçalho
conn.Writev(iov[:])
```

### Exemplo Completo de Gateway

Um gateway TCP de autenticação completo implementando as três primitivas com o `gnet` está disponível em [`examples/gnet`](../examples/gnet).

---

## Rotação de Chaves e Parser Nativo de JWKS (RFC 7517)

### 1. Registro Estático de Múltiplas Chaves (`kid`)

Verifica tokens assinados por chaves antigas enquanto emite novos tokens utilizando a chave ativa:

```go
v, err := zerojwt.New(primarySecret, zerojwt.Options{
    ActiveKeyID: "key-2026-v2", // Embutido nos novos tokens assinados
    Keys: []zerojwt.Key{
        {ID: "key-2026-v2", Secret: primarySecret},
        {ID: "key-2026-v1", Secret: retiredSecret}, // Ainda aceito para verificação
    },
})
```

### 2. Rotação Dinâmica Lock-Free (`UpdateKeys`)

Substitui atomicamente o conjunto de chaves `kid` durante tráfego em produção com zero downtime e zero locks via `atomic.Pointer`:

```go
// Substitui dinamicamente o conjunto de chaves durante o tráfego:
err := v.UpdateKeys([]zerojwt.Key{
    {ID: "key-2026-v3", Secret: nextGenSecret},
    {ID: "key-2026-v2", Secret: primarySecret},
})
```

### 3. Parser Nativo de JWKS RFC 7517 (`UpdateKeysFromJWKS`)

Analisa e ingere conjuntos padrão de chaves JSON Web Key Sets (RFC 7517) de Provedores de Identidade (ex: Auth0, Keycloak, Okta, AWS Cognito) com **0 dependências externas**:

```go
// Parser JWKS em Go puro (suporta oct, OKP/Ed25519, EC P-256/P-384/P-521 e RSA 2048-4096):
keys, err := zerojwt.ParseJWKS(jwksJSONBytes)

// Ou atualize o conjunto de chaves do Verifier diretamente a partir do JSON bruto sem downtime:
err = v.UpdateKeysFromJWKS(jwksJSONBytes)
```

#### Garantias Criptográficas e Conformidade com as RFCs:
- **Tamanhos Estritos de Coordenadas EC (RFC 7518 §6.2.1.2 e §6.2.1.3)**: Coordenadas `x` e `y` devem conter exatamente 32 octetos para P-256, 48 octetos para P-384 e 66 octetos para P-521. Truncamento de zeros à esquerda ou preenchimento com zeros adicionais são estritamente rejeitados.
- **Validação Estrita de Chaves RSA (RFC 7518 §6.3)**: Zeros à esquerda nas codificações `Base64urlUInt` de `n` e `e` são proibidos (`nBytes[0] == 0 || eBytes[0] == 0`). O módulo $N$ deve ser ímpar e ter entre 2048 e 4096 bits; o expoente público $E$ deve ser ímpar com $65537 \le E \le 2^{31}-1$.
- **Verificação de Curva no Padrão Wycheproof**: Valida chaves públicas contra a geometria da curva (`elliptic.Curve.IsOnCurve`), rejeitando o ponto no infinito $(0,0)$ e coordenadas fora da curva já no momento do parse.
- **Matriz de Operações `use` e `key_ops` (RFC 7517)**:
  - `use`: estritamente validado como string; aceita apenas `"sig"` e `"enc"`; rejeita qualquer outro valor.
  - `key_ops`: deve ser um array JSON não-vazio de strings não-vazias. Rejeita configurações conflitantes (ex.: `"use": "sig"` com operações de criptografia ou `"use": "enc"` com operações de assinatura). Chaves sem a permissão `"verify"` são ignoradas sem falhar o JWKS.
- **Integridade de Tipos de Dados e Identificadores**:
  - Rejeita tipos não-string para `kty`, `kid`, `crv`, `k`, `x` e `y`.
  - Rejeita valores de `kid` duplicados no mesmo documento para mitigar ataques de mascaramento de chaves (*key shadowing*).
  - Rejeita divergências de algoritmo (`"alg": "ES256"` em chave `oct`, ou `"alg": "none"`).
  - Decodificação Base64URL estrita rejeita caracteres `\r` e `\n`.

---

## Middlewares HTTP de Alta Performance

### 1. `ProtectFunc` (O Mais Rápido, Zero Alocação)

Passa a struct `*Claims` alocada na pilha diretamente para o manipulador com **0 B/op e 0 allocs/op**:

```go
http.HandleFunc("/api/profile", v.ProtectFunc(func(w http.ResponseWriter, r *http.Request, claims *zerojwt.Claims) {
    w.Write([]byte("Olá, " + claims.Subject()))
}))
```

### 2. Middleware `net/http` Padrão

Anexa as `*Claims` ao `r.Context()`:

```go
mux := http.NewServeMux()
mux.Handle("/api/dashboard", v.Middleware(http.HandlerFunc(DashboardHandler)))

func DashboardHandler(w http.ResponseWriter, r *http.Request) {
    claims := zerojwt.FromContext(r.Context())
    fmt.Fprintf(w, "ID do Usuário: %s", claims.Subject())
}
```

### 3. `VerifyBearer`

Valida diretamente o cabeçalho HTTP `Authorization` com zero cópias:

```go
authHeader := r.Header.Get("Authorization") // ou fasthttp ctx.Request.Header.Peek("Authorization")
var claims zerojwt.Claims
if err := v.VerifyBearer([]byte(authHeader), now, &claims); err != nil {
    http.Error(w, "Não autorizado", http.StatusUnauthorized)
    return
}
```

### 4. ForwardAuth Pronto para Uso para Nginx e Traefik

Manipulador HTTP pronto para sub-requisições de autenticação de proxies reversos. Responde com `200 OK` para tokens válidos e injeta automaticamente cabeçalhos de identidade (`X-Auth-User`, `X-Auth-Sub`) para repasse ao upstream; rejeita tokens inválidos ou expirados com `401 Unauthorized`:

```go
// Endpoint padrão de ForwardAuth (suporta tokens Bearer, cabeçalhos customizados e cookies)
http.HandleFunc("/auth", v.ForwardAuthHandler(zerojwt.ForwardAuthOptions{
    CookieName: "access_token", // Fallback para cookie se o cabeçalho Authorization estiver ausente
}))
```

#### Integração com `ngx_http_auth_request_module` do Nginx:

```nginx
location /api/ {
    auth_request /auth;
    auth_request_set $auth_user $upstream_http_x_auth_user;
    auth_request_set $auth_sub  $upstream_http_x_auth_sub;
    
    proxy_set_header X-User $auth_user;
    proxy_set_header X-Sub  $auth_sub;
    proxy_pass http://upstream_backend;
}

location = /auth {
    internal;
    proxy_pass http://auth_service:8080/auth;
    proxy_pass_request_body off;
    proxy_set_header Content-Length "";
    proxy_set_header X-Original-URI $request_uri;
}
```

#### Middleware `ForwardAuth` do Traefik:

```yaml
http:
  middlewares:
    zerojwt-auth:
      forwardAuth:
        address: "http://auth_service:8080/auth"
        authResponseHeaders:
          - "X-Auth-User"
          - "X-Auth-Sub"
```

> [!IMPORTANT]
> **Prevenção contra Injeção de Cabeçalhos HTTP e Response Splitting (CWE-113)**:  
> O `ForwardAuthHandler` inspeciona rigorosamente as claims `Username()` e `Subject()` antes de emitir os cabeçalhos de identidade. Se qualquer caractere de controle ASCII (`< 0x20` ou `0x7f`, como `\r`, `\n` ou `\x00`) for encontrado, o handler encerra imediatamente com `401 Unauthorized` e suprime qualquer injeção de cabeçalhos, impedindo ataques de poluição de cache ou injeção de headers no Nginx e Traefik.

---

## Endurecimento de Segurança e Higiene de Memória

1. **Zeragem de Memória com `Destroy()`**:  
   Chamar `v.Destroy()` invalida o verificador e sobrescreve chaves privadas e segredos HMAC com `0x00`. Chamadas subsequentes falham em modo fechado com `ErrVerifierDestroyed`.
2. **Parser Estrito de Cabeçalho no Nível Superior (RFC 8259)**:  
   Verificações pré-autenticação validam separadores, números e estrutura (rejeitando cabeçalhos malformados, vírgulas duplicadas/finais como `,,`, números inválidos e colchetes incompatíveis) antes de executar operações criptográficas. Nota: não valida o conteúdo interno das strings (ex.: caracteres de controle crus ou sequências de escape inválidas).
3. **Exigência Obrigatória de Expiração**:  
   Por padrão, tokens sem `exp` são rejeitados (`ErrMissingExp`), em conformidade com OIDC Core 1.0 §3.1.3.7 e RFC 9068 §2.2.
4. **Validação de Tamanho Mínimo de Chave**:  
   Segredos menores que o tamanho do hash são rejeitados na inicialização com `ErrInvalidConfig` (`ErrInsecureSecret`) conforme RFC 7518 §3.2.
5. **Clonagem Defensiva de Material de Chaves**:  
   Para prevenir condições de corrida e mutações concorrentes externas, as coordenadas de `ecdsa.PublicKey` (`big.Int`s `X` e `Y`) e slices de segredos brutos são copiados em profundidade para estruturas internas privadas durante a compilação (`compileKeys`), garantindo verificadores imutáveis e 100% thread-safe.
6. **Validação Rigorosa de Coordenadas e Geometria da Curva**:  
   Chaves de curvas elípticas são verificadas contra as equações da curva durante o parse e registro (`isValidP256PublicKey`), rejeitando pontos fora da curva P-256 e o ponto no infinito $(0,0)$.
7. **Imunidade contra Injeção de Headers e CRLF**:  
   Cabeçalhos emitidos para proxies reversos pelo `ForwardAuthHandler` falham em modo fechado caso qualquer caractere de controle ASCII esteja presente nas claims de usuário ou subject.

---

## Otimização Guiada por Perfil (PGO)

O `zerojwt/v2` inclui um perfil pré-calculado [`v2/default.pgo`](default.pgo) gerado a partir de benchmarks com cargas reais de verificação e emissão.

Ao compilar sua aplicação com Go 1.23+:
```bash
go build -pgo=auto .
```
O compilador Go utiliza automaticamente o `default.pgo`, habilitando *inlining* agressivo e alocação de registradores em todos os caminhos críticos.

---

## Referência de Erros Sentinela

| Erro | Descrição |
| :--- | :--- |
| `ErrInvalidToken` | Token malformado ou contendo caracteres Base64URL inválidos |
| `ErrInvalidHeader` | Cabeçalho ausente, sintaxe JSON inválida ou algoritmo não suportado |
| `ErrInvalidPayload` | Payload JSON malformado ou claims excedendo o tamanho dos buffers |
| `ErrInvalidSignature` | Falha na assinatura criptográfica (token forjado ou corrompido) |
| `ErrTokenExpired` | Timestamp atual é maior que `exp` (considerando `Leeway`) |
| `ErrTokenNotValidYet` | Timestamp atual é menor que `nbf` (considerando `Leeway`) |
| `ErrMissingExp` | Token não contém a claim obrigatória `exp` |
| `ErrPayloadTooLarge` | Payload decodificado excede `MaxPayloadSize` configurado |
| `ErrHeaderTooLarge` | Cabeçalho decodificado excede `MaxHeaderSize` configurado |
| `ErrUnknownKeyID` | Token contém um `kid` não registrado no key store |
| `ErrInvalidConfig` | Configuração inválida no construtor (ex: chave curta, chave inválida) |
| `ErrVerifierDestroyed` | Verificador foi destruído via `Destroy()` |
| `ErrInvalidIssuer` | Claim `iss` não coincide com `ExpectedIssuer` |
| `ErrInvalidAudience` | Claim `aud` não coincide com `ExpectedAudience` |
| `ErrNoSigningKey` | Verificador não possui chave privada para assinar |
| `ErrSigningFailed` | Falha na operação criptográfica de assinatura |
| `ErrMismatchedKeyPair` | Chaves pública e privada não formam um par correspondente |
| `ErrMissingBearer` | Cabeçalho Authorization não começa com o prefixo `Bearer ` |

---

## Guia de Migração da v1 para a v2

1. **Atualize o Caminho de Importação**:
   Altere `github.com/KaikeGM/zerojwt` para `github.com/KaikeGM/zerojwt/v2`.
2. **Atualize o Construtor**:
   Substitua `NewVerifier` ou `NewSecureVerifier` por `zerojwt.New(secret, ...Options)`.
3. **Consolide as Claims**:
   Substitua `ClaimsLarge` por `Claims`. Todos os subjects de até 256 bytes são suportados nativamente.
4. **Atualize as Assinaturas de Sign**:
   Substitua `Sign(dst, pl)` que retornava `[]byte` por `Sign(dst, pl) ([]byte, error)`. O rollback em caso de erro é automático.
5. **Garanta a Expiração**:
   Certifique-se de que os tokens emitidos incluam `ExpiresAt > 0`. Para aceitar tokens legados sem expiração, passe `Options{AllowMissingExp: true}`.
6. **Validação Obrigatória de Key ID (`kid`)**:
   Tokens que possuam o cabeçalho `kid` agora exigem que o ID da chave esteja cadastrado em `Keys` ou via `UpdateKeys` / JWKS. Caso o `kid` não seja reconhecido, `Verify` retorna `ErrUnknownKeyID` imediatamente.

---

## Licença

Licença MIT. Consulte [LICENSE](../LICENSE) para detalhes.
