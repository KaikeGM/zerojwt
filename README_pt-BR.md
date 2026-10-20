# ⚡ `zerojwt` — JWT Industrial Ultra-Rápido e Zero Alocações para Go

[English](README.md) | **Português**

[![Go Reference](https://pkg.go.dev/badge/github.com/KaikeGM/zerojwt.svg)](https://pkg.go.dev/github.com/KaikeGM/zerojwt)
[![Go Report Card](https://goreportcard.com/badge/github.com/KaikeGM/zerojwt)](https://goreportcard.com/report/github.com/KaikeGM/zerojwt)
[![Coverage](https://img.shields.io/badge/coverage-100.0%25-brightgreen.svg)](https://github.com/KaikeGM/zerojwt)
[![Allocations](https://img.shields.io/badge/allocations-0_B%2Fop-blue.svg)](https://github.com/KaikeGM/zerojwt)
[![License: MIT](https://img.shields.io/badge/License-MIT-yellow.svg)](https://opensource.org/licenses/MIT)

`zerojwt` é uma biblioteca pura em Go, com **zero dependências externas**, projetada para assinar e verificar **JSON Web Tokens (JWT / RFC 7519)** em **~215 ns/op (paralelo) / ~415–700 ns/op (single-core)** com garantia estrita de **`0 B/op` e `0 allocs/op`** nos caminhos críticos de execução.

Nascido a partir do **PR #48 (`go-gnet-kaikegm`)** no desafio *The $12 Server Challenge* — onde uma única thread do sistema operacional sustentou **300.000 conexões simultâneas keep-alive** e **35.577 req/s** —, o `zerojwt` elimina o uso de reflexão (`reflect`), alocações dinâmicas de mapas via `encoding/json` e a pressão sobre o Garbage Collector (GC) típica de bibliotecas convencionais de JWT em Go, mantendo um conjunto completo de recursos de padrão industrial.

---

## 📑 Sumário

- [Comparativo de Benchmarks](#-comparativo-de-benchmarks)
- [Principais Recursos](#-principais-recursos)
- [Arquitetura e Modelo de Memória](#-arquitetura-e-modelo-de-memória)
- [Instalação](#-instalação)
- [Início Rápido](#-início-rápido)
- [Algoritmos Criptográficos](#-algoritmos-criptográficos)
  - [Simétrico: HS256, HS384, HS512](#1-simétrico-hmac-hs256-hs384-hs512)
  - [Assimétrico: EdDSA (Ed25519)](#2-assimétrico-eddsa-ed25519--rfc-8037)
  - [Assimétrico: ES256 (ECDSA P-256)](#3-assimétrico-es256-ecdsa-p-256--rfc-7518)
- [Validação RFC 7519 e Claims](#-validação-rfc-7519-e-claims)
  - [Tolerância de Desvio de Relógio (Leeway)](#tolerância-de-desvio-de-relógio-leeway)
  - [Validação de Emissor (iss) e Audiência (aud)](#validação-de-emissor-iss-e-audiência-aud)
  - [Identificador JWT (jti) e Prevenção contra Replay](#identificador-jwt-jti-e-prevenção-contra-replay)
  - [Estruturas Duais de Claims: Claims vs ClaimsLarge](#estruturas-duais-de-claims-claims-vs-claimslarge)
- [Claims Customizadas e SignBuilder Fluente](#-claims-customizadas-e-signbuilder-fluente)
  - [SignBuilder Fluente (0 allocs/op)](#signbuilder-fluente-0-allocsop)
  - [Inspeção de Claims Arbitrárias via VerifyCustom](#inspeção-de-claims-arbitrárias-via-verifycustom)
  - [Iteradores Range-Over-Func do Go 1.23+](#iteradores-range-over-func-do-go-123-zero-alocações)
- [Rotação de Chaves sem Downtime (kid)](#-rotação-de-chaves-sem-downtime-kid)
- [Middlewares HTTP de Alta Performance](#-middlewares-http-de-alta-performance)
  - [ProtectFunc (0 allocs/op)](#1-protectfunc-o-mais-rápido-zero-alocação)
  - [Middleware net/http Padrão e Chi](#2-middleware-padrão-nethttp-e-chi)
  - [Integração com Gin, Fiber e gnet](#3-integração-com-gin-fiber-e-gnet)
- [Endurecimento de Segurança e Higiene de Memória](#-endurecimento-de-segurança-e-higiene-de-memória)
- [Otimização Guiada por Perfil (PGO)](#-otimização-guiada-por-perfil-pgo)
- [Referência da API](#-referência-da-api)
- [Erros Sentinela](#-erros-sentinela)
- [Testes, Fuzzing e Garantia de Qualidade](#-testes-fuzzing-e-garantia-de-qualidade)
- [Licença](#-licença)

---

## 🚀 Comparativo de Benchmarks

Todos os benchmarks são 100% reproduzíveis e estão publicados diretamente neste repositório sob o diretório [`benchmarks/`](benchmarks/). A suíte de benchmarks testa cada biblioteca utilizando **exatamente a mesma chave criptográfica, payload de token, schema de claims e carga de trabalho de verificação**.

> **Nota sobre Zero Dependências:** Os benchmarks das bibliotecas concorrentes residem em um módulo Go isolado (`benchmarks/go.mod`). Isso assegura que seu código de produção ao importar `github.com/KaikeGM/zerojwt` permaneça estritamente com **zero dependências de terceiros**.

### 🔬 Reproduzindo os Benchmarks

Clone o repositório e execute a suíte de benchmarks diretamente:

```bash
cd benchmarks
go test -bench=. -benchmem -benchtime=1s
```

Todas as quatro bibliotecas são validadas quanto à extração idêntica de claims e correção criptográfica antes da execução dos benchmarks via `TestCompetitorsCompatibility`.

### 📊 Resultados dos Benchmarks

*Ambiente: Intel(R) Core(TM) i5-1135G7 @ 2.40GHz (8 CPUs lógicas), Linux amd64, Go 1.23+.*  
*Payload: segredo HS256 de 32 bytes, claims registradas padrão (`sub: "12345"`, `iat`, `exp`), além de claim customizada (`user: "golden_ember_1"`).*  
*Avaliação justa de relógio: Os benchmarks de verificação do `zerojwt` executam `time.Now().Unix()` em cada iteração para nivelar a medição com as bibliotecas concorrentes que invocam o relógio do sistema internamente.*

#### 1. Verificação de Token (Verify & Parse Claims)

| Biblioteca | Modo / Estratégia | Vazão ($10^9 / \text{ns}$) | Tempo Médio / op | Memória / op | Alocs / op |
| :--- | :--- | :---: | :---: | :---: | :---: |
| **`zerojwt`** | **Paralelo (Multi-Core)** | **~4.750.000 ops/s** | **210,5 ns/op** | **`0 B/op`** | **`0 allocs/op`** |
| **`zerojwt`** | **Single-Core (Scratch)** | **~1.387.000 ops/s** | **720,9 ns/op** | **`0 B/op`** | **`0 allocs/op`** |
| **`zerojwt`** | **Single-Core (Pool)** | **~1.372.000 ops/s** | **728,5 ns/op** | **`0 B/op`** | **`0 allocs/op`** |
| `kataras/jwt` | Paralelo (Multi-Core) | ~951.000 ops/s | 1.051,0 ns/op | 1.075 B/op | 15 allocs/op |
| `kataras/jwt` | Single-Core | ~354.000 ops/s | 2.821,0 ns/op | 1.073 B/op | 15 allocs/op |
| `golang-jwt/jwt/v5` | Paralelo (Multi-Core) | ~575.000 ops/s | 1.739,0 ns/op | 2.097 B/op | 37 allocs/op |
| `golang-jwt/jwt/v5` | Single-Core | ~209.000 ops/s | 4.780,0 ns/op | 2.091 B/op | 37 allocs/op |
| `lestrrat-go/jwx/v2` | Paralelo (Multi-Core) | ~185.000 ops/s | 5.385,0 ns/op | 6.135 B/op | 108 allocs/op |
| `lestrrat-go/jwx/v2` | Single-Core | ~91.000 ops/s | 10.948,0 ns/op | 6.112 B/op | 108 allocs/op |

#### 2. Geração de Token (Assinatura)

| Biblioteca | Implementação | Vazão ($10^9 / \text{ns}$) | Tempo Médio / op | Memória / op | Alocs / op |
| :--- | :--- | :---: | :---: | :---: | :---: |
| **`zerojwt`** | **`SignClaims`** | **~2.300.000 ops/s** | **434,7 ns/op** | **`0 B/op`** | **`0 allocs/op`** |
| **`zerojwt`** | **`SignBuilder`** | **~2.083.000 ops/s** | **480,0 ns/op** | **`0 B/op`** | **`0 allocs/op`** |
| `kataras/jwt` | `jwt.Sign` | ~619.000 ops/s | 1.613,0 ns/op | 1.208 B/op | 14 allocs/op |
| `golang-jwt/jwt/v5` | `SignedString` | ~276.000 ops/s | 3.617,0 ns/op | 2.338 B/op | 36 allocs/op |
| `lestrrat-go/jwx/v2` | `jwt.Sign` | ~131.000 ops/s | 7.617,0 ns/op | 4.933 B/op | 118 allocs/op |

> **Conclusão:** Bibliotecas tradicionais de JWT alocam entre 14 e 108 objetos na heap a cada token validado, acumulando megabytes de lixo e disparando pausas frequentes de GC sob carga de produção (10k+ req/s). O `zerojwt` realiza **zero alocações na heap**, permitindo que gateways de API e event loops operem com densidade máxima de conexões e latências planas e previsíveis.

---

## ✨ Principais Recursos

1. **Garantia Estrita de 0 Alocações:**
   - Assinatura e verificação de tokens com HS256/HS384/HS512 e EdDSA operam sem nenhuma alocação na heap (`0 B/op, 0 allocs/op`). O ES256 aloca internamente no pacote padrão `crypto/ecdsa` (varia conforme a versão do Go: ~8–10 allocs/op na verificação, ~33–67 allocs/op na assinatura).
   - Sem conversões de `interface{}`, sem parsing com `map[string]any` e sem reflexão (`reflect`).

2. **Portfólio Criptográfico Completo:**
   - **Simétrico:** `HS256`, `HS384`, `HS512` (HMAC com família SHA-2).
   - **Assimétrico:** `EdDSA` (`Ed25519` / RFC 8037) e `ES256` (`ECDSA P-256` / RFC 7518).
   - Conversão direta customizada de ASN.1 DER para IEEE P1363 com largura fixa (64 bytes $r \parallel s$) implementada diretamente sobre buffers na stack.

3. **Conformidade Rigorosa com RFC 7519 / RFC 7515:**
   - Tolerância configurável para desvio de relógio (`Leeway`).
   - Suporte completo às claims registradas padrão: `exp` (Expires At), `nbf` (Not Before), `iat` (Issued At), `iss` (Issuer), `aud` (Audience), `sub` (Subject) e `jti` (JWT ID).
   - Validação de audiência suporta tanto uma string JSON única (`"aud":"servico"`) quanto um array JSON de strings (`"aud":["svc-a","svc-b"]`) com zero alocações.
   - Validação estrita de `typ: "JWT"` quando o cabeçalho estiver presente.

4. **Lexer In-Place com Zero-Copy (`scanner.go`):**
   - Tokenizador JSON streaming de altíssima performance com tabelas de consulta direta pré-calculadas (LUTs de 256 bytes) para espaços em branco, delimitadores e conversão hexadecimal.
   - Decodificação de escape de strings *in-place* para escapes padrão (`\"`, `\\`, `\/`, `\b`, `\f`, `\n`, `\r`, `\t`) e code points Unicode completos (`\uXXXX`), incluindo pares substitutos UTF-16 (*surrogate pairs* `\uD800..\uDBFF` + `\uDC00..\uDFFF`).

5. **Rotação de Credenciais Multi-Chave (`kid`):**
   - Rotação contínua de chaves sem downtime e com zero alocações usando o parâmetro de cabeçalho `"kid"`.

6. **`SignBuilder` Fluente Alocado na Stack:**
   - Construção e assinatura de payloads customizados com campos arbitrários sem alocar strings ou mapas JSON.

7. **Configuração com Falha Rápida (Fail-Fast) e Higiene de Memória:**
   - Construtores rejeitam credenciais inutilizáveis em tempo de inicialização (segredos HMAC vazios, chaves sem material para o algoritmo selecionado, curvas ou tamanhos incorretos) em vez de instanciar um verificador inseguro.
   - Modo opcional `ZeroMemory` limpa claims e buffers scratch via `memclr` antes de devolvê-los ao pool. Trata-se de uma prática de higiene de memória, não de uma certificação de conformidade.

8. **Zero Dependências Externas:**
   - Construído exclusivamente com a biblioteca padrão do Go (`crypto/*`, `encoding/base64`, `sync`, `unsafe`).

---

## 🏛️ Arquitetura e Modelo de Memória

O `zerojwt` atinge zero alocações na heap substituindo alocações dinâmicas em tempo de execução por **workspaces `Scratch` reutilizáveis**:

```
+-------------------------------------------------------------------------+
|                               Scratch                                   |
|                                                                         |
|  +--------------------+  +--------------------+  +-------------------+  |
|  |   hdrBuf [128]B    |  |  payloadBuf [1024]B|  |   sigBuf [64]B    |  |
|  +--------------------+  +--------------------+  +-------------------+  |
|  +--------------------+  +--------------------+  +-------------------+  |
|  |   sumBuf [64]B     |  |   derBuf [72]B     |  |  mac (hash.Hash)  |  |
|  +--------------------+  +--------------------+  +-------------------+  |
+-------------------------------------------------------------------------+
```

### Dois Modelos de Concorrência

1. **Aplicações Web Multithreaded (`sync.Pool`):**  
   Métodos como `Verifier.Verify`, `Verifier.VerifyLarge`, `Verifier.VerifyBearer` e `Verifier.Sign` obtêm automaticamente uma instância de `*Scratch` a partir de um `sync.Pool` lock-free interno e a devolvem ao finalizar.
2. **Event Loops Single-Threaded (`gnet` / `epoll` / Pools de Workers):**  
   Métodos como `Verifier.VerifyWithScratch`, `Verifier.VerifyLargeWithScratch` e `Verifier.SignWithScratch` aceitam uma instância de `*Scratch` gerenciada pelo chamador (por exemplo, fixada no contexto do worker do event loop), eliminando até mesmo a sobrecarga atômica de `sync.Pool`.

---

## 📦 Instalação

Requer Go 1.23 ou superior:

```bash
go get github.com/KaikeGM/zerojwt
```

---

## 🛠️ Início Rápido

### 1. Recomendado para Produção: `NewSecureVerifier`

Para serviços em produção, utilize preferencialmente `NewSecureVerifier`. Ele aplica automaticamente as exigências modernas de identidade (**OIDC Core 1.0 §3.1.3.7**, **OAuth 2.0 RFC 9068 §2.2** e **RFC 7518 §3.2**):
- **Expiração Obrigatória:** Rejeita qualquer token sem claim `exp` (`ErrMissingExp`).
- **Tamanho Criptográfico Seguro:** Exige tamanho mínimo de segredo HMAC ($\ge 32$ bytes para HS256).
- **Tratamento Idiomático:** Retorna `(*Verifier, error)` na inicialização em vez de disparar panic.

```go
package main

import (
	"fmt"
	"time"

	"github.com/KaikeGM/zerojwt"
)

func main() {
	secret := []byte("secret-key-must-be-at-least-32-bytes!!")
	verifier, err := zerojwt.NewSecureVerifier(secret)
	if err != nil {
		panic(err)
	}
	now := time.Now().Unix()

	// 1. Assina claims com retorno tipado de erro (0 allocs/op)
	var tokBuf [512]byte
	token, err := verifier.TrySignClaims(
		tokBuf[:0],
		[]byte("user_9876"), // sub (suporta até 256 bytes)
		[]byte("kaikegm"),   // username
		now,                 // iat
		now+3600,            // exp (1 hora)
	)
	if err != nil {
		panic(err)
	}

	fmt.Printf("JWT Gerado: %s\n", token)

	// 2. Verifica o token na estrutura Claims alocada na stack (0 allocs/op)
	var claims zerojwt.Claims
	if err := verifier.Verify(token, now, &claims); err != nil {
		panic(err)
	}

	fmt.Printf("Autenticado: Subject=%s, Username=%s, ExpiresAt=%d\n",
		claims.Subject(), claims.Username(), claims.ExpiresAt)
}
```

### 2. Padrão Genérico RFC 7519: `NewVerifier`

Se a sua arquitetura necessitar de tokens sem timestamp de expiração ou utilizar segredos legados, `NewVerifier` mantém os padrões genéricos da RFC 7519 (`RequireExp: false`, tamanho flexível):

```go
verifier := zerojwt.NewVerifier(secret)
token := verifier.SignClaims(tokBuf[:0], []byte("user_1"), nil, now, now+3600)
```

> [!TIP]
> **Ergonomia da API e Retorno de Erros:**
> - **Caminho com Erro Tipado (`TrySign*`):** `TrySign` e `TrySignClaims` retornam `([]byte, error)` com erros sentinela explícitos (`ErrPayloadTooLarge`, `ErrMissingExp`, `ErrNoSigningKey`, `ErrSigningFailed`), mantendo estritos `0 B/op, 0 allocs/op`.
> - **Caminho Direto de Buffer (`Sign*`):** `Sign` e `SignClaims` retornam `[]byte` diretamente (e `nil` em falha) para loops de eventos de alto throughput.
> - **Tamanho de Chave HMAC:** `StrictSecretLength` aplica-se aos algoritmos simétricos HMAC (`HS256`, `HS384`, `HS512` conforme RFC 7518 §3.2). Chaves assimétricas (`EdDSA`, `ES256`) possuem dimensões fixadas matematicamente pela curva e validadas na inicialização.

---

## 🔐 Algoritmos Criptográficos

### 1. Simétrico HMAC: HS256, HS384, HS512

A validação simétrica requer o mesmo segredo compartilhado entre emissor e validador.

```go
// HS256 (Padrão)
v256 := zerojwt.NewVerifier(secret)

// HS384
v384 := zerojwt.NewVerifierWithOptions(secret, zerojwt.Options{
	Algorithm: zerojwt.AlgHS384,
})

// HS512
v512 := zerojwt.NewVerifierWithOptions(secret, zerojwt.Options{
	Algorithm: zerojwt.AlgHS512,
})
```

---

### 2. Assimétrico: EdDSA (Ed25519 / RFC 8037)

O Ed25519 fornece verificação assimétrica ultra-rápida com chaves públicas de 32 bytes e assinaturas de 64 bytes. Ideal para arquiteturas de microsserviços onde serviços internos devem apenas verificar tokens sem a capacidade de emiti-los.

```go
import "crypto/ed25519"

// Gerar par de chaves
pubKey, privKey, _ := ed25519.GenerateKey(nil)

// Servidor de Autenticação (Emite e assina tokens)
authVerifier := zerojwt.NewEd25519Verifier(pubKey, privKey, zerojwt.Options{
	ExpectedIssuer: "https://auth.empresa.com",
})
token := authVerifier.SignClaims(tokBuf[:0], []byte("usr_1"), []byte("alice"), now, now+3600)

// Microsserviço / API Gateway (Apenas verificação: privKey é nil)
gatewayVerifier := zerojwt.NewEd25519Verifier(pubKey, nil, zerojwt.Options{
	ExpectedIssuer: "https://auth.empresa.com",
})
var claims zerojwt.Claims
if err := gatewayVerifier.Verify(token, now, &claims); err != nil {
	log.Fatalf("Token inválido: %v", err)
}
```

---

### 3. Assimétrico: ES256 (ECDSA P-256 / RFC 7518)

O ES256 é amplamente utilizado em ambientes corporativos de OAuth 2.0 / OpenID Connect, clientes móveis e WebAuthn. O `zerojwt` implementa conversão direta de IEEE P1363 ($r \parallel s$) para ASN.1 DER em buffers de stack. Observe que a implementação padrão de `crypto/ecdsa` do Go aloca internamente, logo o ES256 não opera com zero alocações de ponta a ponta.

```go
import (
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
)

// Gerar par de chaves P-256
privKey, _ := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
pubKey := &privKey.PublicKey

// Verificador configurado com ES256
vES256 := zerojwt.NewES256Verifier(pubKey, privKey, zerojwt.Options{
	Leeway: 10 * time.Second,
})

token := vES256.Sign(tokBuf[:0], []byte(`{"sub":"usr_p256","exp":1893456000}`))
```

---

## 📋 Validação RFC 7519 e Claims

### Tolerância de Desvio de Relógio (Leeway)

Em sistemas distribuídos, os servidores podem apresentar pequenas dessincronizações de relógio via NTP. A opção `Leeway` evita rejeição prematura de tokens:

```go
verifier := zerojwt.NewVerifierWithOptions(secret, zerojwt.Options{
	Leeway: 5 * time.Second, // Permite tokens até 5s antes de nbf ou 5s após exp
})
```

---

### Validação de Emissor (`iss`) e Audiência (`aud`)

Quando configurado, o `zerojwt` exige que os tokens recebidos contenham as claims `iss` e `aud` correspondentes:

```go
verifier := zerojwt.NewVerifierWithOptions(secret, zerojwt.Options{
	ExpectedIssuer:   "auth.empresa.com",
	ExpectedAudience: "pagamentos-api",
})
```

O `zerojwt` valida nativamente claims `aud` declaradas tanto como uma **string JSON única** quanto como um **array JSON de strings**:
* Única: `"aud": "pagamentos-api"`
* Array: `"aud": ["relatorios-api", "pagamentos-api", "admin-api"]`

Ambas as variações são analisadas e comparadas **in-place com 0 alocações na heap**.

---

### Identificador JWT (`jti`) e Prevenção contra Replay

A claim `jti` fornece um identificador único (por exemplo, UUID v4) para mitigar ataques de repetição (*replay attacks*). A estrutura `Claims` disponibiliza `claims.JTI()` para verificação contra listas de revogação em memória (como filtros de Bloom ou caches sincronizados):

```go
var claims zerojwt.Claims
if err := verifier.Verify(token, now, &claims); err != nil {
	return err
}

if revocationFilter.Contains(claims.JTI()) {
	return errors.New("token revogado")
}
```

---

### Estruturas Duais de Claims: Claims vs ClaimsLarge

| Recurso | `Claims` (Padrão) | `ClaimsLarge` |
| :--- | :---: | :---: |
| **Caso de Uso Principal** | APIs de alta densidade, microsserviços | Tokens corporativos, usernames longos/UUIDs |
| **Tam. Máximo de Subject** | **64 bytes** | **256 bytes** |
| **Tam. Máximo de Username** | **128 bytes** | **256 bytes** |
| **Tam. Máximo de Issuer** | **64 bytes** | **256 bytes** |
| **Tam. Máximo de Audience** | **64 bytes** | **256 bytes** |
| **Tam. Máximo de JTI** | **36 bytes** (UUID) | **64 bytes** |
| **Ocupação de Memória** | Extremamente compacta | Stack fixa ligeiramente maior |
| **Método de Verificação** | `v.Verify(...)` | `v.VerifyLarge(...)` |

---

## 🛠️ Claims Customizadas e SignBuilder Fluente

### `SignBuilder` Fluente (0 allocs/op)

Construa payloads JWT customizados com atributos arbitrários sem alocar `map[string]any` ou strings:

```go
var tokBuf [1024]byte
builder := verifier.NewSigner(tokBuf[:0])
defer builder.Discard() // Devolve o Scratch ao pool com segurança caso ocorra erro antes de Sign()

token, err := builder.
	SetSubject([]byte("usr_1001")).
	SetUsername([]byte("kaike")).
	SetIssuer([]byte("auth.empresa.com")).
	SetAudience([]byte("api.empresa.com")).
	SetJTI([]byte("9b1deb4d-3b7d-4bad-9bdd-2b0d7b3dcb6d")).
	SetIssuedAt(now).
	SetExpiresAt(now + 7200).
	SetClaimString("role", "admin").
	SetClaimInt("tenant_id", 42).
	SetClaimBool("mfa_verified", true).
	SetClaimRawJSON("permissions", []byte(`["read:users","write:users"]`)).
	Sign()

if err != nil {
	panic(err)
}
```

> **Dica de segurança de memória:** `Sign()` devolve automaticamente a instância pooled de `*Scratch` ao pool ao concluir. Adicionar `defer builder.Discard()` previne vazamento de buffers caso ocorra um erro ou `return` antecipado antes da invocação de `Sign()`; chamar `Discard()` após um `Sign()` bem-sucedido é uma operação segura e inócua (no-op).

---

### Inspeção de Claims Arbitrárias via `VerifyCustom`

Se seu token contém estruturas aninhadas arbitrárias ou atributos customizados, utilize `VerifyCustom`. O método valida a assinatura e as restrições temporais (`exp`, `nbf`, `iss`, `aud`), entregando fatias chave-valor diretamente a partir do buffer validado com **0 alocações**:

```go
err := verifier.VerifyCustom(token, now, func(key, val []byte, isStr bool) bool {
	switch string(key) {
	case "tenant_id":
		id, _ := zerojwt.ParsePositiveInt(val)
		fmt.Printf("Tenant: %d\n", id)
	case "permissions":
		// Iterador range-over-func do Go 1.23+ (0 B/op, 0 allocs/op, ~54 ns/op):
		for elem, isStr := range zerojwt.ArrayElements(val) {
			fmt.Printf("Permissão: %s (isStr=%v)\n", elem, isStr)
		}
	}
	return true // continua o escaneamento das claims
})
```

### Iteradores Range-Over-Func do Go 1.23+ (Zero Alocações)

O Go 1.23 padronizou iteradores por meio dos tipos `iter.Seq` e `iter.Seq2`. O `zerojwt` fornece iteradores nativos que são inlined pelo compilador, operando a **~18.000.000–19.000.000 ops/s** (~52–55 ns/op) com **`0 B/op` e `0 allocs/op`**:

```go
// 1. Iterar sobre elementos de array JSON (não destrutivo, seguro para múltiplas passadas):
for elem, isStr := range zerojwt.ArrayElements(rawArray) {
	fmt.Printf("Elemento: %s (isStr: %v)\n", elem, isStr)
}

// 2. Iterar sobre pares de propriedades de objeto JSON (chave, valor):
for key, val := range zerojwt.ObjectProps(rawObject) {
	fmt.Printf("%s = %s\n", key, val)
}

// 3. Iterar sobre propriedades com metadados de tipo completos:
for prop := range zerojwt.ObjectProperties(rawObject) {
	fmt.Printf("Chave: %s, Valor: %s, IsString: %v\n", prop.Key, prop.Val, prop.IsStr)
}
```

> **Nota sobre valores string:** Elementos e propriedades de string são retornados como fatias não destrutivas sobre o buffer subjacente (sem as aspas externas), preservando quaisquer sequências de escape (ex.: `\"`, `\n`, `\uXXXX`) para garantir que o buffer permaneça imutável em múltiplas passadas. Se o conteúdo decodificado for necessário, chame `zerojwt.UnescapeJSONInPlace(val)`.

#### Detecção Estrita de Erros

Ao iterar sobre payloads JSON externos ou não confiáveis, os iteradores aceitam um ponteiro opcional `*error`. Caso a estrutura JSON esteja truncada ou contenha sintaxe inválida, a iteração é interrompida imediatamente e o erro `zerojwt.ErrInvalidPayload` é registrado:

```go
var scanErr error
for elem, isStr := range zerojwt.ArrayElements(rawArray, &scanErr) {
	// ...
}
if scanErr != nil {
	return fmt.Errorf("array de claims malformado: %w", scanErr)
}
```

---

## 🔄 Rotação de Chaves sem Downtime (`kid`)

Para rotacionar chaves criptográficas sem invalidar sessões ativas existentes, registre múltiplas chaves identificadas por IDs exclusivos:

```go
verifier := zerojwt.NewVerifierWithOptions(primarySecret, zerojwt.Options{
	Algorithm:   zerojwt.AlgHS256,
	ActiveKeyID: "key-2026-v2", // Embutido em novos tokens gerados
	Keys: []zerojwt.Key{
		{ID: "key-2025-v1", Secret: oldSecret},
		{ID: "key-2026-v2", Secret: primarySecret},
	},
})
```

Cada chave deve conter o material correspondente ao algoritmo do verificador: `Secret` para HS256/384/512, uma chave `Ed25519Public` de 32 bytes para EdDSA, ou `ECDSAPublic` sobre a curva P-256 para ES256. Os IDs de chave não podem ser vazios nem duplicados. Uma chave incompatível com o algoritmo resulta em erro de configuração (veja [Endurecimento de Segurança](#-endurecimento-de-segurança-e-higiene-de-memória)); um verificador processa um único algoritmo, não sendo permitida a mistura de algoritmos diferentes no mesmo `Verifier`.

Durante a validação, o `zerojwt` extrai o parâmetro `"kid"` do cabeçalho e seleciona a chave criptográfica correspondente em $O(1)$ sem nenhuma alocação na heap.

---

## 🌐 Middlewares HTTP de Alta Performance

### 1. `ProtectFunc` (O Mais Rápido, Zero Alocação)

Passa um ponteiro `*Claims` alocado na stack diretamente para o handler da requisição, assegurando **`0 B/op` de sobrecarga** por requisição HTTP:

```go
http.HandleFunc("/api/me", verifier.ProtectFunc(func(w http.ResponseWriter, r *http.Request, claims *zerojwt.Claims) {
	w.Header().Set("Content-Type", "application/json")
	fmt.Fprintf(w, `{"sub":"%s","user":"%s"}`, claims.Subject(), claims.Username())
}))
```

---

### 2. Middleware Padrão `net/http` e Chi

> O `Middleware` armazena as claims no `context` da requisição HTTP, o que envolve alocação. Utilize `ProtectFunc` quando for mandatória a exigência de zero alocações por requisição.

Integra-se diretamente com Chi, Gorilla Mux ou roteadores padrão do Go:

```go
r := chi.NewRouter()
r.Use(verifier.Middleware)

r.Get("/api/dashboard", func(w http.ResponseWriter, r *http.Request) {
	claims, ok := zerojwt.ClaimsFromContext(r.Context())
	if !ok {
		http.Error(w, "Não autorizado", http.StatusUnauthorized)
		return
	}
	fmt.Fprintf(w, "Bem-vindo, ID de usuário %d!", claims.SubjectID)
})
```

---

### 3. Integração com Gin, Fiber e gnet

#### Gin
```go
func ZeroJWTGin(v *zerojwt.Verifier) gin.HandlerFunc {
	return func(c *gin.Context) {
		auth := c.GetHeader("Authorization")
		if len(auth) <= 7 {
			c.AbortWithStatus(http.StatusUnauthorized)
			return
		}
		var claims zerojwt.Claims
		if err := v.VerifyBearer([]byte(auth), time.Now().Unix(), &claims); err != nil {
			c.AbortWithStatus(http.StatusUnauthorized)
			return
		}
		c.Set("claims", &claims)
		c.Next()
	}
}
```

#### gnet (Event Loop Single-Threaded)
```go
type server struct {
	*gnet.BuiltinEventEngine
	verifier *zerojwt.Verifier
	scratch  *zerojwt.Scratch // 1 scratch exclusivo por worker thread
}

func (s *server) OnTraffic(c gnet.Conn) gnet.Action {
	buf, _ := c.Next(-1)
	var claims zerojwt.Claims
	// Verificação direta com scratch: 0 alocações, 0 locks de sync.Pool
	if err := s.verifier.VerifyWithScratch(buf, time.Now().Unix(), &claims, s.scratch); err != nil {
		c.Write([]byte("HTTP/1.1 401 Unauthorized\r\n\r\n"))
		return gnet.Close
	}
	// ...
	return gnet.None
}
```

---

## 🛡️ Endurecimento de Segurança e Higiene de Memória

### Configuração com Falha Rápida (Fail-Fast)

As funções construtoras `NewVerifier`, `NewVerifierWithOptions`, `NewEd25519Verifier` e `NewES256Verifier` disparam **panic** com erro encapsulando `zerojwt.ErrInvalidConfig` quando a configuração for inválida ou inutilizável. Dessa forma, uma variável de ambiente `JWT_SECRET` vazia ou ausente derruba a aplicação na inicialização em vez de aceitar silenciosamente tokens forjados. Para tratar o erro programaticamente sem panic, utilize `TryNewVerifier`:

```go
v, err := zerojwt.TryNewVerifier([]byte(os.Getenv("JWT_SECRET")), zerojwt.Options{
	Algorithm:          zerojwt.AlgHS256,
	RequireExp:         true, // rejeita tokens sem "exp"; SignClaims/SignBuilder recusam omitir
	StrictSecretLength: true, // impõe tamanho mínimo da RFC 7518 §3.2: 32/48/64 bytes para HS256/384/512
})
if err != nil {
	log.Fatal(err) // errors.Is(err, zerojwt.ErrInvalidConfig)
}
```

Configurações rejeitadas: segredos HMAC vazios, elementos de `Key` sem o material correspondente ao algoritmo escolhido, IDs de chave vazios ou duplicados, nomes de algoritmo desconhecidos, chaves Ed25519 com tamanho diferente de 32 bytes e chaves ECDSA fora da curva P-256. A opção `StrictSecretLength` é configurável (opt-in) para manter compatibilidade com implantações legadas que utilizem segredos menores (desde que não vazios).

### Formato Estrito de Tokens e Cabeçalhos

O token possui um único formato de string aceito: o Base64URL é decodificado em modo estrito (bits residuais não canônicos são rejeitados) e caracteres de controle como `\r` ou `\n` causam rejeição imediata. Isso é crucial para quem indexa caches de repetição ou listas de revogação pela string bruta do token. Cabeçalhos contendo a diretiva `crit` são rejeitados conforme exigido pela RFC 7515 §4.1.11 para extensões críticas não suportadas.

### Nós Somente-Leitura (Verify-Only)

O método `Verifier.CanSign()` indica se o verificador possui uma chave privada de assinatura ativa. Em nós de apenas verificação (por exemplo, instâncias EdDSA/ES256 sem chave privada), os métodos `Sign*` retornam `nil` e `SignBuilder.Sign` retorna `ErrNoSigningKey`, jamais emitindo um token com assinatura vazia ou inválida.

### Higiene de Memória (`ZeroMemory`, `Destroy`)

Ative `ZeroMemory: true` para aplicar `memclr` em buffers de claims e scratch antes de retorná-los ao pool:

```go
verifier := zerojwt.NewVerifierWithOptions(secret, zerojwt.Options{
	ZeroMemory: true,
})
```

O método `verifier.Destroy()` sobrescreve os segredos mantidos pelo verificador e o torna permanentemente inutilizável (`Verify*` passa a retornar `ErrVerifierDestroyed` e `Sign*` retorna `nil`). Trata-se de uma rotina de higiene em regime de melhor esforço (*best-effort*), **não** constituindo certificação formal de conformidade FIPS ou PCI-DSS: cópias externas da chave passadas pelo usuário, estados internos de HMAC já em cache na biblioteca padrão e instâncias compartilhadas de `*ecdsa.PrivateKey` não são garantidamente apagadas pelo runtime do Go. O método `Destroy` não deve ser executado concorrentemente com outras chamadas.

---

## ⚡ Otimização Guiada por Perfil (PGO)

Ao compilar binários para ambiente de produção, o Go 1.20+ suporta Profile-Guided Optimization (PGO). O compilador do Go detecta e consome automaticamente o arquivo de perfil `default.pgo` presente no **diretório do pacote `main`** que estiver sendo compilado.

Como o Go aplica PGO no nível do executável final e não por dependência isolada, você pode otimizar todo o seu serviço (incluindo as rotinas internas de verificação e parsing do `zerojwt`) capturando um perfil real de tráfego de produção:

```bash
# 1. Capture um perfil de CPU representativo de 30 segundos do seu serviço em execução
curl -o default.pgo "http://localhost:6060/debug/pprof/profile?seconds=30"

# 2. Posicione default.pgo no diretório do seu pacote main (junto ao main.go)

# 3. Compile com Go 1.23+ (o compilador descobre default.pgo automaticamente)
go build -o meu-servico .
```

Para inspecionar as decisões de inlining tomadas pelo PGO durante a compilação:

```bash
go build -gcflags="-m=2" 2>&1 | grep "pgo inline"
```

---

## 📖 Referência da API

### Construtores do Verifier
- `NewVerifier(secret []byte) *Verifier`: Cria um verificador HS256 com limites padrão de buffer (cabeçalho 128B, payload 1024B).
- `NewEd25519Verifier(pub ed25519.PublicKey, priv ed25519.PrivateKey, opts Options) *Verifier`: Cria um verificador EdDSA (Ed25519).
- `NewES256Verifier(pub *ecdsa.PublicKey, priv *ecdsa.PrivateKey, opts Options) *Verifier`: Cria um verificador ES256 (ECDSA P-256).
- `NewVerifierWithOptions(secret []byte, opts Options) *Verifier`: Cria um verificador totalmente customizado. Dispara panic (encapsulando `ErrInvalidConfig`) se a configuração for inválida.
- `TryNewVerifier(secret []byte, opts Options) (*Verifier, error)`: Idêntico a `NewVerifierWithOptions`, porém retorna o erro explicitamente em vez de disparar panic.
- `(*Verifier).CanSign() bool`: Retorna se o verificador contém uma chave de assinatura válida.

### Métodos de Verificação
- `Verify(tok []byte, nowUnix int64, out *Claims) error`: Valida o token e preenche a estrutura padrão `Claims`.
- `VerifyBearer(authHeader []byte, nowUnix int64, out *Claims) error`: Extrai o prefixo `Bearer <token>` e executa a validação.
- `VerifyWithScratch(tok []byte, nowUnix int64, out *Claims, st *Scratch) error`: Valida o token utilizando um `Scratch` fornecido pelo chamador.
- `VerifyLarge(tok []byte, nowUnix int64, out *ClaimsLarge) error`: Valida o token preenchendo a estrutura de alta capacidade `ClaimsLarge`.
- `VerifyLargeWithScratch(tok []byte, nowUnix int64, out *ClaimsLarge, st *Scratch) error`: Valida o token em `ClaimsLarge` utilizando um `Scratch` fornecido pelo chamador.
- `VerifyCustom(tok []byte, nowUnix int64, onClaim func(key, val []byte, isStr bool) bool) error`: Valida assinatura e claims temporais, percorrendo claims customizadas sem alocações.

### Métodos de Assinatura e Builder
Todos os métodos `Sign*` retornam `nil` (jamais um token com assinatura inválida) quando o verificador não puder assinar (`CanSign() == false`), quando a operação falhar, ou quando `RequireExp` estiver ativo e `SignClaims` for invocado com `exp <= 0`.

- `Sign(dst []byte, payloadJSON []byte) []byte`: Assina um payload JSON bruto utilizando buffers padrão.
- `SignClaims(dst, sub, username []byte, iat, exp int64) []byte`: Assina claims padrão diretamente no slice `dst`.
- `SignWithScratch(dst, payloadJSON []byte, st *Scratch) []byte`: Assina o payload utilizando um `Scratch` fornecido pelo chamador.
- `NewSigner(dst []byte) SignBuilder`: Cria um builder fluente para claims customizadas utilizando buffers do `sync.Pool`.
- `NewSignerWithScratch(dst []byte, st *Scratch) SignBuilder`: Cria um builder fluente utilizando um `Scratch` fornecido pelo chamador.
- `(*SignBuilder).Discard()`: Libera o buffer `Scratch` interno de volta ao `sync.Pool` (operação idempotente).
- `(*SignBuilder).Sign() ([]byte, error)`: Assina o payload e libera automaticamente o `Scratch` pooled.

### Lexer e Parser Rápido (`scanner.go`)
- `NextJSONProp(b []byte) (key, val []byte, isStr bool, rest []byte, ok bool)`: Extrai o próximo par `"chave": valor` do corpo de um objeto JSON in-place.
- `NextArrayElement(b []byte) (val []byte, isStr bool, rest []byte, ok bool)`: Extrai o próximo elemento do corpo de um array JSON in-place.
- `TrimJSONObject(b []byte) ([]byte, bool)`: Remove espaços em branco e chaves `{` e `}` externas.
- `TrimJSONArray(b []byte) ([]byte, bool)`: Remove espaços em branco e colchetes `[` e `]` externos.
- `ParseNumeric(b []byte) (float64, bool)`: Faz parsing de números inteiros, decimais e com notação científica com zero alocações.
- `ParsePositiveInt(b []byte) (int64, bool)`: Parser ultra-rápido de inteiros de 64 bits suportando até 19 dígitos (IDs Snowflake).
- `UnescapeJSONInPlace(s []byte) []byte`: Decodifica sequências de escape e code points Unicode in-place.
- `AppendEscapedJSONString(dst, s []byte) []byte`: Anexa uma string entre aspas com caracteres de escape JSON seguros.

### Iteradores Go 1.23+ (`iter.go`)
- `ArrayElements(rawArray []byte, errOut ...*error) iter.Seq2[[]byte, bool]`: Percorre elementos de array JSON de forma não destrutiva e sem alocações.
- `ObjectProps(rawObject []byte, errOut ...*error) iter.Seq2[[]byte, []byte]`: Percorre pares chave-valor de objeto JSON de forma não destrutiva e sem alocações.
- `ObjectProperties(rawObject []byte, errOut ...*error) iter.Seq[JSONProp]`: Percorre propriedades de objeto JSON com metadados de tipo completos sem alocações.

---

## ⚠️ Erros Sentinela

Todos os erros são sentinelas estáticos pré-alocados. Faça a comparação utilizando `errors.Is` ou operador `==` com zero alocações na heap:

| Erro Sentinela | Descrição |
| :--- | :--- |
| `ErrMissingBearer` | O cabeçalho `Authorization` não possui o prefixo `"Bearer "`. |
| `ErrInvalidToken` | Estrutura de token malformada (não contém exatamente 3 segmentos Base64URL separados por ponto). |
| `ErrInvalidHeader` | O cabeçalho não é um JSON válido ou especifica um algoritmo incompatível/não suportado. |
| `ErrInvalidSignature` | A verificação da assinatura criptográfica falhou. |
| `ErrExpiredToken` | O instante atual é $\ge$ à claim `exp` (considerando o `Leeway`). |
| `ErrNotValidYet` | O instante atual é $<$ à claim `nbf` (considerando o `Leeway`). |
| `ErrInvalidPayload` | O JSON do payload está malformado, ausente de claims obrigatórias (`sub`) ou com tipos conflitantes. |
| `ErrPayloadTooLarge` | O tamanho do payload excede `MaxPayloadSize`. |
| `ErrInvalidIssuer` | A claim `iss` não coincide com `ExpectedIssuer`. |
| `ErrInvalidAudience` | A claim `aud` não coincide nem contém `ExpectedAudience`. |
| `ErrUnknownKeyID` | O cabeçalho `"kid"` especifica um ID de chave não reconhecido. |
| `ErrMissingExp` | `RequireExp` está ativo e o token não contém a claim `exp`. |
| `ErrInvalidConfig` | Encapsulado por erros de `TryNewVerifier` e panics de construtores em caso de configuração inválida. |
| `ErrNoSigningKey` | `SignBuilder.Sign` foi chamado em um verificador que não possui chave de assinatura. |
| `ErrVerifierDestroyed` | Um método `Verify*` foi invocado após a execução de `Destroy()`. |

---

## 🧪 Testes, Fuzzing e Garantia de Qualidade

O `zerojwt` conta com uma suíte abrangente de testes e validações com 100% de cobertura de código:

```bash
# 1. Executar todos os testes unitários com 100% de cobertura de declarações
go test -v -coverprofile=coverage.out ./...
go tool cover -func=coverage.out

# 2. Race detector (detecta concorrência desprotegida)
go test -v -race ./...

# 3. Validar zero alocações na heap nos caminhos críticos
go test -v -run=TestZeroAllocations ./...

# 4. Executar benchmarks e coletar estatísticas de alocação de memória
go test -bench=. -benchmem ./...

# 5. Testes contínuos de fuzzing nativo contra entradas adversariais
go test -fuzz=FuzzVerify -fuzztime=30s
```

---

## 📄 Licença

Licença MIT — Copyright (c) 2026 [KaikeGM](https://github.com/KaikeGM).  
Distribuído sob a permissiva licença MIT. Consulte o arquivo [LICENSE](LICENSE) para mais detalhes.
