module github.com/KaikeGM/zerojwt

go 1.23

retract (
	v1.0.0 // Continha vulnerabilidades de validação de chaves e assinatura corrigidas na v1.1.0+.
	v1.0.1 // Continha vulnerabilidades de validação de chaves e assinatura corrigidas na v1.1.0+.
)
