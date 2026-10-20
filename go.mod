module github.com/KaikeGM/zerojwt

go 1.23

retract (
	v1.0.0 // Accepted forged tokens (empty HMAC key); fixed in v1.1.0.
	v1.0.1 // Accepted forged tokens (empty HMAC key); fixed in v1.1.0.
)
