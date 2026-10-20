package zerojwt

import "testing"

func BenchmarkArrayElements(b *testing.B) {
	rawArr := []byte(`["admin", "user", "billing", "auditor"]`)
	b.ReportAllocs()
	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		for elem, isStr := range ArrayElements(rawArr) {
			_ = elem
			_ = isStr
		}
	}
}

func BenchmarkObjectProps(b *testing.B) {
	rawObj := []byte(`{"sub":"123","tenant":"acme","role":"admin"}`)
	b.ReportAllocs()
	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		for k, v := range ObjectProps(rawObj) {
			_ = k
			_ = v
		}
	}
}
