package merkle

import (
	"crypto/sha256"
	"encoding/hex"
	"testing"
)

func leaf(s string) string { h := sha256.Sum256([]byte(s)); return hex.EncodeToString(h[:]) }

func TestRoot(t *testing.T) {
	if _, err := Root(nil); err == nil {
		t.Fatal("empty")
	}
	if r, _ := Root([]string{leaf("a")}); r != leaf("a") {
		t.Fatal("one leaf is its own root")
	}
	a, b, c := leaf("a"), leaf("b"), leaf("c")
	r1, _ := Root([]string{a, b, c})
	r2, _ := Root([]string{a, b, c})
	r3, _ := Root([]string{a, c, b})
	if r1 != r2 || r1 == r3 {
		t.Fatal("deterministic and order-sensitive")
	}
	if _, err := Root([]string{"zz"}); err == nil {
		t.Fatal("bad hex")
	}
}
