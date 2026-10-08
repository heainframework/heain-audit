package seqmodel

import (
	"math"
	"testing"
)

func TestSequenceSurprisal(t *testing.T) {
	// a deploy pipeline: login -> read -> write -> logout, many times, for two actors
	var streams [][]string
	for a := 0; a < 2; a++ {
		var s []string
		for i := 0; i < 200; i++ {
			s = append(s, "login", "read", "write", "logout")
		}
		streams = append(streams, s)
	}
	m := Fit(streams)
	if m.Tokens() != 1600 || m.Vocabulary() != 4 {
		t.Fatalf("tokens %d vocab %d", m.Tokens(), m.Vocabulary())
	}
	usual := m.Surprisal("login", "read", "write")
	odd := m.Surprisal("login", "read", "logout")   // known tokens, never in that order
	novel := m.Surprisal("login", "read", "delete") // never seen at all
	if usual > 0.1 || odd < 8 || novel < odd {
		t.Fatalf("usual %.2f odd %.2f novel %.2f bits", usual, odd, novel)
	}
	var sum float64
	for _, w := range []string{"login", "read", "write", "logout", "delete"} {
		sum += m.P("read", "write", w)
	}
	if sum > 1+1e-9 {
		t.Fatalf("probabilities sum to %g", sum)
	}
	if l := m.Likely("login", "read", 1); len(l) != 1 || l[0] != "write" {
		t.Fatalf("likely %v", l)
	}
	if !math.IsInf(m.Surprisal("a", "b", "c"), 0) && m.Surprisal("a", "b", "c") <= 0 {
		t.Fatal("unseen context")
	}
}
