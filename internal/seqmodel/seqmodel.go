// Package seqmodel is heain-audit's sequence model (Stage B-3a, author
// decisions 2026-10-08): what each actor usually does next. It is a
// trigram language model over the actors' event streams with Witten-Bell
// interpolation (Witten and Bell, 1991; the smoothing of classic n-gram
// language models): P(w | u v) mixes the trigram, bigram and unigram
// estimates, each weighted by how much its context has been seen. An
// event's surprisal, -log2 P(event | the actor's two previous events), is
// high when that actor has rarely or never done this after that -- the
// sequence anomalies the Isolation Forest (one event at a time) cannot see.
// Deterministic: the same history always gives the same model.
package seqmodel

import (
	"math"
	"sort"
)

// Model is a fitted trigram model.
type Model struct {
	uni   map[string]int
	bi    map[[2]string]int // (u, w)
	tri   map[[3]string]int // (u, v, w)
	ctx1  map[string]int    // count of u as a context
	ctx2  map[[2]string]int // count of (u, v) as a context
	typ1  map[string]int    // distinct w after u
	typ2  map[[2]string]int // distinct w after (u, v)
	n     int               // tokens
	start string
}

// Start marks the beginning of an actor's stream.
const Start = "<s>"

// Fit learns from streams: each is one actor's tokens in time order.
func Fit(streams [][]string) *Model {
	m := &Model{uni: map[string]int{}, bi: map[[2]string]int{}, tri: map[[3]string]int{}, ctx1: map[string]int{}, ctx2: map[[2]string]int{},
		typ1: map[string]int{}, typ2: map[[2]string]int{}, start: Start}
	for _, s := range streams {
		u, v := Start, Start
		for _, w := range s {
			m.uni[w]++
			m.n++
			if m.bi[[2]string{v, w}] == 0 {
				m.typ1[v]++
			}
			m.bi[[2]string{v, w}]++
			m.ctx1[v]++
			if m.tri[[3]string{u, v, w}] == 0 {
				m.typ2[[2]string{u, v}]++
			}
			m.tri[[3]string{u, v, w}]++
			m.ctx2[[2]string{u, v}]++
			u, v = v, w
		}
	}
	return m
}

// Tokens is how many tokens the model saw; Vocabulary how many distinct.
func (m *Model) Tokens() int     { return m.n }
func (m *Model) Vocabulary() int { return len(m.uni) }

// P is P(w | u v).
func (m *Model) P(u, v, w string) float64 {
	// unigram with one extra count for "never seen"
	p1 := float64(m.uni[w]+1) / float64(m.n+len(m.uni)+1)
	p2 := p1
	if c := m.ctx1[v]; c > 0 {
		l := float64(c) / float64(c+m.typ1[v])
		p2 = l*float64(m.bi[[2]string{v, w}])/float64(c) + (1-l)*p1
	}
	p3 := p2
	if c := m.ctx2[[2]string{u, v}]; c > 0 {
		l := float64(c) / float64(c+m.typ2[[2]string{u, v}])
		p3 = l*float64(m.tri[[3]string{u, v, w}])/float64(c) + (1-l)*p2
	}
	return p3
}

// Surprisal is -log2 P(w | u v) in bits.
func (m *Model) Surprisal(u, v, w string) float64 { return -math.Log2(m.P(u, v, w)) }

// Likely are the k most likely next tokens after (u, v), for explanations.
func (m *Model) Likely(u, v string, k int) []string {
	type tw struct {
		w string
		p float64
	}
	var all []tw
	for w := range m.uni {
		all = append(all, tw{w, m.P(u, v, w)})
	}
	sort.Slice(all, func(i, j int) bool {
		if all[i].p != all[j].p {
			return all[i].p > all[j].p
		}
		return all[i].w < all[j].w
	})
	var out []string
	for i := 0; i < len(all) && i < k; i++ {
		out = append(out, all[i].w)
	}
	return out
}
