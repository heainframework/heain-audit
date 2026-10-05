// Package iforest is an Isolation Forest (Liu, Ting and Zhou, 2008) in Go:
// heain-audit's anomaly model, replacing the Stage A scikit-learn sidecar
// (author decision 2026-10-06). It is unsupervised -- there is no labelled
// "this was an attack" data -- and scores how easily a point is isolated
// from the rest of its batch: s(x) = 2^(-E[h(x)] / c(n)), near 1 =
// anomalous, around 0.5 or below = normal. A fixed seed makes every score
// reproducible from the same batch.
package iforest

import (
	"math"
	"math/rand"
)

// Params of the forest.
type Params struct {
	Trees  int   // default 100
	Sample int   // sub-sample size per tree, default 256
	Seed   int64 // random seed (reproducible scores)
}

// Forest is a fitted model.
type Forest struct {
	trees []*node
	n     int
}

type node struct {
	feature     int
	split       float64
	left, right *node
	size        int
}

// c is the average path length of an unsuccessful BST search over n points.
func c(n int) float64 {
	if n <= 1 {
		return 0
	}
	if n == 2 {
		return 1
	}
	h := math.Log(float64(n-1)) + 0.5772156649
	return 2*h - 2*float64(n-1)/float64(n)
}

// Fit builds the forest over x (rows of equal length).
func Fit(x [][]float64, p Params) *Forest {
	if p.Trees <= 0 {
		p.Trees = 100
	}
	if p.Sample <= 0 {
		p.Sample = 256
	}
	n := p.Sample
	if n > len(x) {
		n = len(x)
	}
	r := rand.New(rand.NewSource(p.Seed))
	limit := int(math.Ceil(math.Log2(float64(max(n, 2)))))
	f := &Forest{n: n}
	for t := 0; t < p.Trees; t++ {
		idx := r.Perm(len(x))[:n]
		rows := make([][]float64, n)
		for i, j := range idx {
			rows[i] = x[j]
		}
		f.trees = append(f.trees, build(rows, 0, limit, r))
	}
	return f
}

func build(rows [][]float64, depth, limit int, r *rand.Rand) *node {
	if depth >= limit || len(rows) <= 1 {
		return &node{size: len(rows)}
	}
	dims := len(rows[0])
	// pick a feature that varies in this node (try each once, random order)
	for _, f := range r.Perm(dims) {
		lo, hi := rows[0][f], rows[0][f]
		for _, row := range rows {
			lo, hi = math.Min(lo, row[f]), math.Max(hi, row[f])
		}
		if hi > lo {
			s := lo + r.Float64()*(hi-lo)
			var l, rr [][]float64
			for _, row := range rows {
				if row[f] < s {
					l = append(l, row)
				} else {
					rr = append(rr, row)
				}
			}
			return &node{feature: f, split: s, left: build(l, depth+1, limit, r), right: build(rr, depth+1, limit, r)}
		}
	}
	return &node{size: len(rows)} // all points equal
}

func pathLen(n *node, x []float64, depth int) float64 {
	if n.left == nil {
		return float64(depth) + c(n.size)
	}
	if x[n.feature] < n.split {
		return pathLen(n.left, x, depth+1)
	}
	return pathLen(n.right, x, depth+1)
}

// Score is the anomaly score of x in 0..1.
func (f *Forest) Score(x []float64) float64 {
	if len(f.trees) == 0 || f.n <= 1 {
		return 0
	}
	sum := 0.0
	for _, t := range f.trees {
		sum += pathLen(t, x, 0)
	}
	return math.Pow(2, -(sum/float64(len(f.trees)))/c(f.n))
}
