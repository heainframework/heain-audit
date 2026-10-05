package iforest

import (
	"math/rand"
	"testing"
)

func TestIsolationForest(t *testing.T) {
	r := rand.New(rand.NewSource(1))
	var x [][]float64
	for i := 0; i < 300; i++ {
		x = append(x, []float64{r.NormFloat64(), r.NormFloat64()})
	}
	outlier := []float64{8, -9}
	x = append(x, outlier)
	f := Fit(x, Params{Seed: 7})
	so, sn := f.Score(outlier), f.Score([]float64{0, 0})
	if so < 0.65 || sn > 0.55 || so <= sn {
		t.Fatalf("outlier %.3f, normal %.3f", so, sn)
	}
	if g := Fit(x, Params{Seed: 7}).Score(outlier); g != so {
		t.Fatal("same seed, same score")
	}
	same := [][]float64{{1, 1}, {1, 1}, {1, 1}}
	if s := Fit(same, Params{Seed: 1}).Score([]float64{1, 1}); s > 0.6 {
		t.Fatalf("identical points are not anomalous: %.3f", s)
	}
}
