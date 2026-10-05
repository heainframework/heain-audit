// Package merkle computes the Merkle root heain-audit signs in a
// checkpoint: a binary SHA-256 tree over the chain hashes of a range of
// records; an odd node at any level is paired with itself.
package merkle

import (
	"crypto/sha256"
	"encoding/hex"
	"errors"
	"fmt"
)

// Root returns the hex root over hex leaf hashes.
func Root(leaves []string) (string, error) {
	if len(leaves) == 0 {
		return "", errors.New("merkle: no leaves")
	}
	level := make([][]byte, len(leaves))
	for i, h := range leaves {
		b, err := hex.DecodeString(h)
		if err != nil {
			return "", fmt.Errorf("merkle: leaf %d is not hex: %w", i, err)
		}
		level[i] = b
	}
	for len(level) > 1 {
		next := make([][]byte, 0, (len(level)+1)/2)
		for i := 0; i < len(level); i += 2 {
			l, r := level[i], level[i]
			if i+1 < len(level) {
				r = level[i+1]
			}
			s := sha256.Sum256(append(append([]byte{}, l...), r...))
			next = append(next, s[:])
		}
		level = next
	}
	return hex.EncodeToString(level[0]), nil
}
