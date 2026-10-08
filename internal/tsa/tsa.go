// Package tsa anchors heain-audit's roots with a Time-Stamp Authority
// (RFC 3161; Stage B-1d, author decision 2026-10-08): only a SHA-256 digest
// leaves the deployment, and the token the TSA returns proves the digest
// existed at its time. Anyone can check a token offline:
//
//	openssl ts -verify -digest <root hex> -in anchor.tsr -CAfile tsa-ca.pem
package tsa

import (
	"bytes"
	"context"
	"crypto/rand"
	"encoding/asn1"
	"errors"
	"fmt"
	"io"
	"math/big"
	"net/http"
	"os"
	"os/exec"
	"strings"
	"time"
)

var (
	oidSHA256     = asn1.ObjectIdentifier{2, 16, 840, 1, 101, 3, 4, 2, 1}
	oidSignedData = asn1.ObjectIdentifier{1, 2, 840, 113549, 1, 7, 2}
	oidTSTInfo    = asn1.ObjectIdentifier{1, 2, 840, 113549, 1, 9, 16, 1, 4}
)

type algorithm struct {
	Algorithm  asn1.ObjectIdentifier
	Parameters asn1.RawValue `asn1:"optional"`
}

type messageImprint struct {
	HashAlgorithm algorithm
	HashedMessage []byte
}

type request struct {
	Version        int
	MessageImprint messageImprint
	Nonce          *big.Int `asn1:"optional"`
	CertReq        bool     `asn1:"optional"`
}

type statusInfo struct {
	Status       int
	StatusString asn1.RawValue  `asn1:"optional"`
	FailInfo     asn1.BitString `asn1:"optional"`
}

type response struct {
	Status statusInfo
	Token  asn1.RawValue `asn1:"optional"`
}

type contentInfo struct {
	ContentType asn1.ObjectIdentifier
	Content     asn1.RawValue `asn1:"explicit,tag:0"`
}

type encapContent struct {
	EContentType asn1.ObjectIdentifier
	EContent     []byte `asn1:"explicit,tag:0"`
}

type signedData struct {
	Version          int
	DigestAlgorithms asn1.RawValue
	EncapContentInfo encapContent
	Rest             asn1.RawValue `asn1:"optional"`
}

// TSTInfo is the part of a token heain-audit reads.
type TSTInfo struct {
	Version        int
	Policy         asn1.ObjectIdentifier
	MessageImprint messageImprint
	SerialNumber   *big.Int
	GenTime        time.Time     `asn1:"generalized"`
	Rest           asn1.RawValue `asn1:"optional"`
}

// Token is a stamped digest.
type Token struct {
	DER     []byte    // the TimeStampToken (CMS ContentInfo), as the TSA sent it
	GenTime time.Time // when the TSA stamped it
	Serial  string
}

// ErrRefused: the TSA answered without a token.
var ErrRefused = errors.New("tsa: the authority refused the request")

// Stamp asks the TSA at url to stamp a SHA-256 digest.
func Stamp(ctx context.Context, url string, digest []byte, client *http.Client) (Token, error) {
	if len(digest) != 32 {
		return Token{}, errors.New("tsa: a SHA-256 digest is 32 bytes")
	}
	nonce, _ := rand.Int(rand.Reader, new(big.Int).Lsh(big.NewInt(1), 63))
	der, err := asn1.Marshal(request{Version: 1, MessageImprint: messageImprint{
		HashAlgorithm: algorithm{Algorithm: oidSHA256, Parameters: asn1.NullRawValue}, HashedMessage: digest},
		Nonce: nonce, CertReq: true})
	if err != nil {
		return Token{}, err
	}
	req, err := http.NewRequestWithContext(ctx, http.MethodPost, url, bytes.NewReader(der))
	if err != nil {
		return Token{}, err
	}
	req.Header.Set("Content-Type", "application/timestamp-query")
	if client == nil {
		client = &http.Client{Timeout: 30 * time.Second}
	}
	resp, err := client.Do(req)
	if err != nil {
		return Token{}, fmt.Errorf("tsa: %w", err)
	}
	defer resp.Body.Close()
	body, _ := io.ReadAll(io.LimitReader(resp.Body, 1<<20))
	if resp.StatusCode != http.StatusOK {
		return Token{}, fmt.Errorf("tsa: HTTP %d", resp.StatusCode)
	}
	var r response
	if _, err := asn1.Unmarshal(body, &r); err != nil {
		return Token{}, fmt.Errorf("tsa: answer: %w", err)
	}
	if r.Status.Status > 1 || len(r.Token.FullBytes) == 0 {
		return Token{}, fmt.Errorf("%w (status %d)", ErrRefused, r.Status.Status)
	}
	info, err := Parse(r.Token.FullBytes)
	if err != nil {
		return Token{}, err
	}
	if !bytes.Equal(info.MessageImprint.HashedMessage, digest) {
		return Token{}, errors.New("tsa: the token stamps another digest")
	}
	return Token{DER: r.Token.FullBytes, GenTime: info.GenTime.UTC(), Serial: info.SerialNumber.String()}, nil
}

// Parse reads the stamped digest and time from a token (no signature check).
func Parse(token []byte) (TSTInfo, error) {
	var ci contentInfo
	if _, err := asn1.Unmarshal(token, &ci); err != nil {
		return TSTInfo{}, fmt.Errorf("tsa: token: %w", err)
	}
	if !ci.ContentType.Equal(oidSignedData) {
		return TSTInfo{}, errors.New("tsa: token is not CMS SignedData")
	}
	var sd signedData
	if _, err := asn1.Unmarshal(ci.Content.Bytes, &sd); err != nil {
		return TSTInfo{}, fmt.Errorf("tsa: signed data: %w", err)
	}
	if !sd.EncapContentInfo.EContentType.Equal(oidTSTInfo) {
		return TSTInfo{}, errors.New("tsa: token content is not TSTInfo")
	}
	var info TSTInfo
	if _, err := asn1.Unmarshal(sd.EncapContentInfo.EContent, &info); err != nil {
		return TSTInfo{}, fmt.Errorf("tsa: TSTInfo: %w", err)
	}
	if !info.MessageImprint.HashAlgorithm.Algorithm.Equal(oidSHA256) {
		return TSTInfo{}, errors.New("tsa: the token is not over SHA-256")
	}
	return info, nil
}

// Verify checks the TSA's signature on token and that it stamps digest,
// with openssl (the same check anyone can run offline). caFile is the TSA's
// CA certificate(s).
func Verify(token, digest []byte, caFile string) error {
	f, err := os.CreateTemp("", "heain-audit-*.tsr")
	if err != nil {
		return err
	}
	defer os.Remove(f.Name())
	if _, err := f.Write(token); err != nil {
		f.Close()
		return err
	}
	f.Close()
	out, err := exec.Command("openssl", "ts", "-verify", "-digest", fmt.Sprintf("%x", digest), "-token_in", "-in", f.Name(), "-CAfile", caFile).CombinedOutput()
	if err != nil || !strings.Contains(string(out), "Verification: OK") {
		return fmt.Errorf("tsa: openssl ts -verify: %s", strings.TrimSpace(string(out)))
	}
	return nil
}
