// Command test-tsa is a TEST ONLY RFC 3161 time-stamp authority for the live
// tests (openssl ts -reply with a throwaway CA in -dir; its CA is
// <dir>/ca.pem). Never use it for real anchoring.
package main

import (
	"flag"
	"log"
	"net/http"

	"github.com/heainframework/heain-audit/internal/tsa"
)

func main() {
	listen := flag.String("listen", "127.0.0.1:18480", "where to answer")
	dir := flag.String("dir", "./test-tsa", "keys, certificates and serial file")
	flag.Parse()
	t := tsa.TestAuthority{Dir: *dir}
	if err := t.Setup(); err != nil {
		log.Fatal(err)
	}
	log.Printf("test-tsa (TEST ONLY): http://%s, CA %s/ca.pem", *listen, *dir)
	log.Fatal(http.ListenAndServe(*listen, t))
}
