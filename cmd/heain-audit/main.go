// Command heain-audit is the independent auditor base app: it reads its
// node's audit chain from heain-core (the node's audit.readers policy must
// list "heain-audit"), verifies every link itself, keeps a sealed replica,
// signs Merkle checkpoints, detects a rewritten or truncated chain, and
// scores events for anomalies (advisory, through P5). It is configured
// through the heain-sdk HEAIN_* variables and runs however the operator
// likes: a plain process, a service unit, or a container.
package main

import (
	"context"
	"flag"
	"fmt"
	"log"
	"net"
	"os"
	"os/signal"
	"path/filepath"
	"syscall"
	"time"

	"github.com/heainframework/heain-sdk/heain"

	"github.com/heainframework/heain-audit/internal/api"
	"github.com/heainframework/heain-audit/internal/auditor"
	"github.com/heainframework/heain-audit/internal/replica"
)

func main() {
	pull := flag.Duration("pull-every", 5*time.Second, "how often to read new records from core")
	ckpt := flag.Uint64("checkpoint-every", 1000, "sign a checkpoint every this many new records (0 = only on request)")
	scan := flag.Uint64("scan-every", 500, "score anomalies every this many new records (0 = only on request)")
	thr := flag.Float64("threshold", 0.62, "anomaly score at or above which an event is flagged")
	trees := flag.Int("trees", 100, "isolation forest: trees")
	sample := flag.Int("sample", 256, "isolation forest: sub-sample per tree")
	ctxN := flag.Int("context", 500, "earlier events fitted with each window, for context")
	tsaURL := flag.String("tsa-url", os.Getenv("HEAIN_AUDIT_TSA_URL"), "RFC 3161 time-stamp authority that anchors the checkpoints held here (empty = no anchoring); only a SHA-256 root is sent")
	tsaCA := flag.String("tsa-ca", os.Getenv("HEAIN_AUDIT_TSA_CA"), "the TSA's CA certificate(s) (PEM), to verify its tokens")
	anchorEvery := flag.Duration("anchor-every", 10*time.Minute, "anchor what is new this often (with -tsa-url)")
	witness := flag.Bool("witness", os.Getenv("HEAIN_AUDIT_WITNESS") != "off", "send this node's checkpoints to the heain-audit of its zone Master (env HEAIN_AUDIT_WITNESS=off to keep them here only)")
	flag.Parse()
	ctx, stop := signal.NotifyContext(context.Background(), os.Interrupt, syscall.SIGTERM)
	defer stop()
	app, err := heain.StartFromEnv(ctx)
	if err != nil {
		fmt.Fprintf(os.Stderr, "REFUSED: %v\n", err)
		os.Exit(2)
	}
	log.Printf("heain-audit: registered (%s), waiting for admission", app.Status())
	if err := app.WaitActive(ctx); err != nil {
		log.Fatal(err)
	}
	state := os.Getenv("HEAIN_STATE_DIR")
	if state == "" {
		state = "/state"
	}
	sealer, err := app.Sealer(ctx, "replica")
	if err != nil {
		log.Fatalf("heain-audit: data key from core: %v", err)
	}
	st, err := replica.Open(filepath.Join(state, "replica.db"), sealer)
	if err != nil {
		log.Fatal(err)
	}
	defer st.Close()
	a := &auditor.Auditor{Core: app, Store: st, Logf: log.Printf, P: auditor.Params{Node: os.Getenv("HEAIN_CORE_ID"),
		CheckpointEvery: *ckpt, ScanEvery: *scan, Threshold: *thr, Trees: *trees, Sample: *sample, Context: *ctxN}}
	if *witness {
		a.Zone = zone{app}
	}
	if *tsaURL != "" {
		a.Anchoring = &auditor.Anchoring{URL: *tsaURL, CAFile: *tsaCA, Every: *anchorEvery}
		log.Printf("heain-audit: anchoring checkpoints with %s every %s", *tsaURL, *anchorEvery)
	}
	srv := app.NewServer()
	if err := (&api.API{A: a}).Register(srv); err != nil {
		log.Fatal(err)
	}
	go a.Run(ctx, *pull)
	l, err := net.Listen("tcp", heain.Listen(":19470"))
	if err != nil {
		log.Fatal(err)
	}
	log.Printf("heain-audit: active, serving on %s, auditing node %s", l.Addr(), os.Getenv("HEAIN_CORE_ID"))
	if err := srv.Serve(ctx, l); err != nil && ctx.Err() == nil {
		log.Fatal(err)
	}
	_ = app.Close(context.Background())
	log.Printf("heain-audit: deregistered")
}

// zone is the witness side's view of heain-sdk (Stage B-1d).
type zone struct{ app *heain.App }

func (z zone) ZoneMaster(ctx context.Context) (string, string, error) {
	in, err := z.app.Core.Info(ctx)
	return in.NodeID, in.ZoneMaster, err
}

func (z zone) DiscoverZone(ctx context.Context, capability string, version int) ([]heain.ZoneInstance, bool, error) {
	return z.app.DiscoverZone(ctx, capability, version)
}

func (z zone) Call(ctx context.Context, cs heain.CallSpec) (int, error) { return z.app.Call(ctx, cs) }
