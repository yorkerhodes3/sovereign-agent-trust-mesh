// Package reconcile keeps live mesh access in step with on-chain state.
//
// This closes the loop that makes SATM more than a registry lookup. A binding is
// verified once at admission, but the facts it rests on can change afterwards
// with no signal at the broker:
//
//   - the agent NFT is sold, which zeroes `agentWallet` (TH-5)
//   - the registration file is edited to drop the SAM service entry (TH-16)
//   - the agent is marked inactive, or its registry is removed from the
//     allow-list
//
// Without reconciliation a sold agent keeps its mesh access until its Biscuit
// expires, which is precisely the gap the concept brief identifies. PLAN.md
// exit criterion 3 -- "transfer the agent NFT, mesh access is revoked within one
// interval" -- is this package.
package reconcile

import (
	"context"
	"errors"
	"log/slog"
	"sync"
	"time"

	"github.com/yorkerhodes3/sovereign-agent-trust-mesh/services/broker/internal/binding"
)

// Store is the subset of the trust store the reconciler needs.
type Store interface {
	ActiveRecords(ctx context.Context) ([]*binding.Record, error)
	Revoke(ctx context.Context, bindingID, reason string) (bool, error)
}

// Revalidator re-runs the post-admission checks for one binding.
type Revalidator interface {
	Revalidate(ctx context.Context, rec *binding.Record) error
}

// MeshRevoker propagates a revocation into the mesh control plane.
//
// Separated from the store because the two failure modes are different and must
// be handled differently: the store write is authoritative and local, while the
// control-plane call is remote and may fail transiently. The binding is revoked
// locally FIRST, so a control-plane outage cannot keep a sold agent trusted by
// the broker.
type MeshRevoker interface {
	RevokePeer(ctx context.Context, peerID, meshID, reason string) error
}

// NoopMeshRevoker is used when no control plane is wired up.
//
// It logs rather than silently succeeding, because "revocation appeared to work
// but nothing was told to the mesh" is a dangerous thing to do quietly.
type NoopMeshRevoker struct{ Log *slog.Logger }

func (n NoopMeshRevoker) RevokePeer(_ context.Context, peerID, meshID, reason string) error {
	if n.Log != nil {
		n.Log.Warn("binding revoked locally but NOT propagated to the mesh: "+
			"no control-plane revoker is configured, so the peer may retain access until its Biscuit expires",
			"peerId", peerID, "meshId", meshID, "reason", reason)
	}
	return nil
}

// Config parameterises the reconciler.
type Config struct {
	// Interval between sweeps. This is the upper bound on how long a sold agent
	// retains mesh access, so it is a security parameter, not just a tuning
	// knob.
	Interval time.Duration

	// Concurrency bounds parallel revalidations. Each one makes chain and HTTP
	// calls, so an unbounded sweep over a large mesh would hammer the RPC
	// provider and the registration-file hosts.
	Concurrency int

	// Timeout per binding revalidation.
	Timeout time.Duration

	// DryRun reports what would be revoked without revoking it. Useful when
	// first pointing the reconciler at a populated mesh.
	DryRun bool
}

// DefaultConfig returns usable defaults.
func DefaultConfig() Config {
	return Config{
		Interval:    time.Minute,
		Concurrency: 4,
		Timeout:     30 * time.Second,
	}
}

// Reconciler sweeps active bindings.
type Reconciler struct {
	cfg     Config
	store   Store
	checker Revalidator
	mesh    MeshRevoker
	log     *slog.Logger
}

// New builds a Reconciler.
func New(cfg Config, store Store, checker Revalidator, mesh MeshRevoker, log *slog.Logger) (*Reconciler, error) {
	if store == nil || checker == nil {
		return nil, errors.New("reconcile: store and revalidator are required")
	}
	if cfg.Interval <= 0 {
		cfg.Interval = time.Minute
	}
	if cfg.Concurrency <= 0 {
		cfg.Concurrency = 4
	}
	if cfg.Timeout <= 0 {
		cfg.Timeout = 30 * time.Second
	}
	if log == nil {
		log = slog.Default()
	}
	if mesh == nil {
		mesh = NoopMeshRevoker{Log: log}
	}
	return &Reconciler{cfg: cfg, store: store, checker: checker, mesh: mesh, log: log}, nil
}

// Stats summarises one sweep.
type Stats struct {
	Checked int
	Healthy int
	Revoked int
	// Errored counts bindings that could not be CHECKED, as distinct from
	// bindings that failed their checks. Conflating the two would mean an RPC
	// outage silently revoked the entire mesh.
	Errored  int
	Duration time.Duration
}

// Run sweeps until the context is cancelled.
func (r *Reconciler) Run(ctx context.Context) error {
	t := time.NewTicker(r.cfg.Interval)
	defer t.Stop()

	// Sweep immediately rather than waiting a full interval, so a broker
	// restart does not extend the revocation window.
	if _, err := r.Sweep(ctx); err != nil && !errors.Is(err, context.Canceled) {
		r.log.Error("initial reconcile sweep failed", "err", err)
	}

	for {
		select {
		case <-ctx.Done():
			return ctx.Err()
		case <-t.C:
			if _, err := r.Sweep(ctx); err != nil && !errors.Is(err, context.Canceled) {
				r.log.Error("reconcile sweep failed", "err", err)
			}
		}
	}
}

// Sweep runs one full pass over the active bindings.
func (r *Reconciler) Sweep(ctx context.Context) (Stats, error) {
	start := time.Now()
	var stats Stats

	records, err := r.store.ActiveRecords(ctx)
	if err != nil {
		return stats, err
	}
	stats.Checked = len(records)
	if len(records) == 0 {
		stats.Duration = time.Since(start)
		return stats, nil
	}

	var (
		mu   sync.Mutex
		wg   sync.WaitGroup
		sem  = make(chan struct{}, r.cfg.Concurrency)
		errs []error
	)

	for _, rec := range records {
		wg.Add(1)
		go func(rec *binding.Record) {
			defer wg.Done()
			sem <- struct{}{}
			defer func() { <-sem }()

			outcome, err := r.checkOne(ctx, rec)

			mu.Lock()
			defer mu.Unlock()
			switch outcome {
			case outcomeHealthy:
				stats.Healthy++
			case outcomeRevoked:
				stats.Revoked++
			case outcomeErrored:
				stats.Errored++
			}
			// Collected regardless of outcome: a binding can be revoked locally
			// AND fail to propagate to the control plane, and the caller needs
			// to hear about the second part.
			if err != nil {
				errs = append(errs, err)
			}
		}(rec)
	}
	wg.Wait()

	stats.Duration = time.Since(start)
	r.log.Info("reconcile sweep complete",
		"checked", stats.Checked, "healthy", stats.Healthy,
		"revoked", stats.Revoked, "errored", stats.Errored,
		"duration", stats.Duration)

	return stats, errors.Join(errs...)
}

type outcome int

const (
	outcomeHealthy outcome = iota
	outcomeRevoked
	outcomeErrored
)

// checkOne revalidates a single binding and revokes it if it no longer holds.
func (r *Reconciler) checkOne(ctx context.Context, rec *binding.Record) (outcome, error) {
	ctx, cancel := context.WithTimeout(ctx, r.cfg.Timeout)
	defer cancel()

	err := r.checker.Revalidate(ctx, rec)
	if err == nil {
		return outcomeHealthy, nil
	}

	// A binding that could not be CHECKED must not be revoked. An RPC outage or
	// an unreachable registration host is an infrastructure failure, and
	// treating it as a verdict would let a provider outage revoke the entire
	// mesh -- a far worse failure than briefly trusting a stale binding.
	//
	// An error that is not a *binding.Error at all is unclassified, and is
	// treated the same way for the same reason. Note that binding.ReasonOf maps
	// such errors to ReasonMalformed, so it must NOT be used to make this
	// decision -- doing so would silently reclassify every unexpected failure as
	// a revocable verdict.
	var bErr *binding.Error
	if !errors.As(err, &bErr) {
		r.log.Warn("could not revalidate binding (unclassified error); leaving it in place",
			"bindingId", rec.ID, "caid", rec.CAID, "err", err)
		return outcomeErrored, err
	}

	reason := bErr.Reason
	if isInfrastructure(reason) {
		r.log.Warn("could not revalidate binding; leaving it in place",
			"bindingId", rec.ID, "caid", rec.CAID, "reason", string(reason), "err", err)
		return outcomeErrored, err
	}

	if r.cfg.DryRun {
		r.log.Info("DRY RUN: would revoke binding",
			"bindingId", rec.ID, "caid", rec.CAID, "peerId", rec.PeerID, "reason", string(reason))
		return outcomeRevoked, nil
	}

	// Revoke locally FIRST. The store is authoritative, and a control-plane
	// outage must not leave a sold agent trusted by the broker.
	revoked, storeErr := r.store.Revoke(ctx, rec.ID, string(reason))
	if storeErr != nil {
		r.log.Error("failed to revoke binding in the trust store",
			"bindingId", rec.ID, "caid", rec.CAID, "err", storeErr)
		return outcomeErrored, storeErr
	}
	if !revoked {
		// Raced with a re-bind; the newer binding will be checked next sweep.
		return outcomeHealthy, nil
	}

	r.log.Warn("binding revoked",
		"bindingId", rec.ID, "caid", rec.CAID, "peerId", rec.PeerID,
		"reason", string(reason), "detail", err.Error())

	if meshErr := r.mesh.RevokePeer(ctx, rec.PeerID, rec.MeshID, string(reason)); meshErr != nil {
		// The local revocation stands. Surface this loudly: the peer may retain
		// mesh access until its Biscuit expires.
		r.log.Error("binding revoked locally but the control plane could not be told",
			"bindingId", rec.ID, "peerId", rec.PeerID, "err", meshErr)
		return outcomeRevoked, meshErr
	}
	return outcomeRevoked, nil
}

// isInfrastructure reports whether a denial reason means "we could not check"
// rather than "the binding is invalid".
func isInfrastructure(reason binding.Reason) bool {
	switch reason {
	case binding.ReasonChainUnavailable,
		binding.ReasonRegistrationUnreachable,
		binding.ReasonCommitFailed:
		return true
	case binding.ReasonMalformed:
		// A stored document that no longer parses means either store corruption
		// or a parser regression. The second would revoke the ENTIRE mesh on
		// deploy, so this fails toward leaving bindings in place and shouting,
		// rather than toward mass revocation.
		return true
	case "":
		return true
	default:
		return false
	}
}
