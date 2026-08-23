// Package pgstore is a PostgreSQL-backed binding.NonceStore.
//
// # Verification status
//
// Verified in CI against PostgreSQL 16, not on the author's machine: no
// Postgres or Docker was available where this was written. The broker workflow
// runs a service container and executes the shared conformance suite from
// internal/store/storetest under -race -- the same suite the in-memory store
// passes. "The Postgres store behaves like the in-memory store" is therefore a
// checked claim rather than an assumption.
//
// The case that matters most is the 32-way concurrent commit: it is the only
// thing that proves the ON CONFLICT / RowsAffected approach below really does
// serialise competing claims on a nonce. To run it locally:
//
//	SATM_POSTGRES_DSN=... go test -tags postgres ./internal/pgstore/
//
// # Design
//
// The package depends only on database/sql -- no driver is imported here. The
// caller supplies an already-open *sql.DB, so the choice of driver (pgx stdlib,
// lib/pq) stays at the composition root and this package adds no dependency
// weight to the broker.
//
// Nonce uniqueness is enforced by a PRIMARY KEY in its own table rather than by
// application logic, and consumption is tested via ON CONFLICT DO NOTHING plus
// RowsAffected rather than by inspecting SQLSTATE strings. That keeps the
// atomicity guarantee inside the database and keeps this code driver-agnostic.
package pgstore

import (
	"context"
	"database/sql"
	"errors"
	"fmt"

	"github.com/yorkerhodes3/sovereign-agent-trust-mesh/services/broker/internal/binding"
)

// Store is a PostgreSQL NonceStore.
type Store struct {
	db *sql.DB
}

var _ binding.NonceStore = (*Store)(nil)

// New wraps an open database handle.
func New(db *sql.DB) (*Store, error) {
	if db == nil {
		return nil, errors.New("pgstore: nil *sql.DB")
	}
	return &Store{db: db}, nil
}

// Schema is the DDL for the binding tables.
//
// Two separate tables is deliberate. Nonces MUST outlive the bindings they
// created: if a nonce row were deleted when its binding is revoked, the original
// signed document would become replayable, which is exactly what check B3 exists
// to stop. Keeping them apart makes that impossible to get wrong by accident.
const Schema = `
CREATE TABLE IF NOT EXISTS satm_nonce (
    nonce       TEXT PRIMARY KEY,
    consumed_at TIMESTAMPTZ NOT NULL DEFAULT now()
);

CREATE TABLE IF NOT EXISTS satm_binding (
    id               TEXT PRIMARY KEY,
    caid             TEXT        NOT NULL,
    peer_id          TEXT        NOT NULL,
    mesh_id          TEXT        NOT NULL,
    sidecar_key      TEXT        NOT NULL,
    agent_wallet     TEXT        NOT NULL,
    owner_address    TEXT        NOT NULL,
    nonce            TEXT        NOT NULL REFERENCES satm_nonce (nonce),
    document         BYTEA       NOT NULL,
    peer_signature   BYTEA       NOT NULL,
    wallet_signature BYTEA       NOT NULL,
    domain_verified  BOOLEAN     NOT NULL DEFAULT FALSE,
    issued_at        TIMESTAMPTZ NOT NULL,
    expires_at       TIMESTAMPTZ NOT NULL,
    revoked_at       TIMESTAMPTZ,
    created_at       TIMESTAMPTZ NOT NULL DEFAULT now()
);

-- At most one LIVE binding per agent. A partial unique index makes the
-- invariant a database guarantee rather than something the application
-- promises to maintain; superseded rows are retained for audit.
CREATE UNIQUE INDEX IF NOT EXISTS satm_binding_one_active_per_caid
    ON satm_binding (caid) WHERE revoked_at IS NULL;

CREATE INDEX IF NOT EXISTS satm_binding_active_wallet
    ON satm_binding (agent_wallet) WHERE revoked_at IS NULL;

CREATE INDEX IF NOT EXISTS satm_binding_peer
    ON satm_binding (peer_id) WHERE revoked_at IS NULL;
`

// Migrate applies the schema. It is idempotent.
func (s *Store) Migrate(ctx context.Context) error {
	if _, err := s.db.ExecContext(ctx, Schema); err != nil {
		return fmt.Errorf("pgstore: migrate: %w", err)
	}
	return nil
}

// Seen implements check B3.
func (s *Store) Seen(ctx context.Context, nonce string) (bool, error) {
	var exists bool
	err := s.db.QueryRowContext(ctx,
		`SELECT EXISTS (SELECT 1 FROM satm_nonce WHERE nonce = $1)`, nonce).Scan(&exists)
	if err != nil {
		return false, fmt.Errorf("pgstore: seen: %w", err)
	}
	return exists, nil
}

// Commit implements check B15 atomically.
//
// All three effects -- consume the nonce, retire the prior binding for this
// CAID, insert the new one -- happen in ONE transaction. If any step fails the
// whole thing rolls back, so a partially applied binding cannot exist.
func (s *Store) Commit(ctx context.Context, r *binding.Record) error {
	if r == nil {
		return errors.New("pgstore: nil record")
	}

	tx, err := s.db.BeginTx(ctx, nil)
	if err != nil {
		return fmt.Errorf("pgstore: begin: %w", err)
	}
	defer func() { _ = tx.Rollback() }() // no-op once Commit succeeds

	// Claim the nonce FIRST. ON CONFLICT DO NOTHING turns the race into a
	// row-count check: a concurrent transaction holding the same nonce blocks
	// this INSERT until it commits, after which we observe zero rows affected.
	// This avoids parsing driver-specific SQLSTATE values to detect the
	// conflict.
	res, err := tx.ExecContext(ctx,
		`INSERT INTO satm_nonce (nonce) VALUES ($1) ON CONFLICT (nonce) DO NOTHING`, r.Nonce)
	if err != nil {
		return fmt.Errorf("pgstore: claim nonce: %w", err)
	}
	affected, err := res.RowsAffected()
	if err != nil {
		return fmt.Errorf("pgstore: claim nonce rows: %w", err)
	}
	if affected == 0 {
		return binding.ErrNonceReused
	}

	// Retire any live binding for this CAID. Must precede the insert: the
	// partial unique index permits only one non-revoked row per CAID.
	if _, err := tx.ExecContext(ctx,
		`UPDATE satm_binding SET revoked_at = now() WHERE caid = $1 AND revoked_at IS NULL`,
		r.CAID); err != nil {
		return fmt.Errorf("pgstore: revoke prior binding: %w", err)
	}

	if _, err := tx.ExecContext(ctx, `
        INSERT INTO satm_binding (
            id, caid, peer_id, mesh_id, sidecar_key, agent_wallet, owner_address,
            nonce, document, peer_signature, wallet_signature, domain_verified,
            issued_at, expires_at
        ) VALUES ($1,$2,$3,$4,$5,$6,$7,$8,$9,$10,$11,$12,$13,$14)`,
		r.ID, r.CAID, r.PeerID, r.MeshID, r.SidecarKey, r.AgentWallet, r.Owner,
		r.Nonce, r.Document, r.PeerSignature, r.WalletSignature, r.DomainVerified,
		r.IssuedAt, r.ExpiresAt,
	); err != nil {
		return fmt.Errorf("pgstore: insert binding: %w", err)
	}

	if err := tx.Commit(); err != nil {
		return fmt.Errorf("pgstore: commit: %w", err)
	}
	return nil
}

// ActiveByWallet implements check B9a.
func (s *Store) ActiveByWallet(ctx context.Context, wallet string) (string, error) {
	var caid string
	err := s.db.QueryRowContext(ctx,
		`SELECT caid FROM satm_binding
         WHERE agent_wallet = $1 AND revoked_at IS NULL
         ORDER BY created_at DESC LIMIT 1`, wallet).Scan(&caid)
	if errors.Is(err, sql.ErrNoRows) {
		return "", nil
	}
	if err != nil {
		return "", fmt.Errorf("pgstore: active by wallet: %w", err)
	}
	return caid, nil
}

// ActiveByCAID returns the live binding for a CAID. Not part of the NonceStore
// port; used by the API layer for lookups.
func (s *Store) ActiveByCAID(ctx context.Context, caid string) (*binding.Record, error) {
	var r binding.Record
	err := s.db.QueryRowContext(ctx, `
        SELECT id, caid, peer_id, mesh_id, sidecar_key, agent_wallet, owner_address,
               nonce, document, peer_signature, wallet_signature, domain_verified,
               issued_at, expires_at
        FROM satm_binding
        WHERE caid = $1 AND revoked_at IS NULL`, caid,
	).Scan(
		&r.ID, &r.CAID, &r.PeerID, &r.MeshID, &r.SidecarKey, &r.AgentWallet, &r.Owner,
		&r.Nonce, &r.Document, &r.PeerSignature, &r.WalletSignature, &r.DomainVerified,
		&r.IssuedAt, &r.ExpiresAt,
	)
	if errors.Is(err, sql.ErrNoRows) {
		return nil, nil
	}
	if err != nil {
		return nil, fmt.Errorf("pgstore: active by caid: %w", err)
	}
	return &r, nil
}
