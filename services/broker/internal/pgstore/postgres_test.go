//go:build postgres

package pgstore_test

import (
	"context"
	"database/sql"
	"os"
	"testing"

	// Registers the "pgx" driver with database/sql. The pgstore package itself
	// imports no driver, so the choice stays with the caller; the test makes
	// that choice explicitly.
	_ "github.com/jackc/pgx/v5/stdlib"

	"github.com/yorkerhodes3/sovereign-agent-trust-mesh/services/broker/internal/binding"
	"github.com/yorkerhodes3/sovereign-agent-trust-mesh/services/broker/internal/pgstore"
	"github.com/yorkerhodes3/sovereign-agent-trust-mesh/services/broker/internal/store/storetest"
)

// TestPostgresConformance holds the Postgres store to the EXACT same assertions
// the in-memory store passes.
//
// Build-tagged because it needs a live database. CI provides one as a service
// container (see .github/workflows/broker.yml). Locally, set SATM_POSTGRES_DSN
// and run:
//
//	go test -tags postgres ./internal/pgstore/
//
// The concurrency case in the shared suite is the one that matters most here:
// it is the only thing that proves the ON CONFLICT / RowsAffected approach
// really does serialise competing claims on a nonce.
func TestPostgresConformance(t *testing.T) {
	dsn := os.Getenv("SATM_POSTGRES_DSN")
	if dsn == "" {
		t.Skip("SATM_POSTGRES_DSN not set; skipping Postgres conformance suite")
	}

	storetest.Run(t, func(t *testing.T) binding.NonceStore {
		db, err := sql.Open("pgx", dsn)
		if err != nil {
			t.Fatalf("open: %v", err)
		}
		t.Cleanup(func() { _ = db.Close() })

		s, err := pgstore.New(db)
		if err != nil {
			t.Fatalf("new: %v", err)
		}

		ctx := context.Background()
		if err := s.Migrate(ctx); err != nil {
			t.Fatalf("migrate: %v", err)
		}
		// Each subtest needs a clean slate. Order matters: bindings reference
		// nonces.
		if _, err := db.ExecContext(ctx, `TRUNCATE satm_binding, satm_nonce`); err != nil {
			t.Fatalf("truncate: %v", err)
		}
		return s
	})
}
