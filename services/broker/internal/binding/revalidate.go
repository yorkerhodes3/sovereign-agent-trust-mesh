package binding

import (
	"context"
	"fmt"
)

// Revalidate re-runs the checks that can change AFTER a binding is committed.
//
// A binding is not a permanent fact. Three things can invalidate one while it
// sits in the trust store, and none of them produce any signal at the broker:
//
//   - The agent NFT is transferred. ERC-8004 zeroes `agentWallet` on transfer,
//     so the wallet proof that authorised the binding no longer holds (TH-5).
//   - The registration file is edited to drop or change the `SAM` service
//     entry, so the on-chain record no longer advertises this peer (TH-16).
//   - The agent is marked inactive.
//
// This deliberately re-uses the SAME check implementations as initial
// verification rather than a parallel copy. A second implementation would drift,
// and a reconciler that is more permissive than the admission path is worse than
// no reconciler at all -- it would report everything healthy while the invariant
// it exists to protect had already broken.
//
// Freshness (B1) and the nonce (B3/B15) are deliberately NOT re-checked: the
// document's expiry governs how long a binding may be *created* from it, not how
// long the resulting binding lives, and the nonce is already consumed.
func (v *Verifier) Revalidate(ctx context.Context, rec *Record) error {
	if rec == nil {
		return fmt.Errorf("revalidate: nil record")
	}
	doc, err := Parse(rec.Document)
	if err != nil {
		// A stored document that no longer parses means the trust store itself
		// is corrupt. Failing closed is the only safe reading.
		return denyf(ReasonMalformed, "revalidate",
			"stored binding document no longer parses: %v", err)
	}

	// B2 and B2a again. The allow-list is configuration, and configuration
	// changes: a registry removed from it must invalidate bindings that were
	// admitted under it, not keep honouring them.
	if err := v.checkMesh(doc); err != nil {
		return err
	}
	reg, err := v.checkRegistry(doc)
	if err != nil {
		return err
	}

	// B6, B7, B8: ownership and wallet, live from chain. This is where a
	// transferred agent is caught.
	if _, _, err := v.checkOnChainIdentity(ctx, doc, reg); err != nil {
		return err
	}

	// B10..B14: the registration file must still name this agent and advertise
	// this peer on this mesh.
	if _, err := v.checkRegistrationFile(ctx, doc, reg); err != nil {
		return err
	}
	return nil
}
