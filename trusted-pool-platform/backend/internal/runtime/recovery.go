package runtime

import (
	"context"
	"errors"
	"fmt"
	"time"

	"trusted-pool-platform/backend/internal/recovery"
	"trusted-pool-platform/backend/internal/recovery/exporter"
)

// BuildRecoveryProviders 只组装生产注入的外部适配器；缺少任一项时保持 nil，由 Ready fail-close。
func BuildRecoveryProviders(root recovery.RecoveryRootProvider, canonicalizer recovery.ManifestCanonicalizer,
	signer recovery.PlatformSigner, attestation recovery.ProviderAttestationVerifier,
	members recovery.MemberSignatureVerifier, batches recovery.EpochCredentialBatchProvider,
	memberArtifacts recovery.MemberCeremonyGateway, rotations recovery.PermanentSeatRotationProvider,
	activations recovery.PermanentSeatActivationVerifier,
	claimCipher recovery.RecoveryCredentialCipher) recovery.Providers {
	return recovery.Providers{Root: root, Canonicalizer: canonicalizer, PlatformSigner: signer,
		Attestation: attestation, MemberSignatures: members, CredentialBatches: batches,
		MemberArtifacts: memberArtifacts, SeatRotations: rotations,
		SeatActivations: activations, CredentialCipher: claimCipher}
}

type VerificationExportConfig struct {
	ClientID      string
	LeaseOwner    string
	LeaseDuration time.Duration
}

// BuildVerificationExporter requires an explicitly injected external signer. The runtime never
// substitutes a local development key because exported evidence is intended to cross trust domains.
func BuildVerificationExporter(store exporter.Store, signer exporter.Signer,
	config VerificationExportConfig) (*exporter.Manager, error) {
	if store == nil || signer == nil {
		return nil, errors.New("recovery evidence export signer is not configured")
	}
	return exporter.NewManager(store, signer, exporter.Config{ClientID: config.ClientID,
		LeaseOwner: config.LeaseOwner, LeaseDuration: config.LeaseDuration})
}

type VerificationExportProbe struct {
	Manager *exporter.Manager
}

func (probe VerificationExportProbe) Check(ctx context.Context) error {
	if probe.Manager == nil {
		return errors.New("recovery evidence export manager is not configured")
	}
	return probe.Manager.Ready(ctx)
}

type RecoveryProbe struct {
	Manager *recovery.Manager
}

func (p RecoveryProbe) Check(ctx context.Context) error {
	if p.Manager == nil {
		return errors.New("recovery governance manager is not configured")
	}
	return p.Manager.Ready(ctx)
}

type RecoveryFinalizationScanner interface {
	RecoverNextFinalization(context.Context) (bool, error)
}

// RecoveryFinalizationLoop 可恢复 provider commit 至 READY_TO_ISSUE，但不执行 structural final，
// 也不生成或披露最终 claim token；这些动作必须有同步调用方接收。
type RecoveryFinalizationLoop struct {
	scanner     RecoveryFinalizationScanner
	idleBackoff time.Duration
}

func NewRecoveryFinalizationLoop(scanner RecoveryFinalizationScanner, idleBackoff time.Duration) (*RecoveryFinalizationLoop, error) {
	if scanner == nil || idleBackoff <= 0 {
		return nil, errors.New("recovery finalization scanner and positive idle backoff are required")
	}
	return &RecoveryFinalizationLoop{scanner: scanner, idleBackoff: idleBackoff}, nil
}

func (w *RecoveryFinalizationLoop) Run(ctx context.Context) error {
	for {
		worked, err := w.scanner.RecoverNextFinalization(ctx)
		if err != nil {
			return fmt.Errorf("recover Pool finalization: %w", err)
		}
		if worked {
			continue
		}
		timer := time.NewTimer(w.idleBackoff)
		select {
		case <-ctx.Done():
			if !timer.Stop() {
				<-timer.C
			}
			return ctx.Err()
		case <-timer.C:
		}
	}
}
