package exporter

import (
	"context"
	"crypto/sha256"
	"encoding/hex"
	"strings"
	"time"

	"trusted-pool-platform/backend/internal/recovery"
	"trusted-pool-platform/backend/internal/recovery/offline"
)

type Store interface {
	BeginVerificationExport(context.Context, recovery.BeginVerificationExportInput) (*recovery.VerificationExportTarget, bool, error)
	LoadPublicEvidenceSnapshot(context.Context, recovery.LoadPublicEvidenceSnapshotInput) (*recovery.PublicEvidenceSnapshot, error)
	RenewVerificationExportLease(context.Context, recovery.RenewVerificationExportLeaseInput) (*recovery.StoredOperation, error)
	CommitVerificationExport(context.Context, recovery.CommitVerificationExportInput) (*recovery.StoredVerificationExport, bool, error)
	GetVerificationExport(context.Context, string) (*recovery.StoredVerificationExport, error)
}

type SignRequest struct {
	// IdempotencyKey is stable across lease takeover. Signers must replay the
	// same result for the same key/message and reject key reuse with drift.
	IdempotencyKey string
	Statement      offline.VerificationExportStatement
	Message        []byte
}

type Signature struct {
	Algorithm string
	KeyID     string
	Bytes     []byte
}

type Signer interface {
	Ready(context.Context) error
	Sign(context.Context, SignRequest) (Signature, error)
	Verify(context.Context, SignRequest, Signature) error
}

type Config struct {
	ClientID      string
	LeaseOwner    string
	LeaseDuration time.Duration
}

type Command struct {
	OperationID string
	ExportID    string
	PlanID      string
}

type Result struct {
	Export        *recovery.StoredVerificationExport
	Bundle        []byte
	FirstDelivery bool
}

type Manager struct {
	store  Store
	signer Signer
	config Config
}

func NewManager(store Store, signer Signer, config Config) (*Manager, error) {
	if store == nil || signer == nil || !validID(config.ClientID, 128) || !validID(config.LeaseOwner, 256) ||
		config.LeaseDuration < 30*time.Second || config.LeaseDuration > 5*time.Minute {
		return nil, recovery.ErrInvalidData
	}
	return &Manager{store: store, signer: signer, config: config}, nil
}

func (m *Manager) Ready(ctx context.Context) error {
	providerCtx, cancel := m.providerContext(ctx)
	defer cancel()
	if err := m.signer.Ready(providerCtx); err != nil {
		return recovery.ErrProviderUnavailable
	}
	return nil
}

func (m *Manager) Export(ctx context.Context, command Command) (*Result, error) {
	if !validID(command.OperationID, 128) || !validID(command.ExportID, 128) || !validID(command.PlanID, 128) {
		return nil, recovery.ErrInvalidData
	}
	begin := recovery.BeginVerificationExportInput{Key: recovery.OperationKey{ClientID: m.config.ClientID,
		OperationID: command.OperationID}, ExportExternalID: command.ExportID, PlanExternalID: command.PlanID,
		FormatVersion: offline.BundleProtocolVersion, LeaseOwner: m.config.LeaseOwner,
		LeaseDuration: m.config.LeaseDuration}
	begin.RequestSnapshot, begin.RequestHash, _ = recovery.BuildVerificationExportRequestSnapshot(begin)
	target, _, err := m.store.BeginVerificationExport(ctx, begin)
	if err != nil {
		return nil, err
	}
	if !validTarget(target, begin, m.config.LeaseOwner) {
		return nil, recovery.ErrBindingMismatch
	}
	terminal := target.Export.Status == recovery.VerificationExportAvailable
	generatedAt := target.Export.CreatedAt.UTC().Truncate(time.Microsecond)
	if terminal {
		if target.Export.GeneratedAt == nil {
			return nil, recovery.ErrInvalidState
		}
		generatedAt = target.Export.GeneratedAt.UTC().Truncate(time.Microsecond)
	} else if target.Export.Status != recovery.VerificationExportPending || target.Export.CreatedAt.IsZero() {
		return nil, recovery.ErrInvalidState
	}
	snapshotInput := recovery.LoadPublicEvidenceSnapshotInput{
		Key: target.Operation.Key, ExportID: command.ExportID}
	if !terminal {
		snapshotInput.LeaseOwner = m.config.LeaseOwner
		snapshotInput.FencingToken = target.Operation.FencingToken
	}
	snapshot, err := m.store.LoadPublicEvidenceSnapshot(ctx, snapshotInput)
	if err != nil {
		return nil, err
	}
	built, err := offline.BuildPublicEvidenceBundle(*snapshot, generatedAt)
	if err != nil {
		return nil, recovery.ErrInvalidData
	}
	if terminal {
		if target.Export.InventoryDigest != built.InventoryDigest || target.Export.BundleDigest != built.BundleDigest {
			return nil, recovery.ErrHashDrift
		}
		return &Result{Export: target.Export, Bundle: built.CanonicalBytes}, nil
	}
	renewed, err := m.store.RenewVerificationExportLease(ctx, recovery.RenewVerificationExportLeaseInput{
		Key: target.Operation.Key, LeaseOwner: m.config.LeaseOwner,
		ExpectedFencingToken: target.Operation.FencingToken, LeaseDuration: m.config.LeaseDuration,
		ExportExternalID: command.ExportID})
	if err != nil {
		return nil, err
	}
	if renewed == nil || renewed.Key != target.Operation.Key || renewed.Kind != target.Operation.Kind ||
		renewed.Status != "RUNNING" || renewed.FencingToken != target.Operation.FencingToken ||
		renewed.LeaseOwner != m.config.LeaseOwner || renewed.LeaseExpiresAt == nil ||
		renewed.RequestHash != target.Operation.RequestHash {
		return nil, recovery.ErrBindingMismatch
	}
	target.Operation = renewed
	providerCtx, cancel := m.providerContext(ctx)
	defer cancel()
	if err := m.signer.Ready(providerCtx); err != nil {
		return nil, recovery.ErrProviderUnavailable
	}
	statement := offline.VerificationExportStatement{ProtocolVersion: offline.BundleProtocolVersion,
		ExportID: command.ExportID, FormatVersion: offline.BundleProtocolVersion,
		InventoryDigest: hex.EncodeToString(built.InventoryDigest[:]),
		BundleDigest:    hex.EncodeToString(built.BundleDigest[:]),
		GeneratedAt:     generatedAt.Format(time.RFC3339Nano)}
	message, err := offline.BuildVerificationExportSignatureMessage(statement)
	if err != nil {
		return nil, recovery.ErrInvalidData
	}
	request := SignRequest{IdempotencyKey: verificationExportIdempotencyKey(begin),
		Statement: statement, Message: message}
	signature, err := m.signer.Sign(providerCtx, request)
	if err != nil || !validID(signature.Algorithm, 128) || !validID(signature.KeyID, 512) || len(signature.Bytes) == 0 {
		return nil, recovery.ErrProviderUnavailable
	}
	if err := m.signer.Verify(providerCtx, request, signature); err != nil {
		return nil, recovery.ErrProviderUnavailable
	}
	export, committed, err := m.store.CommitVerificationExport(ctx, recovery.CommitVerificationExportInput{
		Key: target.Operation.Key, LeaseOwner: m.config.LeaseOwner, FencingToken: target.Operation.FencingToken,
		ExportExternalID: command.ExportID, InventoryDigest: built.InventoryDigest, BundleDigest: built.BundleDigest,
		SignerDomain: recovery.VerificationExportSignatureDomainV1, SignerAlgorithm: signature.Algorithm,
		SignerKeyID: signature.KeyID, Signature: append([]byte(nil), signature.Bytes...), GeneratedAt: generatedAt})
	if err != nil {
		return nil, err
	}
	return &Result{Export: export, Bundle: built.CanonicalBytes, FirstDelivery: committed}, nil
}

func (m *Manager) Download(ctx context.Context, planID, exportID string) (*Result, error) {
	if !validID(planID, 128) || !validID(exportID, 128) {
		return nil, recovery.ErrInvalidData
	}
	export, err := m.store.GetVerificationExport(ctx, exportID)
	if err != nil {
		return nil, err
	}
	if export == nil || export.Status != recovery.VerificationExportAvailable ||
		export.PlanExternalID != planID || export.GeneratedAt == nil ||
		!validID(export.OperationKey.ClientID, 128) || !validID(export.OperationKey.OperationID, 128) {
		return nil, recovery.ErrInvalidState
	}
	snapshot, err := m.store.LoadPublicEvidenceSnapshot(ctx, recovery.LoadPublicEvidenceSnapshotInput{
		Key: export.OperationKey, ExportID: exportID,
	})
	if err != nil {
		return nil, err
	}
	built, err := offline.BuildPublicEvidenceBundle(*snapshot, export.GeneratedAt.UTC().Truncate(time.Microsecond))
	if err != nil || built.InventoryDigest != export.InventoryDigest || built.BundleDigest != export.BundleDigest {
		return nil, recovery.ErrHashDrift
	}
	return &Result{Export: export, Bundle: built.CanonicalBytes}, nil
}

func (m *Manager) providerContext(parent context.Context) (context.Context, context.CancelFunc) {
	return context.WithTimeout(parent, m.config.LeaseDuration/2)
}

func validTarget(target *recovery.VerificationExportTarget, begin recovery.BeginVerificationExportInput,
	leaseOwner string) bool {
	if target == nil || target.Operation == nil || target.Export == nil || target.Operation.Key != begin.Key ||
		target.Operation.RequestHash != begin.RequestHash || target.Operation.Kind != "EXPORT_RECOVERY_VERIFICATION" ||
		target.Export.ExternalID != begin.ExportExternalID || target.Export.PlanExternalID != begin.PlanExternalID ||
		target.Export.FormatVersion != begin.FormatVersion {
		return false
	}
	if target.Export.Status == recovery.VerificationExportAvailable {
		return target.Operation.Status == "SUCCEEDED"
	}
	return target.Operation.Status == "RUNNING" && target.Operation.FencingToken > 0 &&
		target.Operation.LeaseOwner == leaseOwner && target.Operation.LeaseExpiresAt != nil
}

func validID(value string, maximum int) bool {
	return value != "" && len(value) <= maximum && strings.TrimSpace(value) == value
}

func verificationExportIdempotencyKey(begin recovery.BeginVerificationExportInput) string {
	material := make([]byte, 0, len(recovery.VerificationExportSignatureDomainV1)+
		len(begin.Key.ClientID)+sha256.Size+2)
	material = append(material, recovery.VerificationExportSignatureDomainV1...)
	material = append(material, 0)
	material = append(material, begin.Key.ClientID...)
	material = append(material, 0)
	material = append(material, begin.RequestHash[:]...)
	digest := sha256.Sum256(material)
	return hex.EncodeToString(digest[:])
}
