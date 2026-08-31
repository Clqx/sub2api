package recovery

import (
	"context"
	"crypto/sha256"
	"encoding/hex"
	"errors"
	"reflect"
	"strings"
	"testing"
	"time"

	"trusted-pool-platform/backend/internal/credentials"
)

type prepareStoreStub struct {
	Store
	now                time.Time
	log                *[]string
	operation          *StoredOperation
	plan               *StoredEpochPlan
	root               *StoredRootArtifact
	deliveries         []StoredShareDelivery
	manifest           []byte
	platformAlgorithm  string
	platformDomain     string
	platformKeyRef     string
	platformSignature  []byte
	platformVerifiedAt time.Time
	receipts           []MemberArtifactReceipt
}

func (s *prepareStoreStub) CommitMemberArtifactReceipt(_ context.Context,
	input CommitMemberArtifactReceiptInput) error {
	*s.log = append(*s.log, "commit-artifact-receipt")
	receipt := input.Receipt
	receipt.ProviderProof = append([]byte(nil), input.Receipt.ProviderProof...)
	s.receipts = append(s.receipts, receipt)
	return nil
}

func (s *prepareStoreStub) GetEpochPlan(context.Context, string) (*StoredEpochPlan, error) {
	if s.plan == nil {
		return nil, ErrNotFound
	}
	return clonePlan(s.plan), nil
}
func (s *prepareStoreStub) GetEpochPlanProgress(context.Context, string) (*EpochPlanTarget, error) {
	if s.plan == nil || s.operation == nil {
		return nil, ErrNotFound
	}
	operation := *s.operation
	if s.operation.LeaseExpiresAt != nil {
		expires := *s.operation.LeaseExpiresAt
		operation.LeaseExpiresAt = &expires
	}
	return &EpochPlanTarget{Operation: &operation, Plan: clonePlan(s.plan)}, nil
}
func (s *prepareStoreStub) BeginEpochPlan(_ context.Context, input BeginEpochPlanInput) (*EpochPlanTarget, bool, error) {
	*s.log = append(*s.log, "begin")
	expires := s.now.Add(time.Minute)
	s.operation = &StoredOperation{Key: input.Key, LeaseOwner: input.LeaseOwner, FencingToken: 1,
		LeaseExpiresAt: &expires, RequestHash: input.RequestHash, RequestSnapshot: append([]byte(nil), input.RequestSnapshot...)}
	s.plan = &StoredEpochPlan{ExternalID: input.PlanExternalID, PoolExternalID: input.PoolExternalID,
		CeremonyType: input.CeremonyType, FromEpoch: input.FromEpoch, ToEpoch: input.ToEpoch,
		Status: planStatusPlanned, GovernanceThreshold: input.GovernanceThreshold, RecoveryThreshold: input.RecoveryThreshold,
		ExpectedMemberCount: len(input.Members), ExpectedResourceCount: 2, PreviousManifestHash: input.PreviousManifestHash,
		CeremonyAttestationRef: input.BootstrapAttestationRef, CeremonyAttestationDigest: input.BootstrapAttestationDigest,
		CeremonyAttestationIssuer: input.BootstrapAttestationIssuer, CeremonyAttestationKeyID: input.BootstrapAttestationKeyID,
		CeremonyAttestationVersion: input.BootstrapAttestationVersion, PortableProfile: input.PortableProfile}
	return &EpochPlanTarget{Operation: s.operation, Plan: s.plan}, true, nil
}
func (s *prepareStoreStub) AcquireEpochPlanLease(_ context.Context, input AcquireEpochPlanLeaseInput) (*StoredOperation, error) {
	*s.log = append(*s.log, "heartbeat")
	if s.operation == nil || input.ExpectedFencingToken != s.operation.FencingToken {
		return nil, ErrStaleFence
	}
	if s.operation.LeaseExpiresAt != nil && s.operation.LeaseExpiresAt.After(s.now) && input.LeaseOwner != s.operation.LeaseOwner {
		return nil, ErrLeaseHeld
	}
	expires := s.now.Add(time.Minute)
	clone := *s.operation
	if clone.LeaseExpiresAt == nil || !clone.LeaseExpiresAt.After(s.now) {
		clone.FencingToken++
	}
	clone.LeaseOwner = input.LeaseOwner
	clone.LeaseExpiresAt = &expires
	s.operation = &clone
	return s.operation, nil
}
func (s *prepareStoreStub) CommitRootArtifact(_ context.Context, input RootArtifactInput) (*StoredEpochPlan, error) {
	*s.log = append(*s.log, "commit-root")
	s.root = &StoredRootArtifact{ExternalID: input.ExternalID, Provider: input.Provider,
		ProviderKeyRef: input.ProviderKeyRef, RootHandle: input.RootHandle, RootKeyVersion: input.RootKeyVersion,
		EpochRecoveryAlgorithm: input.EpochRecoveryAlgorithm, EpochRecoveryKeyID: input.EpochRecoveryKeyID,
		EpochRecoveryKeyFingerprint: input.EpochRecoveryKeyFingerprint, WrapDomain: input.WrapDomain,
		WrapAlgorithm: input.WrapAlgorithm, VSSAlgorithm: input.VSSAlgorithm, VSSCommitmentHash: input.VSSCommitmentHash,
		VSSProofHash: input.VSSProofHash, PrivateKeyCommitmentHash: input.PrivateKeyCommitmentHash,
		RootCommitmentHash: input.RootCommitmentHash, RecoveryPackageHash: input.RecoveryPackageHash,
		RequestIntentHash: input.RequestIntentHash, ProviderAttestationRef: input.ProviderAttestationRef,
		AttestationDigest: input.AttestationDigest, AttestationSignature: append([]byte(nil), input.AttestationSignature...),
		AttestationKeyID:                   input.AttestationKeyID,
		PortableAttestationAlgorithm:       input.PortableAttestationAlgorithm,
		PortableAttestationIssuer:          input.PortableAttestationIssuer,
		PortableAttestationKeyID:           input.PortableAttestationKeyID,
		PortableAttestationProtocolVersion: input.PortableAttestationProtocolVersion,
		PortableAttestationSignature:       append([]byte(nil), input.PortableAttestationSignature...)}
	s.plan.Status, s.plan.RootArtifactID = planStatusRootCommitted, input.ExternalID
	return clonePlan(s.plan), nil
}
func (s *prepareStoreStub) CommitShareDeliveries(_ context.Context, _ OperationKey, _ string, _ int64,
	values []ShareDeliveryInput) (*StoredEpochPlan, error) {
	*s.log = append(*s.log, "commit-shares")
	for _, value := range values {
		s.deliveries = append(s.deliveries, StoredShareDelivery{ExternalID: value.ExternalID,
			MemberExternalID: value.MemberExternalID, ShareIndex: value.ShareIndex,
			EncryptionAlgorithm: value.EncryptionAlgorithm, RecipientKeyID: value.RecipientKeyID,
			RecipientKeyFingerprint: value.RecipientKeyFingerprint, CiphertextHash: value.CiphertextHash,
			ProviderShareCommitment:      append([]byte(nil), value.ProviderShareCommitment...),
			ProviderProofDigest:          value.ProviderProofDigest,
			ProviderProofSignature:       append([]byte(nil), value.ProviderProofSignature...),
			PortableProofAlgorithm:       value.PortableProofAlgorithm,
			PortableProofKeyID:           value.PortableProofKeyID,
			PortableProofProtocolVersion: value.PortableProofProtocolVersion,
			PortableProofSignature:       append([]byte(nil), value.PortableProofSignature...),
			RootCommitmentHash:           s.root.RootCommitmentHash, VSSCommitmentHash: s.root.VSSCommitmentHash,
			RecoveryPackageHash: s.root.RecoveryPackageHash, RequestIntentHash: s.root.RequestIntentHash})
	}
	s.plan.Status, s.plan.CommittedShareCount = planStatusSharesCommitted, len(values)
	return clonePlan(s.plan), nil
}
func (s *prepareStoreStub) CommitManifestDraft(_ context.Context, input ManifestDraftInput) (*StoredEpochPlan, error) {
	*s.log = append(*s.log, "commit-manifest")
	if s.root == nil || input.ProviderAttestationDigest != s.root.AttestationDigest {
		return nil, ErrBindingMismatch
	}
	s.manifest = append([]byte(nil), input.CanonicalPayload...)
	s.platformAlgorithm, s.platformKeyRef = input.PlatformAlgorithm, input.PlatformKeyRef
	s.platformDomain = input.PlatformSignatureDomain
	s.platformSignature = append([]byte(nil), input.PlatformSignature...)
	s.platformVerifiedAt = input.PlatformVerifiedAt
	s.plan.Status, s.plan.ManifestID, s.plan.ManifestHash = planStatusManifestDraft, input.ExternalID, input.ManifestHash
	return clonePlan(s.plan), nil
}
func (s *prepareStoreStub) GetEpochSecuritySnapshot(context.Context, string) (*EpochSecuritySnapshot, error) {
	return &EpochSecuritySnapshot{Plan: clonePlan(s.plan), Root: s.root,
		Deliveries: append([]StoredShareDelivery(nil), s.deliveries...), ManifestCanonical: append([]byte(nil), s.manifest...),
		ManifestHash: s.plan.ManifestHash, ManifestPlatformDomain: s.platformDomain,
		ManifestPlatformAlgorithm: s.platformAlgorithm,
		ManifestPlatformKeyRef:    s.platformKeyRef, ManifestPlatformSignature: append([]byte(nil), s.platformSignature...),
		ManifestPlatformVerifiedAt: s.platformVerifiedAt}, nil
}

type managerRootProvider struct{ log *[]string }

func (p *managerRootProvider) Ready(context.Context) error { return nil }
func (p *managerRootProvider) CreateEncryptedPackage(_ context.Context, request RecoveryPackageRequest) (EncryptedRecoveryPackage, error) {
	*p.log = append(*p.log, "provider-root")
	return validRecoveryPackage(request), nil
}
func (*managerRootProvider) WrapCredentialDEK(context.Context, EpochDEKWrapRequest) (EpochDEKWrapResult, error) {
	return EpochDEKWrapResult{}, nil
}

type managerAttestationProvider struct{ now time.Time }

func (*managerAttestationProvider) Ready(context.Context) error { return nil }
func (*managerAttestationProvider) VerifyRecoveryPackage(context.Context, RecoveryPackageVerifyRequest) error {
	return nil
}
func (*managerAttestationProvider) VerifyEncryptedShare(context.Context, EncryptedShareVerifyRequest) error {
	return nil
}
func (*managerAttestationProvider) VerifyCredentialDEKWrap(context.Context, EpochDEKWrapVerifyRequest) error {
	return nil
}
func (*managerAttestationProvider) VerifyStagedCredentialBatch(context.Context, EpochCredentialBatchVerifyRequest) error {
	return nil
}
func (*managerAttestationProvider) VerifyMemberArtifactReceipt(context.Context, MemberArtifactReceiptVerifyRequest) error {
	return nil
}
func (p *managerAttestationProvider) VerifyControlAttestation(_ context.Context, request ProviderAttestationVerifyRequest) (VerifiedProviderAttestation, error) {
	intent := request.Intent
	return VerifiedProviderAttestation{Version: intent.Version, CeremonyType: intent.CeremonyType,
		Purpose: rotationAttestationPurpose, OperationID: intent.OperationID, PoolID: intent.PoolID,
		FromEpoch: intent.FromEpoch, ToEpoch: intent.ToEpoch, FromEpochStatus: intent.FromEpochStatus,
		FromGovernanceState: intent.FromGovernanceState, PreviousManifestHash: intent.PreviousManifestHash,
		Replacements: intent.Replacements, Seats: intent.Seats, Accounts: intent.Accounts,
		Issuer: "provider", VerificationKeyID: "provider-key", Reference: "ceremony-attestation-1",
		CanonicalDigest: sha256.Sum256([]byte("ceremony-attestation")), IssuedAt: p.now.Add(-time.Hour),
		ExpiresAt: p.now.Add(time.Hour)}, nil
}

type managerMemberVerifier struct{}

func (*managerMemberVerifier) Ready(context.Context) error { return nil }
func (*managerMemberVerifier) VerifyMemberKeyProof(context.Context, MemberKeyProofVerifyRequest) error {
	return nil
}
func (*managerMemberVerifier) VerifyMemberSignature(context.Context, MemberSignatureVerifyRequest) error {
	return nil
}

type managerPlatformSigner struct{ now time.Time }

func (*managerPlatformSigner) Ready(context.Context) error { return nil }
func (p *managerPlatformSigner) SignManifest(_ context.Context, request PlatformManifestSignRequest) (PlatformManifestSignature, error) {
	return PlatformManifestSignature{SignatureDomain: request.SignatureDomain, CeremonyType: request.CeremonyType, OperationID: request.OperationID,
		PoolID: request.PoolID, Epoch: request.Epoch, ManifestHash: request.ManifestHash,
		Algorithm: "Ed25519", KeyID: "platform-signing-key", Signature: make([]byte, 64), SignedAt: p.now}, nil
}
func (*managerPlatformSigner) VerifyManifestSignature(context.Context, PlatformManifestVerifyRequest) error {
	return nil
}

type managerBatchProvider struct{}

func (*managerBatchProvider) Ready(context.Context) error { return nil }
func (*managerBatchProvider) SealCredentialBatch(context.Context, EpochCredentialBatchRequest) (EpochCredentialBatchResult, error) {
	return EpochCredentialBatchResult{}, nil
}

type replayingBatchProvider struct {
	results map[string]EpochCredentialBatchResult
}

func (*replayingBatchProvider) Ready(context.Context) error { return nil }
func (p *replayingBatchProvider) SealCredentialBatch(_ context.Context, request EpochCredentialBatchRequest) (EpochCredentialBatchResult, error) {
	if p.results == nil {
		p.results = make(map[string]EpochCredentialBatchResult)
	}
	key := request.OperationID + "\x00" + request.BatchID + "\x00" + hex.EncodeToString(request.RequestHash[:])
	if result, ok := p.results[key]; ok {
		return result, nil
	}
	result := EpochCredentialBatchResult{CeremonyType: request.CeremonyType, OperationID: request.OperationID,
		RequestHash: request.RequestHash, PoolID: request.PoolID, Epoch: request.Epoch,
		Batch: StagedCredentialBatch{ExternalID: request.BatchID}, ProviderProof: []byte("durable-provider-result")}
	p.results[key] = result
	return EpochCredentialBatchResult{}, errors.New("provider result unknown")
}

type managerArtifactGateway struct {
	published []MemberArtifactPublishRequest
}

type managerSeatRotationProvider struct{}

func (*managerSeatRotationProvider) Ready(context.Context) error { return nil }
func (*managerSeatRotationProvider) PreparePoolRotation(context.Context, PermanentPoolRotationPrepareRequest) (PermanentPoolRotationPrepareResult, error) {
	return PermanentPoolRotationPrepareResult{}, nil
}
func (*managerSeatRotationProvider) ActivatePreparedPoolRotation(context.Context, PermanentPoolRotationActivateRequest) (PermanentPoolRotationActivateResult, error) {
	return PermanentPoolRotationActivateResult{}, nil
}
func (*managerSeatRotationProvider) CommitActivatedPoolRotation(context.Context, PermanentPoolRotationCommitRequest) (PermanentPoolRotationCommitResult, error) {
	return PermanentPoolRotationCommitResult{}, nil
}

type finalizationRotationProvider struct {
	now           time.Time
	prepareCalls  int
	activateCalls int
	commitCalls   int
	onPrepare     func()
	waitPrepare   bool
	prepareBudget time.Duration
}

func (*finalizationRotationProvider) Ready(context.Context) error { return nil }

func (p *finalizationRotationProvider) PreparePoolRotation(ctx context.Context,
	request PermanentPoolRotationPrepareRequest) (PermanentPoolRotationPrepareResult, error) {
	p.prepareCalls++
	if deadline, ok := ctx.Deadline(); ok {
		p.prepareBudget = time.Until(deadline)
	}
	if p.waitPrepare {
		<-ctx.Done()
		if p.onPrepare != nil {
			p.onPrepare()
		}
		return PermanentPoolRotationPrepareResult{}, ctx.Err()
	}
	if p.onPrepare != nil {
		p.onPrepare()
	}
	results := make([]PermanentSeatRotationPrepareResult, len(request.Seats))
	for index, seat := range request.Seats {
		results[index] = PermanentSeatRotationPrepareResult{ProtocolVersion: seat.ProtocolVersion,
			OperationID: seat.OperationID, RequestHash: seat.RequestHash, PlanID: seat.PlanID,
			CeremonyType: seat.CeremonyType, PoolID: seat.PoolID, FromEpoch: seat.FromEpoch, ToEpoch: seat.ToEpoch,
			SeatID: seat.SeatID, TargetMemberID: seat.TargetMemberID,
			AssignmentEpoch: seat.ExpectedAssignmentEpoch + 1, PrincipalUserID: seat.PrincipalUserID,
			SubscriptionID: seat.SubscriptionID, APIKeyID: seat.APIKeyID,
			ActiveAPIKeyVersion: seat.ToAPIKeyVersion, State: "ROTATION_PREPARED",
			CredentialRotationComplete: true, Credential: []byte("credential-" + seat.SeatID),
			PreparedRotationRef: "prepared-" + seat.SeatID, CompletedAt: p.now}
	}
	return PermanentPoolRotationPrepareResult{ProtocolVersion: request.ProtocolVersion,
		OperationID: request.OperationID, RequestHash: request.RequestHash, PlanID: request.PlanID,
		CeremonyType: request.CeremonyType, PoolID: request.PoolID, FromEpoch: request.FromEpoch,
		ToEpoch: request.ToEpoch, ChildSetHash: request.ChildSetHash, Seats: results}, nil
}

func (p *finalizationRotationProvider) ActivatePreparedPoolRotation(_ context.Context,
	request PermanentPoolRotationActivateRequest) (PermanentPoolRotationActivateResult, error) {
	p.activateCalls++
	seats := make([]PermanentSeatActivationResult, len(request.Seats))
	for index, seat := range request.Seats {
		seats[index] = PermanentSeatActivationResult{PermanentSeatActivationBinding: seat,
			AssignmentEpoch: seat.ExpectedAssignmentEpoch + 1, State: "ROTATION_ACTIVATED_PENDING_COMMIT"}
	}
	proof := []byte("valid-ed25519-signature")
	return PermanentPoolRotationActivateResult{ProtocolVersion: request.ProtocolVersion,
		OperationID: request.OperationID, PrepareOperationID: request.PrepareOperationID,
		RequestHash: request.RequestHash, PlanID: request.PlanID, CeremonyType: request.CeremonyType,
		PoolID: request.PoolID, FromEpoch: request.FromEpoch, ToEpoch: request.ToEpoch,
		PreparedSetHash: request.PreparedSetHash, State: "ACTIVATED_PENDING_COMMIT",
		OldCredentialSetInvalidated:       true,
		CredentialFingerprintGateEnforced: true, Seats: seats, AttestationAlgorithm: "Ed25519",
		AuthCacheDurableOutbox: true, AuthCacheMinimumEvents: 2,
		AttestationIssuer: "sub2api-rotation", AttestationRef: "activation-proof-1",
		AttestationKeyID: "rotation-signing-key-1", AttestationVersion: 1,
		AttestationDigest: sha256.Sum256([]byte("activation-proof-digest")), Attestation: proof,
		ActivatedAt: p.now}, nil
}

func (p *finalizationRotationProvider) CommitActivatedPoolRotation(_ context.Context,
	request PermanentPoolRotationCommitRequest) (PermanentPoolRotationCommitResult, error) {
	p.commitCalls++
	seats := make([]PermanentSeatActivationResult, len(request.Seats))
	for index, seat := range request.Seats {
		seats[index] = PermanentSeatActivationResult{PermanentSeatActivationBinding: seat,
			AssignmentEpoch: seat.ExpectedAssignmentEpoch + 1, State: "ACTIVE"}
	}
	return PermanentPoolRotationCommitResult{ProtocolVersion: request.ProtocolVersion,
		OperationID: request.OperationID, PrepareOperationID: request.PrepareOperationID,
		ActivationOperationID: request.ActivationOperationID, ActivationRequestHash: request.ActivationRequestHash,
		RequestHash: request.RequestHash, PlanID: request.PlanID, CeremonyType: request.CeremonyType,
		PoolID: request.PoolID, FromEpoch: request.FromEpoch, ToEpoch: request.ToEpoch,
		PreparedSetHash: request.PreparedSetHash, State: "COMMITTED", AllCredentialsEnabled: true,
		AllSubscriptionsEnabled: true, OldCredentialSetInvalidated: true,
		CredentialFingerprintGateEnforced: true, AuthCacheDurableOutbox: true, AuthCacheMinimumEvents: 1,
		Seats: seats, AttestationAlgorithm: "Ed25519", AttestationIssuer: "sub2api-rotation",
		AttestationRef: "commit-proof-1", AttestationKeyID: "rotation-signing-key-1", AttestationVersion: 1,
		AttestationDigest: sha256.Sum256([]byte("commit-proof-digest")),
		Attestation:       []byte("valid-ed25519-signature"), CommittedAt: p.now}, nil
}

type finalizationStoreStub struct {
	Store
	now          time.Time
	target       *PermanentReplacementTarget
	workerLeased bool
	parentFence  int64
	childFences  map[string]int64
	renewParent  int
	renewChild   int
	reconciled   bool
	structural   bool
	issued       bool
	beginOrder   []string
	claimIntents []ReplacementClaimIntent
	commitClaims []ReplacementClaimActivation
}

func (s *finalizationStoreStub) AcquireNextPermanentReplacementLease(_ context.Context,
	_ AcquireNextPermanentReplacementLeaseInput) (*PermanentReplacementTarget, error) {
	if s.workerLeased {
		return nil, ErrNotFound
	}
	s.workerLeased = true
	return s.target, nil
}

func newFinalizationStoreStub(now time.Time) *finalizationStoreStub {
	lease := now.Add(time.Minute)
	return &finalizationStoreStub{now: now, parentFence: 1, childFences: make(map[string]int64),
		target: &PermanentReplacementTarget{
			Operation: &StoredOperation{Key: OperationKey{ClientID: "recovery-client", OperationID: "finalize-op-1"},
				Kind: "REPLACE_PERMANENTLY", Status: "RUNNING", FencingToken: 1,
				LeaseOwner: "worker-unique-1", LeaseExpiresAt: &lease},
			Plan: &StoredEpochPlan{ExternalID: "plan-1", CeremonyType: CeremonyRotate, PoolExternalID: "pool-1",
				FromEpoch: 7, ToEpoch: 8, Status: planStatusReady, ExpectedMemberCount: 1},
			CaseExternalID: "case-1", CaseStatus: "READY",
			SeatTargets: []SeatRotationTarget{{
				Progress: &StoredSeatRotationProgress{PlanExternalID: "plan-1", PoolExternalID: "pool-1",
					FromEpoch: 7, ToEpoch: 8, SeatExternalID: "seat-1", TargetMemberExternalID: "member-new",
					ExpectedAssignmentEpoch: 3, ExpectedPrincipalUserID: 101, ExpectedSubscriptionID: 202,
					ExpectedAPIKeyID: 303, ExpectedAPIKeyVersion: 3},
			}},
		}}
}

func (s *finalizationStoreStub) RenewPermanentReplacementLease(_ context.Context,
	input RenewPermanentReplacementLeaseInput) (*PermanentReplacementTarget, error) {
	s.renewParent++
	operation := s.target.Operation
	if operation == nil || input.Key != operation.Key || input.LeaseOwner != operation.LeaseOwner ||
		input.ExpectedFencingToken != s.parentFence || operation.FencingToken != s.parentFence ||
		operation.LeaseExpiresAt == nil || !s.now.Before(*operation.LeaseExpiresAt) {
		return nil, ErrStaleFence
	}
	expires := s.now.Add(input.LeaseDuration)
	operation.LeaseExpiresAt = &expires
	return s.target, nil
}

func (s *finalizationStoreStub) RenewRecoveryChildOperationLease(_ context.Context,
	input RenewRecoveryChildOperationLeaseInput) (*StoredOperation, error) {
	s.renewChild++
	var operation *StoredOperation
	for index := range s.target.SeatTargets {
		candidate := s.target.SeatTargets[index].Operation
		if candidate != nil && candidate.Key.OperationID == input.DerivedOperationID {
			operation = candidate
			break
		}
	}
	for _, candidate := range []*StoredOperation{s.target.Preparation, s.target.Activation, s.target.ProviderRelease} {
		if candidate != nil && candidate.Key.OperationID == input.DerivedOperationID {
			operation = candidate
			break
		}
	}
	storedFence, exists := s.childFences[input.DerivedOperationID]
	if operation == nil || !exists || input.FinalizationKey != s.target.Operation.Key ||
		input.FinalizationFencingToken != s.parentFence || input.FinalizationLeaseOwner != s.target.Operation.LeaseOwner ||
		input.ChildLeaseOwner != operation.LeaseOwner || input.ExpectedChildFencingToken != storedFence ||
		operation.FencingToken != storedFence ||
		operation.Status != "RUNNING" || operation.LeaseExpiresAt == nil || !s.now.Before(*operation.LeaseExpiresAt) {
		return nil, ErrStaleFence
	}
	expires := s.now.Add(input.ChildLeaseDuration)
	operation.LeaseExpiresAt = &expires
	return operation, nil
}

func (s *finalizationStoreStub) BeginPermanentReplacement(_ context.Context,
	input BeginPermanentReplacementInput) (*PermanentReplacementTarget, bool, error) {
	if input.Key != s.target.Operation.Key || input.PlanExternalID != s.target.Plan.ExternalID || len(input.Seats) != 1 {
		return nil, false, ErrBindingMismatch
	}
	if s.issued {
		s.target.Operation.Status = "SUCCEEDED"
		return s.target, false, nil
	}
	return s.target, true, nil
}

func (s *finalizationStoreStub) BeginSeatRotation(_ context.Context,
	input BeginSeatRotationInput) (*SeatRotationTarget, bool, error) {
	s.beginOrder = append(s.beginOrder, "seat")
	lease := s.now.Add(input.ChildLeaseDuration)
	child := &StoredOperation{Key: OperationKey{ClientID: input.FinalizationKey.ClientID,
		OperationID: input.DerivedOperationID}, Status: "RUNNING", RequestHash: input.RequestHash,
		FencingToken: 1, LeaseOwner: input.ChildLeaseOwner, LeaseExpiresAt: &lease}
	s.target.SeatTargets[0].Operation = child
	s.childFences[input.DerivedOperationID] = child.FencingToken
	s.target.SeatTargets[0].Progress.DerivedOperationID = input.DerivedOperationID
	s.target.SeatTargets[0].Progress.Status = "PREPARE_PENDING"
	return &s.target.SeatTargets[0], true, nil
}

func (s *finalizationStoreStub) BeginPoolPreparation(_ context.Context,
	input BeginPoolPreparationInput) (*PoolPreparationTarget, bool, error) {
	s.beginOrder = append(s.beginOrder, "pool-prepare")
	lease := s.now.Add(input.LeaseDuration)
	s.target.Preparation = &StoredOperation{Key: OperationKey{ClientID: input.FinalizationKey.ClientID,
		OperationID: input.DerivedOperationID}, Status: "RUNNING", RequestHash: input.RequestHash,
		FencingToken: 1, LeaseOwner: input.LeaseOwner, LeaseExpiresAt: &lease}
	s.childFences[input.DerivedOperationID] = s.target.Preparation.FencingToken
	setHash, _ := PermanentRotationChildSetHash([]PermanentSeatRotationPrepareRequest{
		mustSeatPrepareRequestForTest(s.target.Plan, s.target.SeatTargets[0].Progress)})
	return &PoolPreparationTarget{Operation: s.target.Preparation, Plan: s.target.Plan,
		IntentSetHash: setHash}, true, nil
}

func (s *finalizationStoreStub) CommitSeatRotationProgress(_ context.Context,
	input CommitSeatRotationProgressInput) (*StoredSeatRotationProgress, error) {
	progress := s.target.SeatTargets[0].Progress
	progress.Status, progress.PrincipalUserID, progress.SubscriptionID = "PREPARED", input.PrincipalUserID, input.SubscriptionID
	progress.APIKeyID, progress.APIKeyVersion = input.APIKeyID, input.APIKeyVersion
	progress.CredentialFingerprint = input.Claim.CredentialFingerprint
	progress.PreparedReference = input.Claim.PreparedReference
	progress.ProviderResultDigest = input.Claim.ProviderResultDigest
	s.target.SeatTargets[0].Operation.Status = "SUCCEEDED"
	s.target.Preparation.Status = "SUCCEEDED"
	return progress, nil
}

func (s *finalizationStoreStub) CommitPoolPreparationFailure(_ context.Context,
	input CommitPoolPreparationFailureInput) (*StoredOperation, error) {
	if input.Status != "RECONCILE_REQUIRED" || s.target.Preparation == nil ||
		input.PreparationKey != s.target.Preparation.Key ||
		input.PreparationFencingToken != s.target.Preparation.FencingToken {
		return nil, ErrInvalidData
	}
	s.reconciled = true
	s.target.Preparation.Status = "RECONCILE_REQUIRED"
	return s.target.Preparation, nil
}

func (s *finalizationStoreStub) BeginPoolActivation(_ context.Context,
	input BeginPoolActivationInput) (*PoolActivationTarget, bool, error) {
	s.beginOrder = append(s.beginOrder, "pool-activate")
	lease := s.now.Add(input.ChildLeaseDuration)
	s.target.Activation = &StoredOperation{Key: OperationKey{ClientID: input.FinalizationKey.ClientID,
		OperationID: input.DerivedOperationID}, Status: "RUNNING", RequestHash: input.RequestHash,
		FencingToken: 1, LeaseOwner: input.ChildLeaseOwner, LeaseExpiresAt: &lease}
	s.childFences[input.DerivedOperationID] = s.target.Activation.FencingToken
	bindings, _ := activationBindings(s.target.SeatTargets)
	setHash, _ := PermanentPreparedSeatSetHash(bindings)
	return &PoolActivationTarget{Operation: s.target.Activation, Plan: s.target.Plan,
		PreparedSetHash: setHash}, true, nil
}

func (s *finalizationStoreStub) CommitPoolActivation(_ context.Context,
	input CommitPoolActivationInput) (*PermanentReplacementTarget, error) {
	if input.Status != "ACTIVATED" || len(input.Seats) != 1 || !input.CredentialFingerprintGateEnforced {
		return nil, ErrInvalidData
	}
	s.target.Activation.Status = "SUCCEEDED"
	s.target.SeatTargets[0].Progress.Status = "ACTIVATED"
	s.target.CaseStatus = "READY_TO_COMMIT"
	return s.target, nil
}

func (s *finalizationStoreStub) CommitPermanentReplacement(_ context.Context,
	input CommitPermanentReplacementInput) (*StoredOperation, bool, error) {
	if s.structural {
		return s.target.Operation, false, nil
	}
	s.claimIntents = append([]ReplacementClaimIntent(nil), input.ClaimIntents...)
	s.structural = true
	s.target.Plan.Status = planStatusFinalized
	s.target.CaseStatus = "PROVIDER_COMMIT_PENDING"
	s.target.SeatTargets[0].Progress.Status = "COMMITTED"
	return s.target.Operation, true, nil
}

func (s *finalizationStoreStub) BeginProviderRelease(_ context.Context,
	input BeginProviderReleaseInput) (*ProviderReleaseTarget, bool, error) {
	s.beginOrder = append(s.beginOrder, "provider-release")
	lease := s.now.Add(input.ChildLeaseDuration)
	s.target.ProviderRelease = &StoredOperation{Key: OperationKey{ClientID: input.FinalizationKey.ClientID,
		OperationID: input.DerivedOperationID}, Status: "RUNNING", RequestHash: input.RequestHash,
		FencingToken: 1, LeaseOwner: input.ChildLeaseOwner, LeaseExpiresAt: &lease}
	s.childFences[input.DerivedOperationID] = s.target.ProviderRelease.FencingToken
	bindings, _ := releaseBindings(s.target.SeatTargets)
	setHash, _ := PermanentPreparedSeatSetHash(bindings)
	return &ProviderReleaseTarget{Operation: s.target.ProviderRelease, Plan: s.target.Plan,
		PreparedSetHash: setHash}, true, nil
}

func (s *finalizationStoreStub) CommitProviderRelease(_ context.Context,
	input CommitProviderReleaseInput) (*StoredOperation, bool, error) {
	if input.Status != "RELEASED" || input.DerivedOperationID != s.target.ProviderRelease.Key.OperationID ||
		!input.AllCredentialsEnabled || !input.AllSubscriptionsEnabled || !input.OldCredentialSetInvalidated ||
		!input.CredentialFingerprintGateEnforced || input.AuthorizationCacheInvalidated ||
		!input.AuthorizationCacheDurableOutbox || input.AuthCacheMinimumEvents < len(s.target.SeatTargets) {
		return nil, false, ErrInvalidData
	}
	s.target.ProviderRelease.Status = "SUCCEEDED"
	s.target.CaseStatus = "READY_TO_ISSUE"
	return s.target.Operation, true, nil
}

func (s *finalizationStoreStub) CommitReplacementClaims(_ context.Context,
	input CommitReplacementClaimsInput) (*StoredOperation, bool, error) {
	if s.issued {
		return s.target.Operation, false, nil
	}
	s.commitClaims = append([]ReplacementClaimActivation(nil), input.Claims...)
	s.issued = true
	s.target.Operation.Status = "SUCCEEDED"
	s.target.CaseStatus = "FINALIZED"
	return s.target.Operation, true, nil
}

func mustSeatPrepareRequestForTest(plan *StoredEpochPlan,
	progress *StoredSeatRotationProgress) PermanentSeatRotationPrepareRequest {
	request, err := seatPrepareRequest(plan, progress)
	if err != nil {
		panic(err)
	}
	return request
}

type managerSeatActivationVerifier struct{}

func (*managerSeatActivationVerifier) Ready(context.Context) error { return nil }
func (*managerSeatActivationVerifier) VerifyPoolActivation(context.Context, PermanentPoolActivationVerifyRequest) error {
	return nil
}
func (*managerSeatActivationVerifier) VerifyPoolCommit(context.Context, PermanentPoolCommitVerifyRequest) error {
	return nil
}

type managerRecoveryCipher struct {
	onSeal       func()
	deadlineSeen bool
}

func (*managerRecoveryCipher) Ready(context.Context) error { return nil }
func (c *managerRecoveryCipher) Seal(ctx context.Context, plaintext, aad []byte) (credentials.Envelope, error) {
	_, c.deadlineSeen = ctx.Deadline()
	if c.onSeal != nil {
		c.onSeal()
	}
	return credentials.Envelope{Algorithm: "TEST", KeyRef: "kms/recovery-claims",
		Ciphertext: append([]byte(nil), plaintext...), Nonce: []byte("012345678901"),
		AADHash: sha256.Sum256(aad), WrappedDEK: []byte("wrapped-dek")}, nil
}
func (*managerRecoveryCipher) Open(_ context.Context, envelope credentials.Envelope, _ []byte) ([]byte, error) {
	return append([]byte(nil), envelope.Ciphertext...), nil
}

func (*managerArtifactGateway) Ready(context.Context) error { return nil }
func (g *managerArtifactGateway) PublishArtifacts(_ context.Context, request MemberArtifactPublishRequest) (MemberArtifactPublishReceipt, error) {
	clone := request
	clone.EncryptedShare = append([]byte(nil), request.EncryptedShare...)
	clone.ProviderCommitment = append([]byte(nil), request.ProviderCommitment...)
	clone.ProviderProof = append([]byte(nil), request.ProviderProof...)
	clone.VSSCommitment = append([]byte(nil), request.VSSCommitment...)
	clone.VSSProof = append([]byte(nil), request.VSSProof...)
	clone.ManifestCanonical = append([]byte(nil), request.ManifestCanonical...)
	clone.PlatformSignature = append([]byte(nil), request.PlatformSignature...)
	clone.RootAttestation = append([]byte(nil), request.RootAttestation...)
	g.published = append(g.published, clone)
	proof := []byte("artifact-receipt-proof-" + request.MemberID)
	return MemberArtifactPublishReceipt{CeremonyType: request.CeremonyType, OperationID: request.OperationID,
		PoolID: request.PoolID, Epoch: request.Epoch, DeliveryID: request.DeliveryID, MemberID: request.MemberID,
		ManifestHash: request.ManifestHash, ReceiptID: "receipt-" + request.MemberID,
		ReceiptHash: MemberArtifactDigest(request), ProviderProof: proof, ProviderProofDigest: sha256.Sum256(proof),
		ProviderProofAlgorithm: "Ed25519", ProviderProofKeyID: "artifact-provider-key",
		ProviderProofProtocolVersion: "trusted-pool/member-artifact-receipt/v1",
		PublishedAt:                  time.Now().UTC()}, nil
}

type leaseStoreStub struct {
	Store
	acquire func(AcquireEpochPlanLeaseInput) (*StoredOperation, error)
}

func (s *leaseStoreStub) AcquireEpochPlanLease(_ context.Context, input AcquireEpochPlanLeaseInput) (*StoredOperation, error) {
	return s.acquire(input)
}

func TestManagerRequiresExplicitRootProviderTrustBoundary(t *testing.T) {
	store := &leaseStoreStub{}
	_, err := NewManager(store, Providers{}, ManagerConfig{ClientID: "recovery-client", LeaseOwner: "worker-1",
		LeaseDuration: time.Minute})
	if !errors.Is(err, ErrInvalidData) {
		t.Fatalf("NewManager() error = %v", err)
	}
	manager, err := NewManager(store, Providers{}, ManagerConfig{ClientID: "recovery-client", LeaseOwner: "worker-1",
		LeaseDuration: time.Minute, ExpectedRootProviderID: "root-provider", RootTrustProfile: "prod-root-v1"})
	if err != nil {
		t.Fatal(err)
	}
	if err := manager.Ready(context.Background()); !errors.Is(err, ErrProviderUnavailable) {
		t.Fatalf("Ready() error = %v", err)
	}
}

func TestManagerRequiresLeaseLongEnoughForBoundedExternalCalls(t *testing.T) {
	store := &leaseStoreStub{}
	base := ManagerConfig{ClientID: "recovery-client", LeaseOwner: "worker-1",
		ExpectedRootProviderID: "root-provider", RootTrustProfile: "prod-root-v1"}
	base.LeaseDuration = minimumWorkflowLeaseDuration - time.Nanosecond
	if _, err := NewManager(store, Providers{}, base); !errors.Is(err, ErrInvalidData) {
		t.Fatalf("short workflow lease was accepted: %v", err)
	}
	invalid := &Manager{store: store, config: base}
	if err := invalid.Ready(context.Background()); !errors.Is(err, ErrProviderUnavailable) {
		t.Fatalf("Ready accepted short workflow lease: %v", err)
	}
	base.LeaseDuration = minimumWorkflowLeaseDuration
	if _, err := NewManager(store, Providers{}, base); err != nil {
		t.Fatalf("30 second workflow lease was rejected: %v", err)
	}
}

func TestRenewLeaseUsesCurrentFenceAndRejectsTakeover(t *testing.T) {
	now := time.Now().UTC()
	calls := 0
	store := &leaseStoreStub{acquire: func(input AcquireEpochPlanLeaseInput) (*StoredOperation, error) {
		calls++
		if input.ExpectedFencingToken != 7 || input.LeaseOwner != "worker-1" {
			t.Fatalf("unexpected acquire: %+v", input)
		}
		if calls == 2 {
			return nil, ErrLeaseHeld
		}
		expires := now.Add(time.Minute)
		return &StoredOperation{Key: input.Key, LeaseOwner: input.LeaseOwner, FencingToken: 7,
			RequestHash: sha256.Sum256([]byte("intent")), LeaseExpiresAt: &expires}, nil
	}}
	manager, err := NewManager(store, Providers{}, ManagerConfig{ClientID: "recovery-client", LeaseOwner: "worker-1",
		LeaseDuration: time.Minute, ExpectedRootProviderID: "root-provider", RootTrustProfile: "prod-root-v1",
		Now: func() time.Time { return now }})
	if err != nil {
		t.Fatal(err)
	}
	expires := now.Add(30 * time.Second)
	target := &EpochPlanTarget{Operation: &StoredOperation{Key: OperationKey{"recovery-client", "op-1"},
		LeaseOwner: "worker-1", FencingToken: 7, RequestHash: sha256.Sum256([]byte("intent")), LeaseExpiresAt: &expires},
		Plan: &StoredEpochPlan{ExternalID: "plan-1", Status: planStatusPlanned}}
	if err := manager.renewLease(context.Background(), target); err != nil {
		t.Fatalf("renewLease() = %v", err)
	}
	if err := manager.renewLease(context.Background(), target); !errors.Is(err, ErrLeaseHeld) {
		t.Fatalf("renew after takeover = %v", err)
	}
}

func TestFirstPrepareResponseLossRecoversFenceThroughGet(t *testing.T) {
	now := time.Date(2026, 8, 20, 2, 0, 0, 0, time.UTC)
	log := []string{}
	store := &prepareStoreStub{now: now, log: &log}
	manager := newPreparedTestManager(t, store, "worker-first", now)
	request := validManagerPlanRequest(t)
	if _, err := manager.Prepare(context.Background(), request); err != nil {
		t.Fatalf("initial Prepare() = %v", err)
	}
	if _, err := manager.Prepare(context.Background(), request); !errors.Is(err, ErrStaleFence) {
		t.Fatalf("existing plan accepted zero fence: %v", err)
	}
	// 模拟客户端未收到首次响应，只能按 plan ID 恢复当前 CAS fence。
	progress, err := manager.Get(context.Background(), request.PlanExternalID)
	if err != nil || progress.FencingToken != 1 || !progress.LeaseExpiresAt.After(now) {
		t.Fatalf("Get() after lost response = %+v, %v", progress, err)
	}
	request.ExpectedFencingToken = progress.FencingToken
	if retried, err := manager.Prepare(context.Background(), request); err != nil || retried.FencingToken != 1 {
		t.Fatalf("Prepare() after GET = %+v, %v", retried, err)
	}
}

func TestExpiredTakeoverResponseLossAndRestartGetRetry(t *testing.T) {
	now := time.Date(2026, 8, 20, 2, 30, 0, 0, time.UTC)
	log := []string{}
	store := &prepareStoreStub{now: now, log: &log}
	request := validManagerPlanRequest(t)
	first := newPreparedTestManager(t, store, "worker-before-restart", now)
	if _, err := first.Prepare(context.Background(), request); err != nil {
		t.Fatalf("initial Prepare() = %v", err)
	}
	expired := now.Add(-time.Second)
	store.operation.LeaseExpiresAt = &expired

	restarted := newPreparedTestManager(t, store, "worker-after-restart", now)
	request.ExpectedFencingToken = 1
	if progress, err := restarted.Prepare(context.Background(), request); err != nil || progress.FencingToken != 2 {
		t.Fatalf("takeover Prepare() = %+v, %v", progress, err)
	}
	// 模拟 takeover 响应再次丢失；重启实例先 GET 新 fence，再精确重放。
	restartedAgain := newPreparedTestManager(t, store, "worker-after-restart-2", now)
	progress, err := restartedAgain.Get(context.Background(), request.PlanExternalID)
	if err != nil || progress.FencingToken != 2 {
		t.Fatalf("Get() after lost takeover = %+v, %v", progress, err)
	}
	request.ExpectedFencingToken = progress.FencingToken
	if _, err := restartedAgain.Prepare(context.Background(), request); !errors.Is(err, ErrLeaseHeld) {
		t.Fatalf("active lease was stolen after restart: %v", err)
	}
	store.operation.LeaseExpiresAt = &expired
	if retried, err := restartedAgain.Prepare(context.Background(), request); err != nil || retried.FencingToken != 3 {
		t.Fatalf("expired GET -> retry = %+v, %v", retried, err)
	}
}

func TestEpochCredentialBatchProviderUsesPerBatchExactIdempotency(t *testing.T) {
	base := EpochCredentialBatchRequest{CeremonyType: CeremonyRotate, OperationID: "ceremony-op-1",
		PoolID: "pool-1", Epoch: 2, BatchID: "batch-login", ResourceAccountID: "account-1",
		AccountRef: "provider-account-1", BatchType: "LOGIN", BatchVersion: 2,
		RootPublicHandle: "root-handle", RootKeyVersion: "root-v1",
		RootPublicFingerprint: sha256.Sum256([]byte("root-public")), RootWrapDomain: "root-wrap",
		RootWrapAlgorithm: "HPKE", Payload: []byte(`{"username":"alice"}`)}
	base.RequestHash = EpochCredentialBatchRequestHash(base)
	other := base
	other.BatchID, other.BatchType = "batch-mfa", "MFA"
	other.RequestHash = EpochCredentialBatchRequestHash(other)
	if base.RequestHash == other.RequestHash {
		t.Fatal("different batches collided in provider idempotency scope")
	}
	provider := &replayingBatchProvider{}
	if _, err := provider.SealCredentialBatch(context.Background(), base); err == nil {
		t.Fatal("first provider call did not simulate unknown result")
	}
	replayed, err := provider.SealCredentialBatch(context.Background(), base)
	if err != nil || replayed.OperationID != base.OperationID || replayed.Batch.ExternalID != base.BatchID ||
		replayed.RequestHash != base.RequestHash || string(replayed.ProviderProof) != "durable-provider-result" {
		t.Fatalf("same batch was not exactly replayed: %+v, %v", replayed, err)
	}
	if _, err := provider.SealCredentialBatch(context.Background(), other); err == nil {
		t.Fatal("different batch incorrectly reused prior result")
	}
}

func newPreparedTestManager(t *testing.T, store Store, worker string, now time.Time) *Manager {
	t.Helper()
	providers := Providers{Root: &managerRootProvider{log: &[]string{}}, Canonicalizer: &canonicalizerStub{},
		PlatformSigner: &managerPlatformSigner{now: now}, Attestation: &managerAttestationProvider{now: now},
		MemberSignatures: &managerMemberVerifier{}, CredentialBatches: &managerBatchProvider{},
		MemberArtifacts: &managerArtifactGateway{}, SeatRotations: &managerSeatRotationProvider{},
		SeatActivations:  &managerSeatActivationVerifier{},
		CredentialCipher: &managerRecoveryCipher{}}
	manager, err := NewManager(store, providers, ManagerConfig{ClientID: "recovery-client", LeaseOwner: worker,
		LeaseDuration: time.Minute, ExpectedRootProviderID: "root-provider", RootTrustProfile: "prod-root-v1",
		PortableEvidence: true, RecoveryCryptoSuiteID: "hpke-x25519-hkdf-sha256-aes256gcm-v1",
		Now: func() time.Time { return now }})
	if err != nil {
		t.Fatal(err)
	}
	return manager
}

func TestFinalizeUsesPoolThreePhaseRotationAndOnlyFirstIssuanceReturnsClaims(t *testing.T) {
	now := time.Date(2026, 8, 20, 8, 0, 0, 0, time.UTC)
	store := newFinalizationStoreStub(now)
	rotations := &finalizationRotationProvider{now: now}
	providers := Providers{Root: &managerRootProvider{log: &[]string{}}, Canonicalizer: &canonicalizerStub{},
		PlatformSigner: &managerPlatformSigner{now: now}, Attestation: &managerAttestationProvider{now: now},
		MemberSignatures: &managerMemberVerifier{}, CredentialBatches: &managerBatchProvider{},
		MemberArtifacts: &managerArtifactGateway{}, SeatRotations: rotations,
		SeatActivations: &managerSeatActivationVerifier{}, CredentialCipher: &managerRecoveryCipher{}}
	manager, err := NewManager(store, providers, ManagerConfig{ClientID: "recovery-client",
		LeaseOwner: "worker-unique-1", LeaseDuration: time.Minute, ExpectedRootProviderID: "root-provider",
		RootTrustProfile: "prod-root-v1", Now: func() time.Time { return now },
		ClaimToken: func() (string, error) { return "one-time-claim-token", nil }})
	if err != nil {
		t.Fatal(err)
	}
	request := FinalizeRequest{OperationID: "finalize-op-1", PlanExternalID: "plan-1",
		CaseExternalID: "case-1", Replacements: []SeatReplacementIntent{{SeatExternalID: "seat-1",
			TargetMemberExternalID: "member-new"}}, EvidenceExternalIDs: []string{"evidence-1"}}
	progress, err := manager.Finalize(context.Background(), request)
	if err != nil {
		t.Fatalf("Finalize() = %v", err)
	}
	if progress.Status != planStatusFinalized || len(progress.Claims) != 1 ||
		progress.Claims[0].ClaimToken != "one-time-claim-token" ||
		progress.Claims[0].OperationID == "" || progress.Claims[0].ClaimOperationID == "" {
		t.Fatalf("first finalization progress = %+v", progress)
	}
	if rotations.prepareCalls != 1 || rotations.activateCalls != 1 || rotations.commitCalls != 1 ||
		!reflect.DeepEqual(store.beginOrder, []string{"seat", "pool-prepare", "pool-activate", "provider-release"}) {
		t.Fatalf("unexpected three-phase order=%v prepare=%d activate=%d commit=%d", store.beginOrder,
			rotations.prepareCalls, rotations.activateCalls, rotations.commitCalls)
	}
	if len(store.claimIntents) != 1 || store.claimIntents[0].ClaimOperationID == "" {
		t.Fatalf("structural claim intents = %+v", store.claimIntents)
	}
	if len(store.commitClaims) != 1 || store.commitClaims[0].TokenHash != sha256.Sum256([]byte("one-time-claim-token")) {
		t.Fatalf("stored claim activation = %+v", store.commitClaims)
	}
	replay, err := manager.Finalize(context.Background(), request)
	if err != nil {
		t.Fatalf("Finalize(replay) = %v", err)
	}
	if replay.Status != planStatusFinalized || len(replay.Claims) != 0 {
		t.Fatalf("replay leaked raw claim token: %+v", replay)
	}
	if rotations.prepareCalls != 1 || rotations.activateCalls != 1 || rotations.commitCalls != 1 {
		t.Fatal("successful replay repeated upstream network work")
	}
}

func TestFinalizationHeartbeatsAcrossOriginalLeaseDuringProviderAndKMSCalls(t *testing.T) {
	now := time.Date(2026, 8, 20, 8, 10, 0, 0, time.UTC)
	store := newFinalizationStoreStub(now)
	originalExpiry := now.Add(5 * time.Millisecond)
	store.target.Operation.LeaseExpiresAt = &originalExpiry
	rotations := &finalizationRotationProvider{now: now, onPrepare: func() {
		store.now = store.now.Add(20 * time.Millisecond)
	}}
	cipher := &managerRecoveryCipher{onSeal: func() { store.now = store.now.Add(20 * time.Millisecond) }}
	leaseDuration := 100 * time.Millisecond
	manager := &Manager{store: store, providers: Providers{SeatRotations: rotations,
		SeatActivations: &managerSeatActivationVerifier{}, CredentialCipher: cipher},
		config: ManagerConfig{ClientID: "recovery-client", LeaseOwner: "worker-unique-1",
			LeaseDuration: leaseDuration, ReplacementClaimTTL: time.Minute,
			FinalizationBackoff: time.Minute, Now: func() time.Time { return store.now },
			ClaimToken: func() (string, error) { return "claim-token", nil }}}
	request := FinalizeRequest{OperationID: "finalize-op-1", PlanExternalID: "plan-1",
		CaseExternalID: "case-1", Replacements: []SeatReplacementIntent{{SeatExternalID: "seat-1",
			TargetMemberExternalID: "member-new"}}, EvidenceExternalIDs: []string{"evidence-1"}}
	progress, err := manager.Finalize(context.Background(), request)
	if err != nil || progress.Status != planStatusFinalized {
		t.Fatalf("Finalize() across original lease = %+v, %v", progress, err)
	}
	if !store.now.After(originalExpiry) || store.renewParent == 0 || store.renewChild == 0 ||
		!cipher.deadlineSeen || rotations.prepareBudget <= 0 || rotations.prepareBudget > leaseDuration/2 {
		t.Fatalf("heartbeat/call budget missing: now=%v expiry=%v parent=%d child=%d cipherDeadline=%v budget=%v",
			store.now, originalExpiry, store.renewParent, store.renewChild, cipher.deadlineSeen,
			rotations.prepareBudget)
	}
}

func TestFinalizationProviderTimeoutPersistsReconcileBeforeLeaseExpiry(t *testing.T) {
	now := time.Date(2026, 8, 20, 8, 20, 0, 0, time.UTC)
	store := newFinalizationStoreStub(now)
	leaseDuration := 200 * time.Millisecond
	rotations := &finalizationRotationProvider{now: now, waitPrepare: true, onPrepare: func() {
		store.now = store.now.Add(110 * time.Millisecond)
	}}
	manager := &Manager{store: store, providers: Providers{SeatRotations: rotations,
		SeatActivations: &managerSeatActivationVerifier{}, CredentialCipher: &managerRecoveryCipher{}},
		config: ManagerConfig{ClientID: "recovery-client", LeaseOwner: "worker-unique-1",
			LeaseDuration: leaseDuration, ReplacementClaimTTL: time.Minute,
			FinalizationBackoff: time.Minute, Now: func() time.Time { return store.now },
			ClaimToken: func() (string, error) { return "claim-token", nil }}}
	request := FinalizeRequest{OperationID: "finalize-op-1", PlanExternalID: "plan-1",
		CaseExternalID: "case-1", Replacements: []SeatReplacementIntent{{SeatExternalID: "seat-1",
			TargetMemberExternalID: "member-new"}}, EvidenceExternalIDs: []string{"evidence-1"}}
	started := time.Now()
	_, err := manager.Finalize(context.Background(), request)
	if !errors.Is(err, ErrProviderUnavailable) || !store.reconciled {
		t.Fatalf("timed out provider result was not persisted for reconcile: reconciled=%v err=%v",
			store.reconciled, err)
	}
	if rotations.prepareBudget <= 0 || rotations.prepareBudget > leaseDuration/2 ||
		time.Since(started) >= leaseDuration || store.renewParent < 3 {
		t.Fatalf("provider call was not bounded inside lease: budget=%v elapsed=%v renewals=%d",
			rotations.prepareBudget, time.Since(started), store.renewParent)
	}
}

func TestFinalizationDropsProviderResultAfterChildFenceTakeover(t *testing.T) {
	now := time.Date(2026, 8, 20, 8, 25, 0, 0, time.UTC)
	store := newFinalizationStoreStub(now)
	rotations := &finalizationRotationProvider{now: now, onPrepare: func() {
		for operationID := range store.childFences {
			store.childFences[operationID]++
		}
	}}
	providers := Providers{Root: &managerRootProvider{log: &[]string{}}, Canonicalizer: &canonicalizerStub{},
		PlatformSigner: &managerPlatformSigner{now: now}, Attestation: &managerAttestationProvider{now: now},
		MemberSignatures: &managerMemberVerifier{}, CredentialBatches: &managerBatchProvider{},
		MemberArtifacts: &managerArtifactGateway{}, SeatRotations: rotations,
		SeatActivations: &managerSeatActivationVerifier{}, CredentialCipher: &managerRecoveryCipher{}}
	manager, err := NewManager(store, providers, ManagerConfig{ClientID: "recovery-client",
		LeaseOwner: "worker-unique-1", LeaseDuration: time.Minute, ExpectedRootProviderID: "root-provider",
		RootTrustProfile: "prod-root-v1", Now: func() time.Time { return store.now }})
	if err != nil {
		t.Fatal(err)
	}
	request := FinalizeRequest{OperationID: "finalize-op-1", PlanExternalID: "plan-1",
		CaseExternalID: "case-1", Replacements: []SeatReplacementIntent{{SeatExternalID: "seat-1",
			TargetMemberExternalID: "member-new"}}, EvidenceExternalIDs: []string{"evidence-1"}}
	_, err = manager.Finalize(context.Background(), request)
	if !errors.Is(err, ErrStaleFence) || store.reconciled ||
		store.target.SeatTargets[0].Progress.Status != "PREPARE_PENDING" {
		t.Fatalf("old child fence wrote provider result: status=%s reconciled=%v err=%v",
			store.target.SeatTargets[0].Progress.Status, store.reconciled, err)
	}
}

func TestFinalizationWorkerStopsBeforeStructuralCommitAndTokenIssuance(t *testing.T) {
	now := time.Date(2026, 8, 20, 8, 30, 0, 0, time.UTC)
	store := newFinalizationStoreStub(now)
	rotations := &finalizationRotationProvider{now: now}
	tokenCalls := 0
	providers := Providers{Root: &managerRootProvider{log: &[]string{}}, Canonicalizer: &canonicalizerStub{},
		PlatformSigner: &managerPlatformSigner{now: now}, Attestation: &managerAttestationProvider{now: now},
		MemberSignatures: &managerMemberVerifier{}, CredentialBatches: &managerBatchProvider{},
		MemberArtifacts: &managerArtifactGateway{}, SeatRotations: rotations,
		SeatActivations: &managerSeatActivationVerifier{}, CredentialCipher: &managerRecoveryCipher{}}
	manager, err := NewManager(store, providers, ManagerConfig{ClientID: "recovery-client",
		LeaseOwner: "worker-unique-1", LeaseDuration: time.Minute, ExpectedRootProviderID: "root-provider",
		RootTrustProfile: "prod-root-v1", Now: func() time.Time { return now },
		ClaimToken: func() (string, error) { tokenCalls++; return "must-not-be-generated", nil }})
	if err != nil {
		t.Fatal(err)
	}
	worked, err := manager.RecoverNextFinalization(context.Background())
	if err != nil || !worked {
		t.Fatalf("RecoverNextFinalization() = %v, %v", worked, err)
	}
	if store.target.CaseStatus != "READY_TO_COMMIT" || store.structural || tokenCalls != 0 ||
		rotations.commitCalls != 0 {
		t.Fatalf("worker crossed issuance boundary: case=%s structural=%v tokenCalls=%d commitCalls=%d",
			store.target.CaseStatus, store.structural, tokenCalls, rotations.commitCalls)
	}
}

func TestFinalizationWorkerRecoversProviderReleaseButStopsBeforeIssuance(t *testing.T) {
	now := time.Date(2026, 8, 20, 8, 45, 0, 0, time.UTC)
	store := newFinalizationStoreStub(now)
	rotations := &finalizationRotationProvider{now: now}
	tokenCalls := 0
	providers := Providers{Root: &managerRootProvider{log: &[]string{}}, Canonicalizer: &canonicalizerStub{},
		PlatformSigner: &managerPlatformSigner{now: now}, Attestation: &managerAttestationProvider{now: now},
		MemberSignatures: &managerMemberVerifier{}, CredentialBatches: &managerBatchProvider{},
		MemberArtifacts: &managerArtifactGateway{}, SeatRotations: rotations,
		SeatActivations: &managerSeatActivationVerifier{}, CredentialCipher: &managerRecoveryCipher{}}
	manager, err := NewManager(store, providers, ManagerConfig{ClientID: "recovery-client",
		LeaseOwner: "worker-unique-1", LeaseDuration: time.Minute, ExpectedRootProviderID: "root-provider",
		RootTrustProfile: "prod-root-v1", Now: func() time.Time { return now },
		ClaimToken: func() (string, error) { tokenCalls++; return "must-not-be-generated", nil }})
	if err != nil {
		t.Fatal(err)
	}
	ready, err := manager.advanceFinalizationNetwork(context.Background(), store.target, false)
	if err != nil || ready.CaseStatus != "READY_TO_COMMIT" {
		t.Fatalf("prepare held activation = %+v, %v", ready, err)
	}
	if _, err = manager.commitStructuralFinalization(context.Background(), ready); err != nil {
		t.Fatal(err)
	}
	worked, err := manager.RecoverNextFinalization(context.Background())
	if err != nil || !worked {
		t.Fatalf("RecoverNextFinalization() = %v, %v", worked, err)
	}
	if store.target.CaseStatus != "READY_TO_ISSUE" || store.target.Operation.Status != "RUNNING" ||
		rotations.commitCalls != 1 || tokenCalls != 0 || len(store.commitClaims) != 0 {
		t.Fatalf("worker crossed issuance boundary: case=%s parent=%s commitCalls=%d tokenCalls=%d claims=%d",
			store.target.CaseStatus, store.target.Operation.Status, rotations.commitCalls, tokenCalls,
			len(store.commitClaims))
	}
}

func TestCommittedPackageReplayMustExactlyMatchRootAndShares(t *testing.T) {
	request := validRecoveryRequest(t)
	pkg := validRecoveryPackage(request)
	planRequest := PlanRequest{PlanExternalID: "plan-1", RootArtifactExternalID: "root-1", PoolID: request.PoolID}
	root := &StoredRootArtifact{ExternalID: "root-1", Provider: pkg.ProviderID,
		ProviderKeyRef: pkg.RootPublicHandle, RootHandle: pkg.RootPublicHandle, RootKeyVersion: pkg.RootKeyVersion,
		EpochRecoveryAlgorithm: pkg.RootPublicAlgorithm, EpochRecoveryKeyID: pkg.RootPublicHandle,
		EpochRecoveryKeyFingerprint: pkg.RootPublicFingerprint, WrapDomain: pkg.RootWrapDomain,
		WrapAlgorithm: pkg.RootWrapAlgorithm, VSSAlgorithm: pkg.VSSAlgorithm,
		VSSCommitmentHash: sha256.Sum256(pkg.VSSCommitment), VSSProofHash: sha256.Sum256(pkg.VSSProof),
		PrivateKeyCommitmentHash: sha256.Sum256(pkg.RootPrivateCommitment), RootCommitmentHash: RecoveryRootCommitmentHash(pkg),
		RecoveryPackageHash: pkg.PackageHash, RequestIntentHash: pkg.RequestIntentHash,
		ProviderAttestationRef: pkg.ProviderAttestationRef, AttestationDigest: pkg.ProviderAttestationDigest,
		AttestationSignature: append([]byte(nil), pkg.ProviderAttestation...), AttestationKeyID: pkg.ProviderAttestationKeyID,
		PortableAttestationAlgorithm:       pkg.PortableAttestationAlgorithm,
		PortableAttestationIssuer:          pkg.PortableAttestationIssuer,
		PortableAttestationKeyID:           pkg.PortableAttestationKeyID,
		PortableAttestationProtocolVersion: pkg.PortableAttestationProtocolVersion,
		PortableAttestationSignature:       append([]byte(nil), pkg.PortableAttestationSignature...)}
	snapshot := &EpochSecuritySnapshot{Plan: &StoredEpochPlan{ExternalID: "plan-1", PoolExternalID: request.PoolID}, Root: root}
	for _, share := range pkg.EncryptedShares {
		snapshot.Deliveries = append(snapshot.Deliveries, StoredShareDelivery{
			ExternalID: deterministicExternalID("share", "plan-1", share.MemberID), MemberExternalID: share.MemberID,
			ShareIndex: share.ShareIndex, EncryptionAlgorithm: share.EncryptionAlgorithm,
			RecipientKeyID: share.EncryptionKeyID, RecipientKeyFingerprint: share.EncryptionKeyFingerprint,
			CiphertextHash: share.CiphertextHash, ProviderShareCommitment: append([]byte(nil), share.ProviderCommitment...),
			ProviderProofDigest: sha256.Sum256(share.ProviderProof), ProviderProofSignature: append([]byte(nil), share.ProviderProof...),
			PortableProofAlgorithm: share.PortableProofAlgorithm, PortableProofKeyID: share.PortableProofKeyID,
			PortableProofProtocolVersion: share.PortableProofProtocolVersion,
			PortableProofSignature:       append([]byte(nil), share.PortableProofSignature...),
			RootCommitmentHash:           root.RootCommitmentHash, VSSCommitmentHash: root.VSSCommitmentHash,
			RecoveryPackageHash: pkg.PackageHash, RequestIntentHash: pkg.RequestIntentHash})
	}
	if err := validateCommittedRecoveryPackage(snapshot, planRequest, pkg, true); err != nil {
		t.Fatalf("valid replay = %v", err)
	}
	tampered := pkg
	tampered.RootPublicHandle = "different-root"
	if err := validateCommittedRecoveryPackage(snapshot, planRequest, tampered, true); !errors.Is(err, ErrBindingMismatch) {
		t.Fatalf("tampered replay = %v", err)
	}
	snapshot.Deliveries[0].CiphertextHash = sha256.Sum256([]byte("different-share"))
	if err := validateCommittedRecoveryPackage(snapshot, planRequest, pkg, true); !errors.Is(err, ErrBindingMismatch) {
		t.Fatalf("split root/share replay = %v", err)
	}
}

func TestProviderErrorsAreRedactedAndUnknownProviderIsRejected(t *testing.T) {
	request := validRecoveryRequest(t)
	pkg := validRecoveryPackage(request)
	verifier := &attestationVerifierStub{packageErr: errors.New("payload=credential-canary")}
	err := VerifyRecoveryPackage(context.Background(), verifier, request, pkg)
	if !errors.Is(err, ErrSignatureInvalid) || strings.Contains(err.Error(), "credential-canary") {
		t.Fatalf("unsafe provider error = %v", err)
	}
	verifier.packageErr = nil
	pkg.ProviderID = "unknown-provider"
	if err := VerifyRecoveryPackage(context.Background(), verifier, request, pkg); !errors.Is(err, ErrBindingMismatch) {
		t.Fatalf("unknown provider = %v", err)
	}
}

func TestControlBatchVersionMustIncrease(t *testing.T) {
	payload := validManifestPayload()
	payload.Accounts[0].Batches[0].ToBatchVersion = payload.Accounts[0].Batches[0].FromBatchVersion
	if err := ValidateManifestPayload(payload); !errors.Is(err, ErrInvalidData) {
		t.Fatalf("non-increasing batch version = %v", err)
	}
}

func TestStagedBatchMustMatchManifestCiphertextAndRecoveryWrapHashes(t *testing.T) {
	ciphertext := []byte("sealed-control-batch")
	ciphertextHash := sha256.Sum256(ciphertext)
	recoveryHash := sha256.Sum256([]byte("recovery-binding"))
	plan := ControlBatchPlan{ToCiphertextHash: hex.EncodeToString(ciphertextHash[:]),
		ToRecoveryWrapHash: hex.EncodeToString(recoveryHash[:])}
	batch := StagedCredentialBatch{Ciphertext: ciphertext, RecoveryBindingHash: recoveryHash}
	if err := validateStagedBatchPlanBinding(plan, batch); err != nil {
		t.Fatalf("valid staged batch binding = %v", err)
	}
	batch.RecoveryBindingHash = sha256.Sum256([]byte("different-wrap"))
	if err := validateStagedBatchPlanBinding(plan, batch); !errors.Is(err, ErrBindingMismatch) {
		t.Fatalf("recovery wrap drift = %v", err)
	}
}

func TestPrepareOrdersExternalWorkAndReachesManifestDraft(t *testing.T) {
	now := time.Date(2026, 8, 19, 1, 0, 0, 0, time.UTC)
	log := []string{}
	store := &prepareStoreStub{now: now, log: &log}
	root := &managerRootProvider{log: &log}
	artifacts := &managerArtifactGateway{}
	providers := Providers{Root: root, Canonicalizer: &canonicalizerStub{}, PlatformSigner: &managerPlatformSigner{now: now},
		Attestation: &managerAttestationProvider{now: now}, MemberSignatures: &managerMemberVerifier{},
		CredentialBatches: &managerBatchProvider{}, MemberArtifacts: artifacts,
		SeatRotations:    &managerSeatRotationProvider{},
		SeatActivations:  &managerSeatActivationVerifier{},
		CredentialCipher: &managerRecoveryCipher{}}
	manager, err := NewManager(store, providers, ManagerConfig{ClientID: "recovery-client", LeaseOwner: "worker-unique-1",
		LeaseDuration: time.Minute, ExpectedRootProviderID: "root-provider", RootTrustProfile: "prod-root-v1",
		Now: func() time.Time { return now }})
	if err != nil {
		t.Fatal(err)
	}
	progress, err := manager.Prepare(context.Background(), validManagerPlanRequest(t))
	if err != nil {
		t.Fatalf("Prepare() = %v, log=%v", err, log)
	}
	if progress.Plan.Status != planStatusManifestDraft || progress.FencingToken != 1 ||
		len(artifacts.published) != 2 || len(store.receipts) != 2 {
		t.Fatalf("progress=%+v published=%d receipts=%d", progress, len(artifacts.published), len(store.receipts))
	}
	positions := map[string]int{}
	for index, item := range log {
		if _, exists := positions[item]; !exists {
			positions[item] = index
		}
	}
	if !(positions["begin"] < positions["provider-root"] && positions["provider-root"] < positions["commit-root"] &&
		positions["commit-root"] < positions["commit-shares"] && positions["commit-shares"] < positions["commit-manifest"]) {
		t.Fatalf("unsafe stage order: %v", log)
	}
	rootCall := positions["provider-root"]
	if rootCall+1 >= len(log) || log[rootCall+1] != "heartbeat" || positions["commit-root"] <= rootCall+1 {
		t.Fatalf("missing heartbeat after long provider call: %v", log)
	}
	for _, published := range artifacts.published {
		if len(published.EncryptedShare) == 0 || len(published.ManifestCanonical) == 0 || published.MemberID == "" ||
			published.RecoveryPackageHash == ([sha256.Size]byte{}) || len(published.VSSCommitment) == 0 ||
			len(published.VSSProof) == 0 || len(published.PlatformSignature) == 0 ||
			len(published.RootAttestation) == 0 || published.RootAttestationDigest == ([sha256.Size]byte{}) {
			t.Fatalf("incomplete member artifact: %+v", published)
		}
	}
	for _, receipt := range store.receipts {
		if receipt.PlanExternalID != "plan-1" || receipt.ManifestExternalID != "manifest-1" ||
			receipt.ProviderProofAlgorithm != "Ed25519" ||
			receipt.ProviderProofProtocolVersion != "trusted-pool/member-artifact-receipt/v1" ||
			len(receipt.ProviderProof) == 0 || receipt.ArtifactDigest == ([sha256.Size]byte{}) {
			t.Fatalf("incomplete persisted member artifact receipt: %+v", receipt)
		}
	}
}

func TestExistingPlanUsesPersistedCeremonyAttestationWithoutExpiryRecheck(t *testing.T) {
	now := time.Date(2026, 9, 1, 0, 0, 0, 0, time.UTC)
	manager, err := NewManager(&leaseStoreStub{}, Providers{Attestation: &managerAttestationProvider{now: now},
		MemberSignatures: &managerMemberVerifier{}}, ManagerConfig{ClientID: "recovery-client", LeaseOwner: "worker-1",
		LeaseDuration: time.Minute, ExpectedRootProviderID: "root-provider", RootTrustProfile: "prod-root-v1", Now: func() time.Time { return now }})
	if err != nil {
		t.Fatal(err)
	}
	request := validManagerPlanRequest(t)
	stored := &StoredEpochPlan{ExternalID: request.PlanExternalID, CeremonyType: request.CeremonyType,
		CeremonyAttestationRef:    "ceremony-attestation-1",
		CeremonyAttestationDigest: sha256.Sum256([]byte("ceremony-attestation")),
		CeremonyAttestationIssuer: "provider", CeremonyAttestationKeyID: "provider-key", CeremonyAttestationVersion: 1}
	prepared, err := manager.prepareIntent(context.Background(), request, stored)
	if err != nil {
		t.Fatalf("persisted attestation rejected after original expiry: %v", err)
	}
	if prepared.attestation.CanonicalDigest != stored.CeremonyAttestationDigest ||
		prepared.attestation.Reference != stored.CeremonyAttestationRef {
		t.Fatalf("unexpected persisted attestation: %+v", prepared.attestation)
	}
	stored.CeremonyAttestationDigest = [sha256.Size]byte{}
	if _, err := manager.prepareIntent(context.Background(), request, stored); !errors.Is(err, ErrBindingMismatch) {
		t.Fatalf("corrupt persisted attestation = %v", err)
	}
}

func TestSecuritySnapshotRejectsHTTPMemberKeyReplacement(t *testing.T) {
	request := validManagerPlanRequest(t)
	canonical := []byte(`{"manifest":"trusted"}`)
	plan := &StoredEpochPlan{ExternalID: request.PlanExternalID, Status: planStatusManifestDraft,
		ExpectedMemberCount: len(request.Members)}
	snapshot := &EpochSecuritySnapshot{Plan: clonePlan(plan), Members: cloneEpochMembers(request.Members),
		Deliveries: make([]StoredShareDelivery, len(request.Members)), ManifestCanonical: canonical,
		ManifestHash: sha256.Sum256(canonical)}
	if err := validateSecuritySnapshot(snapshot, plan, planStatusManifestDraft, request.Members); err != nil {
		t.Fatalf("trusted snapshot rejected: %v", err)
	}
	tampered := cloneEpochMembers(request.Members)
	tampered[0].SigningPublicKey = []byte("attacker-key")
	tampered[0].SigningKeyFingerprint = sha256.Sum256(tampered[0].SigningPublicKey)
	if err := validateSecuritySnapshot(snapshot, plan, planStatusManifestDraft, tampered); !errors.Is(err, ErrBindingMismatch) {
		t.Fatalf("HTTP key replacement = %v", err)
	}
}

func validManagerPlanRequest(t *testing.T) PlanRequest {
	t.Helper()
	payload := validManifestPayload()
	request := PlanRequest{OperationID: payload.OperationID, PlanExternalID: "plan-1",
		RootRequestID: "root-request-1", RootArtifactExternalID: "root-1", ManifestExternalID: "manifest-1",
		CeremonyType: payload.CeremonyType, PoolID: payload.PoolID, FromEpoch: payload.FromEpoch, ToEpoch: payload.Epoch,
		GovernanceThreshold: payload.GovernanceThreshold, RecoveryThreshold: payload.RecoveryThreshold,
		PreviousManifestHash: payload.PreviousManifestHash, Seats: payload.Seats, Accounts: payload.Accounts,
		ProviderAttestationEnvelope: []byte("signed-control-attestation")}
	seatByMember := map[string]string{"member-a": "seat-a", "member-b": "seat-b"}
	for _, member := range payload.Members {
		signingFingerprint, _ := hex.DecodeString(member.SigningKeyFingerprint)
		recoveryFingerprint, _ := hex.DecodeString(member.RecoveryEncryptionKeyHash)
		var signingHash, recoveryHash [sha256.Size]byte
		copy(signingHash[:], signingFingerprint)
		copy(recoveryHash[:], recoveryFingerprint)
		request.Members = append(request.Members, EpochMember{SeatExternalID: seatByMember[member.MemberID],
			MemberExternalID: member.MemberID, Role: member.Role, ShareIndex: member.ShareIndex,
			SigningAlgorithm: member.SigningAlgorithm, SigningKeyID: member.SigningKeyID,
			SigningPublicKey: append([]byte(nil), member.SigningPublicKey...), SigningKeyFingerprint: signingHash,
			SigningProofAlgorithm: member.SigningAlgorithm, SigningProof: []byte("signing-proof-" + member.MemberID),
			RecoveryKeyAlgorithm: member.RecoveryEncryptionAlgorithm, RecoveryKeyID: member.RecoveryEncryptionKeyID,
			RecoveryEncryptionPublicKey: append([]byte(nil), member.RecoveryEncryptionPublicKey...),
			RecoveryKeyFingerprint:      recoveryHash, RecoveryKeyProofAlgorithm: member.RecoveryEncryptionAlgorithm,
			RecoveryKeyProof: []byte("recovery-proof-" + member.MemberID)})
	}
	for _, seat := range payload.Seats {
		freezeHash, _ := hex.DecodeString(seat.FreezeSnapshotHash)
		var hash [sha256.Size]byte
		copy(hash[:], freezeHash)
		request.SeatFreezes = append(request.SeatFreezes, EpochSeatFreeze{SeatExternalID: seat.SeatID,
			ExpectedAssignmentEpoch: seat.ExpectedAssignmentEpoch, FreezeOperationID: seat.FreezeOperationID,
			FreezeSnapshotHash: hash})
	}
	for _, replacement := range payload.Replacements {
		freezeHash, _ := hex.DecodeString(replacement.FreezeSnapshotHash)
		var hash [sha256.Size]byte
		copy(hash[:], freezeHash)
		request.Replacements = append(request.Replacements, EpochSeatReplacement{SeatExternalID: replacement.SeatID,
			FromMemberExternalID: replacement.FromMemberID, ToMemberExternalID: replacement.ToMemberID,
			ExpectedAssignmentEpoch: replacement.ExpectedAssignmentEpoch, FreezeOperationID: replacement.FreezeOperationID,
			FreezeSnapshotHash: hash})
	}
	return request
}
