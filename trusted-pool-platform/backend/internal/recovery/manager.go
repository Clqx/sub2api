package recovery

import (
	"bytes"
	"context"
	"crypto/rand"
	"crypto/sha256"
	"encoding/base64"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"sort"
	"strings"
	"time"

	"trusted-pool-platform/backend/internal/credentials"
)

const (
	planStatusPlanned         = "PLANNED"
	planStatusRootCommitted   = "ROOT_COMMITTED"
	planStatusSharesCommitted = "SHARES_COMMITTED"
	planStatusManifestDraft   = "MANIFEST_DRAFT"
	planStatusManifestSigned  = "MANIFEST_SIGNED"
	planStatusAcknowledged    = "ACKNOWLEDGED"
	planStatusBatchesStaged   = "BATCHES_STAGED"
	planStatusReady           = "READY"
	planStatusFinalized       = "FINALIZED"
)

const (
	defaultReplacementClaimTTL      = 10 * time.Minute
	maxReplacementClaimTTL          = 30 * time.Minute
	defaultFinalizationRetryBackoff = time.Minute
	minimumWorkflowLeaseDuration    = 30 * time.Second
)

type ManagerConfig struct {
	ClientID               string
	LeaseOwner             string
	LeaseDuration          time.Duration
	ExpectedRootProviderID string
	RootTrustProfile       string
	PortableEvidence       bool
	RecoveryCryptoSuiteID  string
	ReplacementClaimTTL    time.Duration
	FinalizationBackoff    time.Duration
	Now                    func() time.Time
	ClaimToken             func() (string, error)
}

// FinalizeRequest 是 Pool 级最终切换的完整幂等意图；EvidenceExternalIDs 必须规范排序且与 READY plan 一致。
type FinalizeRequest struct {
	OperationID          string                  `json:"operation_id"`
	PlanExternalID       string                  `json:"plan_id"`
	CaseExternalID       string                  `json:"case_id"`
	Replacements         []SeatReplacementIntent `json:"replacements,omitempty"`
	EvidenceExternalIDs  []string                `json:"evidence_ids"`
	ExpectedFencingToken int64                   `json:"expected_fencing_token"`
}

type ReplacementClaimToken struct {
	OperationID      string    `json:"operation_id"`
	ClaimOperationID string    `json:"claim_operation_id"`
	SeatID           string    `json:"seat_id"`
	TargetMemberID   string    `json:"target_member_id"`
	ClaimToken       string    `json:"claim_token"`
	ExpiresAt        time.Time `json:"expires_at"`
}

// FinalizationProgress 的 Claims 仅允许在首次成功提交的调用栈内出现；GET、worker 和幂等重放必须为空。
type FinalizationProgress struct {
	PlanID         string                  `json:"plan_id"`
	CeremonyType   CeremonyType            `json:"ceremony_type"`
	PoolID         string                  `json:"pool_id"`
	FromEpoch      uint64                  `json:"from_epoch"`
	ToEpoch        uint64                  `json:"to_epoch"`
	Status         string                  `json:"status"`
	FencingToken   int64                   `json:"fencing_token,omitempty"`
	LeaseExpiresAt *time.Time              `json:"lease_expires_at,omitempty"`
	Claims         []ReplacementClaimToken `json:"claims,omitempty"`
}

type ReplacementCredentialClaimRequest struct {
	PlanExternalID string `json:"plan_id"`
	OperationID    string `json:"operation_id"`
	SeatID         string `json:"seat_id"`
	TargetMemberID string `json:"target_member_id"`
	ClaimToken     string `json:"claim_token"`
}

type ReplacementCredentialDelivery struct {
	OperationID    string `json:"operation_id"`
	SeatID         string `json:"seat_id"`
	TargetMemberID string `json:"target_member_id"`
	Credential     string `json:"credential"`
}

// PlanRequest 是所有阶段重放的完整幂等意图。后续阶段必须原样携带，Manager 才能安全续租。
type PlanRequest struct {
	OperationID                 string                 `json:"operation_id"`
	PlanExternalID              string                 `json:"plan_id"`
	RootRequestID               string                 `json:"root_request_id"`
	RootArtifactExternalID      string                 `json:"root_artifact_id"`
	ManifestExternalID          string                 `json:"manifest_id"`
	CeremonyType                CeremonyType           `json:"ceremony_type"`
	PoolID                      string                 `json:"pool_id"`
	FromEpoch                   uint64                 `json:"from_epoch"`
	ToEpoch                     uint64                 `json:"to_epoch"`
	GovernanceThreshold         uint16                 `json:"governance_threshold"`
	RecoveryThreshold           uint16                 `json:"recovery_threshold"`
	PreviousManifestHash        string                 `json:"previous_manifest_hash"`
	Members                     []EpochMember          `json:"members"`
	SeatFreezes                 []EpochSeatFreeze      `json:"seat_freezes"`
	Replacements                []EpochSeatReplacement `json:"replacements"`
	Seats                       []SeatPlan             `json:"seats"`
	Accounts                    []ResourceAccountPlan  `json:"accounts"`
	ProviderAttestationEnvelope []byte                 `json:"provider_attestation_envelope"`
	// ExpectedFencingToken 由上一个阶段响应返回；首次创建必须为零。它不属于不可变 ceremony intent。
	ExpectedFencingToken int64 `json:"expected_fencing_token"`
}

// PlanProgress 只公开推进下一阶段所需的租约 CAS 值，不包含 Root、Share、DEK 或持久化密文。
type PlanProgress struct {
	Plan           *StoredEpochPlan `json:"plan"`
	FencingToken   int64            `json:"fencing_token"`
	LeaseExpiresAt time.Time        `json:"lease_expires_at"`
}

type SubmittedMemberSignature struct {
	MemberID  string `json:"member_id"`
	Algorithm string `json:"algorithm"`
	KeyID     string `json:"key_id"`
	Signature []byte `json:"signature"`
}

type SubmittedShareAcknowledgement struct {
	DeliveryID         string `json:"delivery_id"`
	MemberID           string `json:"member_id"`
	Algorithm          string `json:"algorithm"`
	KeyID              string `json:"key_id"`
	VerifiedCommitment bool   `json:"verified_commitment"`
	Signature          []byte `json:"signature"`
}

type StagedBatchPayload struct {
	BatchID           string                `json:"batch_id"`
	ResourceAccountID string                `json:"resource_account_id"`
	AccountRef        string                `json:"account_ref"`
	BatchType         credentials.BatchType `json:"batch_type"`
	BatchVersion      uint64                `json:"batch_version"`
	Payload           json.RawMessage       `json:"payload"`
}

type Manager struct {
	store     Store
	providers Providers
	config    ManagerConfig
}

func NewManager(store Store, providers Providers, config ManagerConfig) (*Manager, error) {
	config.ClientID = strings.TrimSpace(config.ClientID)
	config.LeaseOwner = strings.TrimSpace(config.LeaseOwner)
	config.ExpectedRootProviderID = strings.TrimSpace(config.ExpectedRootProviderID)
	config.RootTrustProfile = strings.TrimSpace(config.RootTrustProfile)
	config.RecoveryCryptoSuiteID = strings.TrimSpace(config.RecoveryCryptoSuiteID)
	if store == nil || !validSecurityID(config.ClientID) || !validSecurityID(config.LeaseOwner) ||
		!validSecurityID(config.ExpectedRootProviderID) || !validSecurityID(config.RootTrustProfile) ||
		config.LeaseDuration < minimumWorkflowLeaseDuration || config.LeaseDuration > 5*time.Minute {
		return nil, ErrInvalidData
	}
	if config.PortableEvidence && !validSecurityID(config.RecoveryCryptoSuiteID) {
		return nil, ErrInvalidData
	}
	if config.Now == nil {
		config.Now = time.Now
	}
	if config.ReplacementClaimTTL == 0 {
		config.ReplacementClaimTTL = defaultReplacementClaimTTL
	}
	if config.FinalizationBackoff == 0 {
		config.FinalizationBackoff = defaultFinalizationRetryBackoff
	}
	if config.ClaimToken == nil {
		config.ClaimToken = newRecoveryClaimToken
	}
	if config.ReplacementClaimTTL <= 0 || config.ReplacementClaimTTL > maxReplacementClaimTTL ||
		config.FinalizationBackoff <= 0 {
		return nil, ErrInvalidData
	}
	return &Manager{store: store, providers: providers, config: config}, nil
}

func (m *Manager) externalCallContext(ctx context.Context) (context.Context, context.CancelFunc) {
	return context.WithTimeout(ctx, m.config.LeaseDuration/2)
}

func (m *Manager) Ready(ctx context.Context) error {
	if m == nil || m.store == nil || m.config.LeaseDuration < minimumWorkflowLeaseDuration ||
		m.config.LeaseDuration > 5*time.Minute {
		return ErrProviderUnavailable
	}
	return m.providers.Ready(ctx)
}

// Finalize 推进 Pool 级三阶段轮换。只有 provider release 已持久后，同步调用才生成 claim token。
func (m *Manager) Finalize(ctx context.Context, request FinalizeRequest) (*FinalizationProgress, error) {
	target, err := m.beginFinalization(ctx, request)
	if err != nil {
		return nil, err
	}
	if target.Operation != nil && target.Operation.Status == "SUCCEEDED" {
		return finalizationProgress(target, planStatusFinalized, nil), nil
	}
	target, err = m.advanceFinalizationNetwork(ctx, target, true)
	if err != nil {
		return nil, err
	}
	if target.CaseStatus != "READY_TO_ISSUE" {
		return finalizationProgress(target, target.CaseStatus, nil), nil
	}
	return m.issueReplacementClaims(ctx, target)
}

// RecoverNextFinalization 恢复所有可精确重放的外部调用，但不生成无人接收的原始 claim token。
func (m *Manager) RecoverNextFinalization(ctx context.Context) (bool, error) {
	target, err := m.store.AcquireNextPermanentReplacementLease(ctx,
		AcquireNextPermanentReplacementLeaseInput{LeaseOwner: m.config.LeaseOwner,
			LeaseDuration: m.config.LeaseDuration})
	if errors.Is(err, ErrNotFound) {
		return false, nil
	}
	if err != nil {
		return false, err
	}
	if target == nil || target.Operation == nil || target.Plan == nil {
		return false, ErrInvalidData
	}
	_, err = m.advanceFinalizationNetwork(ctx, target, false)
	return true, err
}

// ClaimReplacementCredential 是受控管理员交付接口；Recovery key 只授权流程，不代表目标成员身份。
func (m *Manager) ClaimReplacementCredential(ctx context.Context,
	request ReplacementCredentialClaimRequest) (*ReplacementCredentialDelivery, error) {
	if !validSecurityID(request.PlanExternalID) || !validSecurityID(request.OperationID) ||
		!validSecurityID(request.SeatID) || !validSecurityID(request.TargetMemberID) ||
		strings.TrimSpace(request.ClaimToken) == "" {
		return nil, ErrInvalidData
	}
	tokenHash := sha256.Sum256([]byte(request.ClaimToken))
	claim, err := m.store.AcquireReplacementCredentialClaim(ctx, AcquireReplacementCredentialClaimInput{
		Key:            OperationKey{ClientID: m.config.ClientID, OperationID: request.OperationID},
		PlanExternalID: request.PlanExternalID, SeatExternalID: request.SeatID,
		TargetMemberExternalID: request.TargetMemberID, TokenHash: tokenHash,
		LeaseOwner: m.config.LeaseOwner, LeaseDuration: m.config.LeaseDuration,
	})
	if err != nil {
		return nil, err
	}
	if claim == nil || claim.Key.OperationID != request.OperationID ||
		claim.PlanExternalID != request.PlanExternalID || claim.SeatExternalID != request.SeatID ||
		claim.TargetMemberExternalID != request.TargetMemberID || claim.PrepareRequestHash == ([sha256.Size]byte{}) ||
		claim.CredentialFingerprint == ([sha256.Size]byte{}) {
		return nil, ErrBindingMismatch
	}
	envelope := credentials.Envelope{Algorithm: claim.EnvelopeAlgorithm, KeyRef: claim.EnvelopeKeyRef,
		Ciphertext: append([]byte(nil), claim.EnvelopeCiphertext...), Nonce: append([]byte(nil), claim.EnvelopeNonce...),
		AADHash: claim.EnvelopeAADHash, WrappedDEK: append([]byte(nil), claim.WrappedDEK...)}
	defer clearCredentialEnvelope(&envelope)
	aad := ReplacementCredentialClaimAAD(m.config.ClientID, claim.PlanExternalID, claim.Key.OperationID,
		claim.SeatExternalID, claim.TargetMemberExternalID, claim.PrepareRequestHash, claim.CredentialFingerprint)
	credential, err := m.providers.CredentialCipher.Open(ctx, envelope, aad)
	if err != nil {
		return nil, ErrProviderUnavailable
	}
	defer clear(credential)
	if sha256.Sum256(credential) != claim.CredentialFingerprint {
		return nil, ErrBindingMismatch
	}
	committed, err := m.store.CommitReplacementCredentialClaim(ctx, CommitReplacementCredentialClaimInput{
		Key: claim.Key, PlanExternalID: claim.PlanExternalID, SeatExternalID: claim.SeatExternalID,
		TargetMemberExternalID: claim.TargetMemberExternalID, TokenHash: tokenHash,
		LeaseOwner: m.config.LeaseOwner, FencingToken: claim.FencingToken,
	})
	if err != nil {
		return nil, err
	}
	if committed == nil || committed.Status != "CLAIMED" {
		return nil, ErrInvalidState
	}
	return &ReplacementCredentialDelivery{OperationID: request.OperationID, SeatID: request.SeatID,
		TargetMemberID: request.TargetMemberID, Credential: string(credential)}, nil
}

func (m *Manager) beginFinalization(ctx context.Context, request FinalizeRequest) (*PermanentReplacementTarget, error) {
	if err := validateFinalizeRequest(&request); err != nil {
		return nil, err
	}
	snapshotRequest := request
	snapshotRequest.ExpectedFencingToken = 0
	snapshot, err := canonicalIntentJSON(snapshotRequest)
	if err != nil {
		return nil, err
	}
	key := OperationKey{ClientID: m.config.ClientID, OperationID: request.OperationID}
	if len(request.Replacements) == 0 {
		target, _, beginErr := m.store.BeginBootstrapFinalization(ctx, BeginBootstrapFinalizationInput{
			Key: key, CaseExternalID: request.CaseExternalID, PlanExternalID: request.PlanExternalID,
			EvidenceExternalIDs: request.EvidenceExternalIDs, RequestHash: sha256.Sum256(snapshot),
			RequestSnapshot: snapshot, LeaseOwner: m.config.LeaseOwner, LeaseDuration: m.config.LeaseDuration,
			ExpectedFencingToken: request.ExpectedFencingToken,
		})
		return validateFinalizationTarget(target, beginErr)
	}
	target, _, beginErr := m.store.BeginPermanentReplacement(ctx, BeginPermanentReplacementInput{
		Key: key, CaseExternalID: request.CaseExternalID, PlanExternalID: request.PlanExternalID,
		Seats: request.Replacements, EvidenceExternalIDs: request.EvidenceExternalIDs,
		RequestHash: sha256.Sum256(snapshot), RequestSnapshot: snapshot,
		LeaseOwner: m.config.LeaseOwner, LeaseDuration: m.config.LeaseDuration,
		ExpectedFencingToken: request.ExpectedFencingToken,
	})
	return validateFinalizationTarget(target, beginErr)
}

func (m *Manager) advanceFinalizationNetwork(ctx context.Context,
	target *PermanentReplacementTarget, allowStructural bool) (*PermanentReplacementTarget, error) {
	if target == nil || target.Operation == nil || target.Plan == nil ||
		target.Operation.LeaseOwner != m.config.LeaseOwner || target.Operation.LeaseExpiresAt == nil ||
		len(target.SeatTargets) == 0 {
		return nil, ErrInvalidState
	}
	if target.CaseStatus == "FINALIZED" || target.CaseStatus == "READY_TO_ISSUE" {
		return target, nil
	}
	if target.CaseStatus == "PROVIDER_COMMIT_PENDING" {
		if target.Plan.Status != planStatusFinalized {
			return nil, ErrInvalidState
		}
		return m.releasePermanentRotation(ctx, target)
	}
	if target.Plan.Status != planStatusReady {
		return nil, ErrInvalidState
	}
	// Activation is deliberately durable before the platform structural commit. A restart at
	// this boundary must validate the persisted activation and resume there; replaying prepare
	// would reject the already-ACTIVATED seats and could repeat an external side effect.
	if target.CaseStatus == "READY_TO_COMMIT" {
		if target.Preparation == nil || target.Preparation.Status != "SUCCEEDED" ||
			target.Activation == nil || target.Activation.Status != "SUCCEEDED" {
			return nil, ErrInvalidState
		}
		validated, validateErr := m.activatePermanentRotation(ctx, target)
		if validateErr != nil {
			return nil, validateErr
		}
		if !allowStructural {
			return validated, nil
		}
		committed, commitErr := m.commitStructuralFinalization(ctx, validated)
		if commitErr != nil {
			return nil, commitErr
		}
		return m.releasePermanentRotation(ctx, committed)
	}
	prepared, preparation, err := m.preparePermanentRotation(ctx, target)
	if err != nil {
		return nil, err
	}
	target.SeatTargets = prepared
	target.Preparation = preparation
	target, err = m.activatePermanentRotation(ctx, target)
	if err != nil || target.CaseStatus != "READY_TO_COMMIT" || !allowStructural {
		return target, err
	}
	target, err = m.commitStructuralFinalization(ctx, target)
	if err != nil {
		return nil, err
	}
	return m.releasePermanentRotation(ctx, target)
}

// renewPermanentRotationLeases 在外部调用和本地持久化边界执行显式心跳。
// 续租不改变 fencing token；一旦发生 takeover，旧执行者必须在写入前失败关闭。
func (m *Manager) renewPermanentRotationLeases(ctx context.Context, target *PermanentReplacementTarget,
	children ...**StoredOperation) error {
	if target == nil || target.Operation == nil {
		return ErrInvalidState
	}
	current := target.Operation
	renewed, err := m.store.RenewPermanentReplacementLease(ctx, RenewPermanentReplacementLeaseInput{
		Key: current.Key, LeaseOwner: m.config.LeaseOwner, ExpectedFencingToken: current.FencingToken,
		LeaseDuration: m.config.LeaseDuration,
	})
	if err != nil {
		return err
	}
	if renewed == nil || renewed.Operation == nil || renewed.Operation.Key != current.Key ||
		renewed.Operation.FencingToken != current.FencingToken || renewed.Operation.Status != "RUNNING" ||
		renewed.Operation.LeaseOwner != m.config.LeaseOwner || renewed.Operation.LeaseExpiresAt == nil {
		return ErrBindingMismatch
	}
	target.Operation = renewed.Operation
	for _, childRef := range children {
		if childRef == nil || *childRef == nil || (*childRef).Status != "RUNNING" {
			return ErrInvalidState
		}
		child := *childRef
		updated, renewErr := m.store.RenewRecoveryChildOperationLease(ctx,
			RenewRecoveryChildOperationLeaseInput{FinalizationKey: target.Operation.Key,
				FinalizationLeaseOwner:   m.config.LeaseOwner,
				FinalizationFencingToken: target.Operation.FencingToken,
				DerivedOperationID:       child.Key.OperationID, ChildLeaseOwner: m.config.LeaseOwner,
				ExpectedChildFencingToken: child.FencingToken, ChildLeaseDuration: m.config.LeaseDuration})
		if renewErr != nil {
			return renewErr
		}
		if updated == nil || updated.Key != child.Key || updated.RequestHash != child.RequestHash ||
			updated.FencingToken != child.FencingToken || updated.Status != "RUNNING" ||
			updated.LeaseOwner != m.config.LeaseOwner || updated.LeaseExpiresAt == nil {
			return ErrBindingMismatch
		}
		*childRef = updated
	}
	return nil
}

func (m *Manager) renewPoolPreparationLeases(ctx context.Context, target *PermanentReplacementTarget,
	seats []SeatRotationTarget, preparation *PoolPreparationTarget) error {
	if preparation == nil || preparation.Operation == nil {
		return ErrInvalidState
	}
	children := []**StoredOperation{&preparation.Operation}
	for index := range seats {
		if seats[index].Operation != nil && seats[index].Operation.Status == "RUNNING" {
			children = append(children, &seats[index].Operation)
		}
	}
	return m.renewPermanentRotationLeases(ctx, target, children...)
}

func (m *Manager) preparePermanentRotation(ctx context.Context, target *PermanentReplacementTarget) (
	[]SeatRotationTarget, *StoredOperation, error) {
	seats := append([]SeatRotationTarget(nil), target.SeatTargets...)
	sort.Slice(seats, func(i, j int) bool { return seats[i].Progress.SeatExternalID < seats[j].Progress.SeatExternalID })
	requests := make([]PermanentSeatRotationPrepareRequest, len(seats))
	for index := range seats {
		request, err := seatPrepareRequest(target.Plan, seats[index].Progress)
		if err != nil {
			return nil, nil, err
		}
		requests[index] = request
		if seats[index].Progress.Status == "PREPARED" {
			if seats[index].Operation == nil || seats[index].Operation.RequestHash != request.RequestHash {
				return nil, nil, ErrBindingMismatch
			}
			continue
		}
		snapshot, err := canonicalIntentJSON(request)
		if err != nil {
			return nil, nil, err
		}
		expectedFence := int64(0)
		if seats[index].Operation != nil {
			expectedFence = seats[index].Operation.FencingToken
		}
		child, _, err := m.store.BeginSeatRotation(ctx, BeginSeatRotationInput{
			FinalizationKey: target.Operation.Key, FinalizationLeaseOwner: m.config.LeaseOwner,
			FinalizationFencingToken: target.Operation.FencingToken, SeatExternalID: request.SeatID,
			DerivedOperationID: request.OperationID, RequestHash: request.RequestHash, RequestSnapshot: snapshot,
			ChildLeaseOwner: m.config.LeaseOwner, ExpectedChildFencingToken: expectedFence,
			ChildLeaseDuration: m.config.LeaseDuration,
		})
		if err != nil {
			return nil, nil, err
		}
		seats[index] = *child
	}
	childSetHash, err := PermanentRotationChildSetHash(requests)
	if err != nil {
		return nil, nil, err
	}
	poolRequest := PermanentPoolRotationPrepareRequest{ProtocolVersion: PermanentSeatRotationProtocolV1,
		OperationID: deterministicExternalID("prepare-set", target.Plan.ExternalID, target.Operation.Key.OperationID),
		PlanID:      target.Plan.ExternalID, CeremonyType: target.Plan.CeremonyType, PoolID: target.Plan.PoolExternalID,
		FromEpoch: target.Plan.FromEpoch, ToEpoch: target.Plan.ToEpoch, ChildSetHash: childSetHash, Seats: requests}
	poolRequest.RequestHash = PermanentPoolRotationPrepareRequestHash(poolRequest)
	if allSeatsPrepared(seats) {
		if target.Preparation == nil || target.Preparation.Key.OperationID != poolRequest.OperationID ||
			target.Preparation.RequestHash != poolRequest.RequestHash || target.Preparation.Status != "SUCCEEDED" {
			return nil, nil, ErrBindingMismatch
		}
		return seats, target.Preparation, nil
	}
	poolSnapshot, err := rotationSnapshot(poolRequest, "child_set_hash", childSetHash)
	if err != nil {
		return nil, nil, err
	}
	expectedPoolFence := int64(0)
	if target.Preparation != nil {
		expectedPoolFence = target.Preparation.FencingToken
	}
	preparation, _, err := m.store.BeginPoolPreparation(ctx, BeginPoolPreparationInput{
		FinalizationKey: target.Operation.Key, FinalizationLeaseOwner: m.config.LeaseOwner,
		FinalizationFencingToken: target.Operation.FencingToken, DerivedOperationID: poolRequest.OperationID,
		RequestHash: poolRequest.RequestHash, RequestSnapshot: poolSnapshot, LeaseOwner: m.config.LeaseOwner,
		ExpectedFencingToken: expectedPoolFence, LeaseDuration: m.config.LeaseDuration,
	})
	if err != nil {
		return nil, nil, err
	}
	if preparation == nil || preparation.Operation == nil || preparation.IntentSetHash != childSetHash {
		return nil, nil, ErrBindingMismatch
	}
	if err := m.renewPoolPreparationLeases(ctx, target, seats, preparation); err != nil {
		return nil, nil, err
	}
	providerCtx, cancelProvider := m.externalCallContext(ctx)
	result, providerErr := m.providers.SeatRotations.PreparePoolRotation(providerCtx, poolRequest)
	cancelProvider()
	if err := m.renewPoolPreparationLeases(ctx, target, seats, preparation); err != nil {
		return nil, nil, err
	}
	if providerErr != nil {
		return nil, nil, m.commitPreparationUncertain(ctx, target, preparation.Operation, "UPSTREAM_RESULT_UNKNOWN")
	}
	defer clearPermanentPrepareCredentials(result.Seats)
	if err := ValidatePermanentPoolRotationPrepareResult(poolRequest, result); err != nil {
		return nil, nil, m.commitPreparationUncertain(ctx, target, preparation.Operation, "UPSTREAM_BINDING_INVALID")
	}
	for index := range result.Seats {
		if seats[index].Progress.Status == "PREPARED" {
			fingerprint := sha256.Sum256(result.Seats[index].Credential)
			if seats[index].Progress.CredentialFingerprint != fingerprint ||
				seats[index].Progress.PreparedReference != result.Seats[index].PreparedRotationRef ||
				seats[index].Progress.ProviderResultDigest != PermanentSeatRotationPrepareResultDigest(result.Seats[index], fingerprint) {
				return nil, nil, ErrBindingMismatch
			}
			continue
		}
		fingerprint := sha256.Sum256(result.Seats[index].Credential)
		aad := ReplacementCredentialClaimAAD(m.config.ClientID, result.Seats[index].PlanID,
			result.Seats[index].OperationID, result.Seats[index].SeatID, result.Seats[index].TargetMemberID,
			result.Seats[index].RequestHash, fingerprint)
		if err := m.renewPermanentRotationLeases(ctx, target, &seats[index].Operation,
			&preparation.Operation); err != nil {
			return nil, nil, err
		}
		sealCtx, cancelSeal := m.externalCallContext(ctx)
		envelope, sealErr := m.providers.CredentialCipher.Seal(sealCtx, result.Seats[index].Credential, aad)
		cancelSeal()
		if err := m.renewPermanentRotationLeases(ctx, target, &seats[index].Operation,
			&preparation.Operation); err != nil {
			clearCredentialEnvelope(&envelope)
			return nil, nil, err
		}
		if sealErr != nil {
			clearCredentialEnvelope(&envelope)
			return nil, nil, ErrProviderUnavailable
		}
		claim := replacementClaimFromEnvelope(result.Seats[index], fingerprint, envelope)
		if err := m.renewPermanentRotationLeases(ctx, target, &seats[index].Operation,
			&preparation.Operation); err != nil {
			clearCredentialEnvelope(&envelope)
			return nil, nil, err
		}
		progress, err := m.store.CommitSeatRotationProgress(ctx, CommitSeatRotationProgressInput{
			FinalizationKey: target.Operation.Key, FinalizationLeaseOwner: m.config.LeaseOwner,
			FinalizationFencingToken: target.Operation.FencingToken, ChildLeaseOwner: m.config.LeaseOwner,
			ChildFencingToken: seats[index].Operation.FencingToken, PreparationKey: preparation.Operation.Key,
			PreparationLeaseOwner: m.config.LeaseOwner, PreparationFencingToken: preparation.Operation.FencingToken,
			PreparationSetHash: childSetHash, SeatExternalID: result.Seats[index].SeatID,
			DerivedOperationID: result.Seats[index].OperationID, Status: "PREPARED",
			PrincipalUserID: result.Seats[index].PrincipalUserID, SubscriptionID: result.Seats[index].SubscriptionID,
			APIKeyID: result.Seats[index].APIKeyID, APIKeyVersion: result.Seats[index].ActiveAPIKeyVersion,
			Claim: &claim,
		})
		clearCredentialEnvelope(&envelope)
		if err != nil {
			return nil, nil, err
		}
		seats[index].Progress = progress
		seats[index].Operation.Status = "SUCCEEDED"
	}
	preparation.Operation.Status = "SUCCEEDED"
	return seats, preparation.Operation, nil
}

func (m *Manager) activatePermanentRotation(ctx context.Context,
	target *PermanentReplacementTarget) (*PermanentReplacementTarget, error) {
	bindings, err := activationBindings(target.SeatTargets)
	if err != nil {
		return nil, err
	}
	preparedSetHash, err := PermanentPreparedSeatSetHash(bindings)
	if err != nil {
		return nil, err
	}
	request := PermanentPoolRotationActivateRequest{ProtocolVersion: PermanentSeatRotationProtocolV1,
		OperationID:        deterministicExternalID("activate-set", target.Plan.ExternalID, target.Operation.Key.OperationID),
		PrepareOperationID: target.Preparation.Key.OperationID, PlanID: target.Plan.ExternalID,
		CeremonyType: target.Plan.CeremonyType, PoolID: target.Plan.PoolExternalID,
		FromEpoch: target.Plan.FromEpoch, ToEpoch: target.Plan.ToEpoch, PreparedSetHash: preparedSetHash, Seats: bindings}
	request.RequestHash = PermanentPoolRotationActivateRequestHash(request)
	if target.Activation != nil && target.Activation.Status == "SUCCEEDED" {
		if target.Activation.Key.OperationID != request.OperationID || target.Activation.RequestHash != request.RequestHash {
			return nil, ErrBindingMismatch
		}
		return target, nil
	}
	snapshot, err := rotationSnapshot(request, "prepared_set_hash", preparedSetHash)
	if err != nil {
		return nil, err
	}
	expectedFence := int64(0)
	if target.Activation != nil {
		expectedFence = target.Activation.FencingToken
	}
	activation, _, err := m.store.BeginPoolActivation(ctx, BeginPoolActivationInput{
		FinalizationKey: target.Operation.Key, FinalizationLeaseOwner: m.config.LeaseOwner,
		FinalizationFencingToken: target.Operation.FencingToken, DerivedOperationID: request.OperationID,
		RequestHash: request.RequestHash, RequestSnapshot: snapshot, ChildLeaseOwner: m.config.LeaseOwner,
		ExpectedChildFencingToken: expectedFence, ChildLeaseDuration: m.config.LeaseDuration,
	})
	if err != nil {
		return nil, err
	}
	if activation == nil || activation.Operation == nil || activation.PreparedSetHash != preparedSetHash {
		return nil, ErrBindingMismatch
	}
	if err := m.renewPermanentRotationLeases(ctx, target, &activation.Operation); err != nil {
		return nil, err
	}
	providerCtx, cancelProvider := m.externalCallContext(ctx)
	result, providerErr := m.providers.SeatRotations.ActivatePreparedPoolRotation(providerCtx, request)
	cancelProvider()
	if err := m.renewPermanentRotationLeases(ctx, target, &activation.Operation); err != nil {
		return nil, err
	}
	if providerErr != nil {
		return nil, m.commitActivationUncertain(ctx, target, activation.Operation, preparedSetHash,
			"UPSTREAM_RESULT_UNKNOWN")
	}
	if err := VerifyPermanentPoolRotationActivateResult(ctx, m.providers.SeatActivations, request, result); err != nil {
		return nil, m.commitActivationUncertain(ctx, target, activation.Operation, preparedSetHash,
			"UPSTREAM_BINDING_INVALID")
	}
	activatedSeats := make([]PoolActivatedSeat, len(result.Seats))
	for index, seat := range result.Seats {
		activatedSeats[index] = PoolActivatedSeat{SeatExternalID: seat.SeatID,
			TargetMemberExternalID: seat.TargetMemberID, PreparedReference: seat.PreparedRotationRef,
			PrincipalUserID: seat.PrincipalUserID, SubscriptionID: seat.SubscriptionID, APIKeyID: seat.APIKeyID,
			APIKeyVersion: seat.ActiveAPIKeyVersion, CredentialFingerprint: seat.CredentialFingerprint,
			CurrentConcurrency: int64(seat.CurrentConcurrency), PendingSettlements: int64(seat.PendingSettlements)}
	}
	if err := m.renewPermanentRotationLeases(ctx, target, &activation.Operation); err != nil {
		return nil, err
	}
	return m.store.CommitPoolActivation(ctx, CommitPoolActivationInput{
		FinalizationKey: target.Operation.Key, FinalizationLeaseOwner: m.config.LeaseOwner,
		FinalizationFencingToken: target.Operation.FencingToken, ChildLeaseOwner: m.config.LeaseOwner,
		ChildFencingToken: activation.Operation.FencingToken, DerivedOperationID: request.OperationID,
		Status: "ACTIVATED", PreparedSetHash: preparedSetHash, ProviderAttestationRef: result.AttestationRef,
		ProviderAttestationDigest: result.AttestationDigest, ProviderAttestationIssuer: result.AttestationIssuer,
		ProviderAttestationKeyID: result.AttestationKeyID, ProviderAttestationVersion: result.AttestationVersion,
		ProviderAttestationSignature:      append([]byte(nil), result.Attestation...),
		OldCredentialSetInvalidated:       result.OldCredentialSetInvalidated,
		CredentialFingerprintGateEnforced: result.CredentialFingerprintGateEnforced,
		AuthorizationCacheInvalidated:     result.AuthorizationCacheInvalidated,
		AuthorizationCacheDurableOutbox:   result.AuthCacheDurableOutbox,
		AuthCacheMinimumEvents:            result.AuthCacheMinimumEvents,
		Seats:                             activatedSeats,
	})
}

func (m *Manager) commitPreparationUncertain(ctx context.Context, target *PermanentReplacementTarget,
	operation *StoredOperation, code string) error {
	if err := m.renewPermanentRotationLeases(ctx, target, &operation); err != nil {
		return err
	}
	next := m.config.Now().UTC().Add(m.config.FinalizationBackoff)
	_, err := m.store.CommitPoolPreparationFailure(ctx, CommitPoolPreparationFailureInput{
		FinalizationKey: target.Operation.Key, FinalizationLeaseOwner: m.config.LeaseOwner,
		FinalizationFencingToken: target.Operation.FencingToken, PreparationKey: operation.Key,
		PreparationLeaseOwner: m.config.LeaseOwner, PreparationFencingToken: operation.FencingToken,
		Status: "RECONCILE_REQUIRED", ErrorCode: code,
		ErrorDetail: "external Pool preparation outcome requires exact replay", NextAttemptAt: &next,
	})
	if err != nil {
		return err
	}
	return ErrProviderUnavailable
}

func (m *Manager) commitActivationUncertain(ctx context.Context, target *PermanentReplacementTarget,
	operation *StoredOperation, preparedSetHash [sha256.Size]byte, code string) error {
	if err := m.renewPermanentRotationLeases(ctx, target, &operation); err != nil {
		return err
	}
	next := m.config.Now().UTC().Add(m.config.FinalizationBackoff)
	_, err := m.store.CommitPoolActivation(ctx, CommitPoolActivationInput{
		FinalizationKey: target.Operation.Key, FinalizationLeaseOwner: m.config.LeaseOwner,
		FinalizationFencingToken: target.Operation.FencingToken, ChildLeaseOwner: m.config.LeaseOwner,
		ChildFencingToken: operation.FencingToken, DerivedOperationID: operation.Key.OperationID,
		Status: "RECONCILE_REQUIRED", PreparedSetHash: preparedSetHash, ErrorCode: code,
		ErrorDetail: "external Pool activation outcome requires exact replay", NextAttemptAt: &next,
	})
	if err != nil {
		return err
	}
	return ErrProviderUnavailable
}

func (m *Manager) commitStructuralFinalization(ctx context.Context,
	target *PermanentReplacementTarget) (*PermanentReplacementTarget, error) {
	intents := make([]ReplacementClaimIntent, len(target.SeatTargets))
	for index, seat := range target.SeatTargets {
		if seat.Operation == nil || seat.Progress == nil || seat.Progress.Status != "ACTIVATED" {
			return nil, ErrInvalidState
		}
		intents[index] = ReplacementClaimIntent{SeatExternalID: seat.Progress.SeatExternalID,
			ClaimOperationID: deterministicExternalID("credential-claim", target.Plan.ExternalID,
				seat.Progress.SeatExternalID)}
	}
	sort.Slice(intents, func(i, j int) bool { return intents[i].SeatExternalID < intents[j].SeatExternalID })
	resultSnapshot, err := canonicalIntentJSON(map[string]any{"plan_id": target.Plan.ExternalID,
		"ceremony_type": target.Plan.CeremonyType, "pool_id": target.Plan.PoolExternalID,
		"from_epoch": target.Plan.FromEpoch, "to_epoch": target.Plan.ToEpoch, "status": planStatusFinalized})
	if err != nil {
		return nil, err
	}
	if err := m.renewPermanentRotationLeases(ctx, target); err != nil {
		return nil, err
	}
	input := CommitPermanentReplacementInput{Key: target.Operation.Key, LeaseOwner: m.config.LeaseOwner,
		FencingToken: target.Operation.FencingToken, ClaimIntents: intents, ResultSnapshot: resultSnapshot}
	var operation *StoredOperation
	if target.Plan.CeremonyType == CeremonyBootstrap {
		operation, _, err = m.store.CommitBootstrapFinalization(ctx, input)
	} else {
		operation, _, err = m.store.CommitPermanentReplacement(ctx, input)
	}
	if err != nil {
		return nil, err
	}
	if operation == nil || operation.Key != target.Operation.Key || operation.Status != "RUNNING" ||
		operation.LeaseOwner != m.config.LeaseOwner || operation.LeaseExpiresAt == nil {
		return nil, ErrInvalidState
	}
	target.Operation = operation
	target.Plan.Status = planStatusFinalized
	target.CaseStatus = "PROVIDER_COMMIT_PENDING"
	for index := range target.SeatTargets {
		target.SeatTargets[index].Progress.Status = "COMMITTED"
	}
	return target, nil
}

func (m *Manager) releasePermanentRotation(ctx context.Context,
	target *PermanentReplacementTarget) (*PermanentReplacementTarget, error) {
	bindings, err := releaseBindings(target.SeatTargets)
	if err != nil || target.Preparation == nil || target.Activation == nil {
		return nil, ErrInvalidState
	}
	preparedSetHash, err := PermanentPreparedSeatSetHash(bindings)
	if err != nil {
		return nil, err
	}
	request := PermanentPoolRotationCommitRequest{ProtocolVersion: PermanentSeatRotationProtocolV1,
		OperationID:           deterministicExternalID("provider-commit", target.Plan.ExternalID, target.Operation.Key.OperationID),
		PrepareOperationID:    target.Preparation.Key.OperationID,
		ActivationOperationID: target.Activation.Key.OperationID,
		ActivationRequestHash: target.Activation.RequestHash, PlanID: target.Plan.ExternalID,
		CeremonyType: target.Plan.CeremonyType, PoolID: target.Plan.PoolExternalID,
		FromEpoch: target.Plan.FromEpoch, ToEpoch: target.Plan.ToEpoch,
		PreparedSetHash: preparedSetHash, Seats: bindings}
	request.RequestHash = PermanentPoolRotationCommitRequestHash(request)
	if target.ProviderRelease != nil && target.ProviderRelease.Status == "SUCCEEDED" {
		if target.ProviderRelease.Key.OperationID != request.OperationID ||
			target.ProviderRelease.RequestHash != request.RequestHash {
			return nil, ErrBindingMismatch
		}
		target.CaseStatus = "READY_TO_ISSUE"
		return target, nil
	}
	snapshot, err := rotationSnapshot(request, "prepared_set_hash", preparedSetHash)
	if err != nil {
		return nil, err
	}
	expectedFence := int64(0)
	if target.ProviderRelease != nil {
		expectedFence = target.ProviderRelease.FencingToken
	}
	release, _, err := m.store.BeginProviderRelease(ctx, BeginProviderReleaseInput{
		FinalizationKey: target.Operation.Key, FinalizationLeaseOwner: m.config.LeaseOwner,
		FinalizationFencingToken: target.Operation.FencingToken, DerivedOperationID: request.OperationID,
		RequestHash: request.RequestHash, RequestSnapshot: snapshot, ChildLeaseOwner: m.config.LeaseOwner,
		ExpectedChildFencingToken: expectedFence, ChildLeaseDuration: m.config.LeaseDuration,
	})
	if err != nil {
		return nil, err
	}
	if release == nil || release.Operation == nil || release.Plan == nil ||
		release.Operation.Key != (OperationKey{ClientID: target.Operation.Key.ClientID, OperationID: request.OperationID}) ||
		release.Operation.RequestHash != request.RequestHash || release.Operation.Status != "RUNNING" ||
		release.Operation.LeaseOwner != m.config.LeaseOwner || release.Operation.LeaseExpiresAt == nil ||
		release.Plan.ExternalID != target.Plan.ExternalID || release.PreparedSetHash != preparedSetHash {
		return nil, ErrBindingMismatch
	}
	if err := m.renewPermanentRotationLeases(ctx, target, &release.Operation); err != nil {
		return nil, err
	}
	providerCtx, cancelProvider := m.externalCallContext(ctx)
	result, providerErr := m.providers.SeatRotations.CommitActivatedPoolRotation(providerCtx, request)
	cancelProvider()
	if err := m.renewPermanentRotationLeases(ctx, target, &release.Operation); err != nil {
		return nil, err
	}
	if providerErr != nil {
		return nil, m.commitReleaseUncertain(ctx, target, release.Operation, "UPSTREAM_RESULT_UNKNOWN")
	}
	if err := VerifyPermanentPoolRotationCommitResult(ctx, m.providers.SeatActivations, request, result); err != nil {
		return nil, m.commitReleaseUncertain(ctx, target, release.Operation, "UPSTREAM_BINDING_INVALID")
	}
	resultSnapshot, err := canonicalIntentJSON(result)
	if err != nil {
		return nil, err
	}
	if err := m.renewPermanentRotationLeases(ctx, target, &release.Operation); err != nil {
		return nil, err
	}
	parent, _, err := m.store.CommitProviderRelease(ctx, CommitProviderReleaseInput{
		FinalizationKey: target.Operation.Key, FinalizationLeaseOwner: m.config.LeaseOwner,
		FinalizationFencingToken: target.Operation.FencingToken, DerivedOperationID: request.OperationID,
		ChildLeaseOwner: m.config.LeaseOwner, ChildFencingToken: release.Operation.FencingToken,
		Status: "RELEASED", ProviderAttestationRef: result.AttestationRef,
		ProviderAttestationDigest: result.AttestationDigest, ProviderAttestationIssuer: result.AttestationIssuer,
		ProviderAttestationKeyID: result.AttestationKeyID, ProviderAttestationVersion: result.AttestationVersion,
		ProviderAttestationSignature:      append([]byte(nil), result.Attestation...),
		AllCredentialsEnabled:             result.AllCredentialsEnabled,
		AllSubscriptionsEnabled:           result.AllSubscriptionsEnabled,
		OldCredentialSetInvalidated:       result.OldCredentialSetInvalidated,
		CredentialFingerprintGateEnforced: result.CredentialFingerprintGateEnforced,
		AuthorizationCacheInvalidated:     result.AuthorizationCacheInvalidated,
		AuthorizationCacheDurableOutbox:   result.AuthCacheDurableOutbox,
		AuthCacheMinimumEvents:            result.AuthCacheMinimumEvents,
		ResultSnapshot:                    resultSnapshot,
	})
	if err != nil {
		return nil, err
	}
	if parent == nil || parent.Key != target.Operation.Key || parent.Status != "RUNNING" ||
		parent.LeaseOwner != m.config.LeaseOwner || parent.LeaseExpiresAt == nil {
		return nil, ErrInvalidState
	}
	target.Operation = parent
	target.ProviderRelease = release.Operation
	target.ProviderRelease.Status = "SUCCEEDED"
	target.CaseStatus = "READY_TO_ISSUE"
	return target, nil
}

func (m *Manager) commitReleaseUncertain(ctx context.Context, target *PermanentReplacementTarget,
	operation *StoredOperation, code string) error {
	if err := m.renewPermanentRotationLeases(ctx, target, &operation); err != nil {
		return err
	}
	next := m.config.Now().UTC().Add(m.config.FinalizationBackoff)
	_, _, err := m.store.CommitProviderRelease(ctx, CommitProviderReleaseInput{
		FinalizationKey: target.Operation.Key, FinalizationLeaseOwner: m.config.LeaseOwner,
		FinalizationFencingToken: target.Operation.FencingToken, DerivedOperationID: operation.Key.OperationID,
		ChildLeaseOwner: m.config.LeaseOwner, ChildFencingToken: operation.FencingToken,
		Status: "RECONCILE_REQUIRED", ErrorCode: code,
		ErrorDetail: "external Pool provider commit outcome requires exact replay", NextAttemptAt: &next,
	})
	if err != nil {
		return err
	}
	return ErrProviderUnavailable
}

func (m *Manager) issueReplacementClaims(ctx context.Context,
	target *PermanentReplacementTarget) (*FinalizationProgress, error) {
	if target == nil || target.Operation == nil || target.Plan == nil || target.CaseStatus != "READY_TO_ISSUE" {
		return nil, ErrInvalidState
	}
	now := m.config.Now().UTC()
	expiresAt := now.Add(m.config.ReplacementClaimTTL)
	claims := make([]ReplacementClaimActivation, len(target.SeatTargets))
	rawClaims := make([]ReplacementClaimToken, len(target.SeatTargets))
	for index, seat := range target.SeatTargets {
		if seat.Operation == nil || seat.Progress == nil || seat.Progress.Status != "COMMITTED" {
			return nil, ErrInvalidState
		}
		token, err := m.config.ClaimToken()
		if err != nil || strings.TrimSpace(token) == "" {
			return nil, ErrProviderUnavailable
		}
		claimOperationID := deterministicExternalID("credential-claim", target.Plan.ExternalID,
			seat.Progress.SeatExternalID)
		claims[index] = ReplacementClaimActivation{SeatExternalID: seat.Progress.SeatExternalID,
			ClaimOperationID: claimOperationID, TokenHash: sha256.Sum256([]byte(token)), ExpiresAt: expiresAt}
		rawClaims[index] = ReplacementClaimToken{OperationID: seat.Operation.Key.OperationID,
			ClaimOperationID: claimOperationID, SeatID: seat.Progress.SeatExternalID,
			TargetMemberID: seat.Progress.TargetMemberExternalID, ClaimToken: token, ExpiresAt: expiresAt}
	}
	sort.Slice(claims, func(i, j int) bool { return claims[i].SeatExternalID < claims[j].SeatExternalID })
	sort.Slice(rawClaims, func(i, j int) bool { return rawClaims[i].SeatID < rawClaims[j].SeatID })
	if err := m.renewPermanentRotationLeases(ctx, target); err != nil {
		return nil, err
	}
	operation, committed, err := m.store.CommitReplacementClaims(ctx, CommitReplacementClaimsInput{
		Key: target.Operation.Key, LeaseOwner: m.config.LeaseOwner,
		FencingToken: target.Operation.FencingToken, Claims: claims})
	if err != nil {
		return nil, err
	}
	if operation == nil || operation.Key != target.Operation.Key || operation.Status != "SUCCEEDED" {
		return nil, ErrInvalidState
	}
	target.Operation = operation
	target.CaseStatus = "FINALIZED"
	if !committed {
		rawClaims = nil
	}
	return finalizationProgress(target, planStatusFinalized, rawClaims), nil
}

// Prepare 只推进至 MANIFEST_DRAFT。所有外部 provider 调用都发生在 Store 事务之外。
func (m *Manager) Prepare(ctx context.Context, request PlanRequest) (*PlanProgress, error) {
	target, prepared, err := m.resume(ctx, request)
	if err != nil {
		return nil, err
	}
	plan := target.Plan
	if planStatusAtLeast(plan.Status, planStatusManifestDraft) {
		if plan.Status == planStatusManifestDraft {
			if err := m.republishMemberArtifacts(ctx, target, request, prepared); err != nil {
				return nil, err
			}
		}
		return planProgress(target, plan), nil
	}
	if err := m.renewLease(ctx, target); err != nil {
		return nil, err
	}
	pkg, err := m.createRecoveryPackage(ctx, request, prepared.members, prepared.previousHash)
	if err != nil {
		return nil, err
	}
	defer clearRecoveryPackage(&pkg)
	if err := m.renewLease(ctx, target); err != nil {
		return nil, err
	}
	if planStatusAtLeast(plan.Status, planStatusRootCommitted) {
		snapshot, snapshotErr := m.store.GetEpochSecuritySnapshot(ctx, request.PlanExternalID)
		if snapshotErr != nil {
			return nil, snapshotErr
		}
		if err := validateCommittedRecoveryPackage(snapshot, request, pkg,
			planStatusAtLeast(plan.Status, planStatusSharesCommitted)); err != nil {
			return nil, err
		}
	}
	key, fence := target.Operation.Key, target.Operation.FencingToken
	if plan.Status == planStatusPlanned {
		rootHash := RecoveryRootCommitmentHash(pkg)
		plan, err = m.store.CommitRootArtifact(ctx, RootArtifactInput{
			Key: key, LeaseOwner: m.config.LeaseOwner, FencingToken: fence,
			ExternalID: request.RootArtifactExternalID, Provider: pkg.ProviderID,
			ProviderKeyRef: pkg.RootPublicHandle, RootHandle: pkg.RootPublicHandle,
			RootKeyVersion: pkg.RootKeyVersion, EpochRecoveryAlgorithm: pkg.RootPublicAlgorithm,
			EpochRecoveryKeyID: pkg.RootPublicHandle, EpochRecoveryKeyFingerprint: pkg.RootPublicFingerprint,
			WrapDomain: pkg.RootWrapDomain, WrapAlgorithm: pkg.RootWrapAlgorithm,
			VSSAlgorithm: pkg.VSSAlgorithm, VSSCommitment: pkg.VSSCommitment,
			VSSCommitmentHash: sha256.Sum256(pkg.VSSCommitment), VSSProof: pkg.VSSProof,
			VSSProofHash: sha256.Sum256(pkg.VSSProof), PrivateKeyCommitment: pkg.RootPrivateCommitment,
			PrivateKeyCommitmentHash: sha256.Sum256(pkg.RootPrivateCommitment), RootCommitmentHash: rootHash,
			RecoveryPackageHash: pkg.PackageHash, RequestIntentHash: pkg.RequestIntentHash,
			ProviderAttestationRef: pkg.ProviderAttestationRef, AttestationDigest: pkg.ProviderAttestationDigest,
			AttestationSignature: pkg.ProviderAttestation, AttestationKeyID: pkg.ProviderAttestationKeyID,
			PortableAttestationAlgorithm:       pkg.PortableAttestationAlgorithm,
			PortableAttestationIssuer:          pkg.PortableAttestationIssuer,
			PortableAttestationKeyID:           pkg.PortableAttestationKeyID,
			PortableAttestationProtocolVersion: pkg.PortableAttestationProtocolVersion,
			PortableAttestationSignature:       append([]byte(nil), pkg.PortableAttestationSignature...),
		})
		if err != nil {
			return nil, err
		}
		target.Plan = plan
		if err := m.renewLease(ctx, target); err != nil {
			return nil, err
		}
		fence = target.Operation.FencingToken
	}
	if plan.Status == planStatusRootCommitted {
		deliveries := make([]ShareDeliveryInput, len(pkg.EncryptedShares))
		for index, share := range pkg.EncryptedShares {
			deliveries[index] = ShareDeliveryInput{
				ExternalID:       deterministicExternalID("share", request.PlanExternalID, share.MemberID),
				MemberExternalID: share.MemberID, ShareIndex: share.ShareIndex,
				EncryptionAlgorithm: share.EncryptionAlgorithm, RecipientKeyID: share.EncryptionKeyID,
				RecipientKeyFingerprint: share.EncryptionKeyFingerprint,
				Ciphertext:              append([]byte(nil), share.Ciphertext...), CiphertextHash: share.CiphertextHash,
				ProviderShareCommitment:      append([]byte(nil), share.ProviderCommitment...),
				ProviderProofDigest:          sha256.Sum256(share.ProviderProof),
				ProviderProofSignature:       append([]byte(nil), share.ProviderProof...),
				PortableProofAlgorithm:       share.PortableProofAlgorithm,
				PortableProofKeyID:           share.PortableProofKeyID,
				PortableProofProtocolVersion: share.PortableProofProtocolVersion,
				PortableProofSignature:       append([]byte(nil), share.PortableProofSignature...),
			}
		}
		plan, err = m.store.CommitShareDeliveries(ctx, key, m.config.LeaseOwner, fence, deliveries)
		clearShareDeliveries(deliveries)
		if err != nil {
			return nil, err
		}
		target.Plan = plan
		snapshot, snapshotErr := m.store.GetEpochSecuritySnapshot(ctx, request.PlanExternalID)
		if snapshotErr != nil {
			return nil, snapshotErr
		}
		if err := validateCommittedRecoveryPackage(snapshot, request, pkg, true); err != nil {
			return nil, err
		}
	}
	if plan.Status == planStatusSharesCommitted {
		if err := m.renewLease(ctx, target); err != nil {
			return nil, err
		}
		manifest, bindings, batchSetHash, err := m.buildManifest(ctx, request, prepared, pkg)
		if err != nil {
			return nil, err
		}
		defer clear(manifest.Bytes)
		if err := m.renewLease(ctx, target); err != nil {
			return nil, err
		}
		signRequest := PlatformManifestSignRequest{CeremonyType: request.CeremonyType,
			OperationID: request.OperationID, PoolID: request.PoolID, Epoch: request.ToEpoch,
			ManifestHash: manifest.Hash, Canonical: append([]byte(nil), manifest.Bytes...)}
		if profile := m.portableEvidenceProfile(); profile != nil {
			signRequest.SignatureDomain = profile.PlatformSignatureDomain
		}
		signature, err := m.providers.PlatformSigner.SignManifest(ctx, signRequest)
		if err != nil {
			clear(signRequest.Canonical)
			return nil, ErrSignatureInvalid
		}
		if err := m.renewLease(ctx, target); err != nil {
			clear(signRequest.Canonical)
			clear(signature.Signature)
			return nil, err
		}
		if err := VerifyPlatformManifestSignature(ctx, m.providers.PlatformSigner, signRequest, signature); err != nil {
			clear(signRequest.Canonical)
			clear(signature.Signature)
			return nil, err
		}
		clear(signRequest.Canonical)
		if err := m.renewLease(ctx, target); err != nil {
			clear(signature.Signature)
			return nil, err
		}
		fence = target.Operation.FencingToken
		plan, err = m.store.CommitManifestDraft(ctx, ManifestDraftInput{
			Key: key, LeaseOwner: m.config.LeaseOwner, FencingToken: fence,
			ExternalID: request.ManifestExternalID, ProtocolVersion: ProtocolVersionV1,
			CanonicalPayload: manifest.Bytes, ManifestHash: manifest.Hash, BatchSetHash: batchSetHash,
			RecoveryPackageHash: pkg.PackageHash, ProviderAttestationDigest: pkg.ProviderAttestationDigest,
			PlatformKeyRef: signature.KeyID, PlatformAlgorithm: signature.Algorithm,
			PlatformSignatureDomain: signature.SignatureDomain,
			PlatformSignature:       signature.Signature, PlatformVerifiedAt: m.config.Now().UTC(), BatchBindings: bindings,
		})
		clear(signature.Signature)
		if err != nil {
			return nil, err
		}
		target.Plan = plan
		snapshot, snapshotErr := m.store.GetEpochSecuritySnapshot(ctx, request.PlanExternalID)
		if snapshotErr != nil {
			return nil, snapshotErr
		}
		if err := m.publishMemberArtifacts(ctx, target, request, pkg, snapshot); err != nil {
			return nil, err
		}
	}
	return planProgress(target, plan), nil
}

func (m *Manager) republishMemberArtifacts(ctx context.Context, target *EpochPlanTarget,
	request PlanRequest, prepared preparedPlan) error {
	if err := m.renewLease(ctx, target); err != nil {
		return err
	}
	pkg, err := m.createRecoveryPackage(ctx, request, prepared.members, prepared.previousHash)
	if err != nil {
		return err
	}
	defer clearRecoveryPackage(&pkg)
	if err := m.renewLease(ctx, target); err != nil {
		return err
	}
	snapshot, err := m.store.GetEpochSecuritySnapshot(ctx, request.PlanExternalID)
	if err != nil {
		return err
	}
	if err := validateCommittedRecoveryPackage(snapshot, request, pkg, true); err != nil {
		return err
	}
	return m.publishMemberArtifacts(ctx, target, request, pkg, snapshot)
}

func (m *Manager) publishMemberArtifacts(ctx context.Context, target *EpochPlanTarget, request PlanRequest,
	pkg EncryptedRecoveryPackage, snapshot *EpochSecuritySnapshot) error {
	if snapshot == nil || snapshot.Root == nil || len(snapshot.ManifestCanonical) == 0 ||
		sha256.Sum256(snapshot.ManifestCanonical) != snapshot.ManifestHash ||
		snapshot.ManifestHash != target.Plan.ManifestHash || !validSecurityID(snapshot.ManifestPlatformAlgorithm) ||
		!validSecurityID(snapshot.ManifestPlatformKeyRef) || len(snapshot.ManifestPlatformSignature) == 0 ||
		snapshot.ManifestPlatformVerifiedAt.IsZero() || len(pkg.EncryptedShares) != len(snapshot.Deliveries) ||
		!bytes.Equal(snapshot.Root.AttestationSignature, pkg.ProviderAttestation) {
		return ErrBindingMismatch
	}
	deliveries := deliveryMap(snapshot.Deliveries)
	for _, share := range pkg.EncryptedShares {
		deliveryID := deterministicExternalID("share", request.PlanExternalID, share.MemberID)
		delivery, exists := deliveries[deliveryID]
		if !exists || delivery.MemberExternalID != share.MemberID || delivery.CiphertextHash != share.CiphertextHash {
			return ErrBindingMismatch
		}
		publish := MemberArtifactPublishRequest{CeremonyType: request.CeremonyType,
			OperationID: request.OperationID, PoolID: request.PoolID, Epoch: request.ToEpoch,
			DeliveryID: deliveryID, MemberID: share.MemberID, ShareIndex: share.ShareIndex,
			EncryptedShare: append([]byte(nil), share.Ciphertext...), CiphertextHash: share.CiphertextHash,
			ProviderCommitment: append([]byte(nil), share.ProviderCommitment...),
			ProviderProof:      append([]byte(nil), share.ProviderProof...),
			VSSAlgorithm:       pkg.VSSAlgorithm, VSSCommitment: append([]byte(nil), pkg.VSSCommitment...),
			VSSProof: append([]byte(nil), pkg.VSSProof...), VSSProofHash: sha256.Sum256(pkg.VSSProof),
			ManifestCanonical: append([]byte(nil), snapshot.ManifestCanonical...), ManifestHash: snapshot.ManifestHash,
			PlatformAlgorithm: snapshot.ManifestPlatformAlgorithm, PlatformKeyID: snapshot.ManifestPlatformKeyRef,
			PlatformSignature:  append([]byte(nil), snapshot.ManifestPlatformSignature...),
			PlatformVerifiedAt: snapshot.ManifestPlatformVerifiedAt,
			RootCommitmentHash: snapshot.Root.RootCommitmentHash, VSSCommitmentHash: snapshot.Root.VSSCommitmentHash,
			RootProviderID: snapshot.Root.Provider, RootAttestationRef: snapshot.Root.ProviderAttestationRef,
			RootAttestationKeyID: snapshot.Root.AttestationKeyID, RootAttestationDigest: snapshot.Root.AttestationDigest,
			RootAttestation:     append([]byte(nil), snapshot.Root.AttestationSignature...),
			RecoveryPackageHash: pkg.PackageHash, RecoveryRequestIntent: pkg.RequestIntentHash}
		if err := m.renewLease(ctx, target); err != nil {
			clearMemberArtifactPublish(&publish)
			return err
		}
		receipt, err := m.providers.MemberArtifacts.PublishArtifacts(ctx, publish)
		if err != nil {
			clearMemberArtifactPublish(&publish)
			return ErrProviderUnavailable
		}
		artifactHash := MemberArtifactDigest(publish)
		if receipt.CeremonyType != request.CeremonyType || receipt.OperationID != request.OperationID ||
			receipt.PoolID != request.PoolID || receipt.Epoch != request.ToEpoch ||
			receipt.DeliveryID != deliveryID || receipt.MemberID != share.MemberID ||
			receipt.ManifestHash != snapshot.ManifestHash || !validSecurityID(receipt.ReceiptID) ||
			receipt.ReceiptHash != artifactHash || len(receipt.ProviderProof) == 0 ||
			sha256.Sum256(receipt.ProviderProof) != receipt.ProviderProofDigest || receipt.PublishedAt.IsZero() ||
			!validSecurityID(receipt.ProviderProofAlgorithm) || !validSecurityID(receipt.ProviderProofKeyID) ||
			!validSecurityID(receipt.ProviderProofProtocolVersion) {
			clearMemberArtifactPublish(&publish)
			return ErrBindingMismatch
		}
		if err := m.providers.Attestation.VerifyMemberArtifactReceipt(ctx,
			MemberArtifactReceiptVerifyRequest{Request: publish, Receipt: receipt}); err != nil {
			clearMemberArtifactPublish(&publish)
			return ErrSignatureInvalid
		}
		if err := m.renewLease(ctx, target); err != nil {
			clearMemberArtifactPublish(&publish)
			return err
		}
		if err := m.store.CommitMemberArtifactReceipt(ctx, CommitMemberArtifactReceiptInput{
			Key: target.Operation.Key, LeaseOwner: m.config.LeaseOwner,
			FencingToken: target.Operation.FencingToken, Receipt: MemberArtifactReceipt{
				PlanExternalID: request.PlanExternalID, DeliveryExternalID: deliveryID,
				ManifestExternalID: request.ManifestExternalID, MemberExternalID: share.MemberID,
				ArtifactDigest: artifactHash, ReceiptID: receipt.ReceiptID, ReceiptDigest: receipt.ReceiptHash,
				ProviderProof:                append([]byte(nil), receipt.ProviderProof...),
				ProviderProofDigest:          receipt.ProviderProofDigest,
				ProviderProofAlgorithm:       receipt.ProviderProofAlgorithm,
				ProviderProofKeyID:           receipt.ProviderProofKeyID,
				ProviderProofProtocolVersion: receipt.ProviderProofProtocolVersion,
				PublishedAt:                  receipt.PublishedAt,
			},
		}); err != nil {
			clearMemberArtifactPublish(&publish)
			return err
		}
		clearMemberArtifactPublish(&publish)
		if err := m.renewLease(ctx, target); err != nil {
			return err
		}
	}
	return nil
}

func clearMemberArtifactPublish(value *MemberArtifactPublishRequest) {
	if value == nil {
		return
	}
	clear(value.EncryptedShare)
	clear(value.ProviderCommitment)
	clear(value.ProviderProof)
	clear(value.VSSCommitment)
	clear(value.VSSProof)
	clear(value.ManifestCanonical)
	clear(value.PlatformSignature)
	clear(value.RootAttestation)
}

func MemberArtifactDigest(value MemberArtifactPublishRequest) [sha256.Size]byte {
	var encoded bytes.Buffer
	writeSecurityString(&encoded, "trusted-pool/member-ceremony-artifact/v1")
	writeSecurityString(&encoded, string(value.CeremonyType))
	writeSecurityString(&encoded, value.OperationID)
	writeSecurityString(&encoded, value.PoolID)
	writeSecurityUint64(&encoded, value.Epoch)
	writeSecurityString(&encoded, value.DeliveryID)
	writeSecurityString(&encoded, value.MemberID)
	writeSecurityUint16(&encoded, value.ShareIndex)
	encoded.Write(value.CiphertextHash[:])
	providerCommitmentHash, providerProofHash := sha256.Sum256(value.ProviderCommitment), sha256.Sum256(value.ProviderProof)
	encoded.Write(providerCommitmentHash[:])
	encoded.Write(providerProofHash[:])
	writeSecurityString(&encoded, value.VSSAlgorithm)
	encoded.Write(value.VSSCommitmentHash[:])
	encoded.Write(value.VSSProofHash[:])
	encoded.Write(value.ManifestHash[:])
	writeSecurityString(&encoded, value.PlatformAlgorithm)
	writeSecurityString(&encoded, value.PlatformKeyID)
	platformSignatureHash := sha256.Sum256(value.PlatformSignature)
	encoded.Write(platformSignatureHash[:])
	writeSecurityString(&encoded, value.PlatformVerifiedAt.UTC().Format(time.RFC3339Nano))
	encoded.Write(value.RootCommitmentHash[:])
	writeSecurityString(&encoded, value.RootProviderID)
	writeSecurityString(&encoded, value.RootAttestationRef)
	writeSecurityString(&encoded, value.RootAttestationKeyID)
	encoded.Write(value.RootAttestationDigest[:])
	rootAttestationHash := sha256.Sum256(value.RootAttestation)
	encoded.Write(rootAttestationHash[:])
	encoded.Write(value.RecoveryPackageHash[:])
	encoded.Write(value.RecoveryRequestIntent[:])
	return sha256.Sum256(encoded.Bytes())
}

func (m *Manager) CommitMemberSignatures(ctx context.Context, request PlanRequest,
	submitted []SubmittedMemberSignature) (*PlanProgress, error) {
	target, _, err := m.resume(ctx, request)
	if err != nil {
		return nil, err
	}
	if planStatusAtLeast(target.Plan.Status, planStatusManifestSigned) {
		return planProgress(target, target.Plan), nil
	}
	if target.Plan.Status != planStatusManifestDraft || len(submitted) < int(target.Plan.GovernanceThreshold) {
		return nil, ErrInvalidState
	}
	snapshot, err := m.store.GetEpochSecuritySnapshot(ctx, request.PlanExternalID)
	if err != nil {
		return nil, err
	}
	if err := validateSecuritySnapshot(snapshot, target.Plan, planStatusManifestDraft, request.Members); err != nil {
		return nil, err
	}
	members := epochMemberMap(recoveryMembersFromEpoch(snapshot.Members))
	inputs := make([]ManifestMemberSignature, len(submitted))
	for index, item := range submitted {
		if index > 0 && submitted[index-1].MemberID >= item.MemberID {
			return nil, ErrDuplicate
		}
		member, exists := members[item.MemberID]
		if !exists {
			return nil, ErrBindingMismatch
		}
		messageHash, err := VerifyMemberManifestApproval(ctx, m.providers.MemberSignatures, member,
			MemberManifestApproval{Version: 1, CeremonyType: request.CeremonyType,
				OperationID: request.OperationID, PoolID: request.PoolID, Epoch: request.ToEpoch,
				MemberID: item.MemberID, ManifestHash: snapshot.ManifestHash},
			item.Algorithm, item.KeyID, item.Signature)
		if err != nil {
			return nil, err
		}
		if err := m.renewLease(ctx, target); err != nil {
			return nil, err
		}
		inputs[index] = ManifestMemberSignature{MemberExternalID: item.MemberID, Algorithm: item.Algorithm,
			KeyID: item.KeyID, MessageHash: messageHash, Signature: append([]byte(nil), item.Signature...),
			VerifiedAt: m.config.Now().UTC()}
	}
	plan, err := m.store.CommitManifest(ctx, CommitManifestInput{Key: target.Operation.Key,
		LeaseOwner: m.config.LeaseOwner, FencingToken: target.Operation.FencingToken, Signatures: inputs})
	for index := range inputs {
		clear(inputs[index].Signature)
	}
	if err != nil {
		return nil, err
	}
	return planProgress(target, plan), nil
}

func (m *Manager) CommitShareAcknowledgements(ctx context.Context, request PlanRequest,
	submitted []SubmittedShareAcknowledgement) (*PlanProgress, error) {
	target, _, err := m.resume(ctx, request)
	if err != nil {
		return nil, err
	}
	if planStatusAtLeast(target.Plan.Status, planStatusAcknowledged) {
		return planProgress(target, target.Plan), nil
	}
	if target.Plan.Status != planStatusManifestSigned || len(submitted) != target.Plan.ExpectedMemberCount {
		return nil, ErrInvalidState
	}
	snapshot, err := m.store.GetEpochSecuritySnapshot(ctx, request.PlanExternalID)
	if err != nil {
		return nil, err
	}
	if err := validateSecuritySnapshot(snapshot, target.Plan, planStatusManifestSigned, request.Members); err != nil {
		return nil, err
	}
	members, deliveries := epochMemberMap(recoveryMembersFromEpoch(snapshot.Members)), deliveryMap(snapshot.Deliveries)
	inputs := make([]ShareAcknowledgementInput, len(submitted))
	for index, item := range submitted {
		if index > 0 && submitted[index-1].MemberID >= item.MemberID {
			return nil, ErrDuplicate
		}
		member, memberExists := members[item.MemberID]
		delivery, deliveryExists := deliveries[item.DeliveryID]
		if !memberExists || !deliveryExists || delivery.MemberExternalID != item.MemberID || delivery.Acknowledged ||
			!item.VerifiedCommitment {
			return nil, ErrBindingMismatch
		}
		ack := ShareAcknowledgement{Version: 1, CeremonyType: request.CeremonyType,
			OperationID: request.OperationID, DeliveryID: item.DeliveryID, PoolID: request.PoolID,
			Epoch: request.ToEpoch, MemberID: item.MemberID, ShareIndex: delivery.ShareIndex,
			CiphertextHash: delivery.CiphertextHash, ManifestHash: snapshot.ManifestHash,
			RootCommitmentHash: delivery.RootCommitmentHash, VSSCommitmentHash: delivery.VSSCommitmentHash,
			VerifiedCommitment: true}
		messageHash, err := VerifyShareAcknowledgementSignature(ctx, m.providers.MemberSignatures, member,
			ack, item.Algorithm, item.KeyID, item.Signature)
		if err != nil {
			return nil, err
		}
		if err := m.renewLease(ctx, target); err != nil {
			return nil, err
		}
		inputs[index] = ShareAcknowledgementInput{DeliveryExternalID: item.DeliveryID,
			MemberExternalID: item.MemberID, ManifestHash: snapshot.ManifestHash,
			RootCommitmentHash: delivery.RootCommitmentHash, VSSCommitmentHash: delivery.VSSCommitmentHash,
			VerifiedCommitment: true, Algorithm: item.Algorithm, KeyID: item.KeyID,
			MessageHash: messageHash, Signature: append([]byte(nil), item.Signature...), VerifiedAt: m.config.Now().UTC()}
	}
	plan, err := m.store.CommitShareAcknowledgements(ctx, CommitShareAcknowledgementsInput{
		Key: target.Operation.Key, LeaseOwner: m.config.LeaseOwner, FencingToken: target.Operation.FencingToken,
		Acknowledgements: inputs})
	for index := range inputs {
		clear(inputs[index].Signature)
	}
	if err != nil {
		return nil, err
	}
	return planProgress(target, plan), nil
}

// StageCredentialBatches 调用外部 Epoch provider 生成完整双包装，HTTP 不接受 DEK 或包装结果。
func (m *Manager) StageCredentialBatches(ctx context.Context, request PlanRequest,
	payloads []StagedBatchPayload) (*PlanProgress, error) {
	defer clearBatchPayloads(payloads)
	target, _, err := m.resume(ctx, request)
	if err != nil {
		return nil, err
	}
	if planStatusAtLeast(target.Plan.Status, planStatusBatchesStaged) {
		return planProgress(target, target.Plan), nil
	}
	if target.Plan.Status != planStatusAcknowledged || len(payloads) != target.Plan.ExpectedResourceCount*4 {
		return nil, ErrInvalidState
	}
	snapshot, err := m.store.GetEpochSecuritySnapshot(ctx, request.PlanExternalID)
	if err != nil {
		return nil, err
	}
	if snapshot == nil || snapshot.Root == nil || snapshot.Root.Provider != m.config.ExpectedRootProviderID ||
		snapshot.Root.ExternalID != request.RootArtifactExternalID ||
		snapshot.Root.RequestIntentHash == ([sha256.Size]byte{}) || snapshot.Root.RecoveryPackageHash == ([sha256.Size]byte{}) {
		return nil, ErrBindingMismatch
	}
	root := snapshot.Root
	expected := expectedToBatchMap(request.Accounts)
	batches := make([]StagedCredentialBatch, len(payloads))
	for index, payload := range payloads {
		key := payload.ResourceAccountID + "\x00" + string(payload.BatchType)
		planBatch, exists := expected[key]
		if !exists || payload.BatchID != planBatch.ToBatchID || payload.BatchVersion != planBatch.ToBatchVersion ||
			payload.AccountRef != expectedAccountRef(request.Accounts, payload.ResourceAccountID) ||
			len(bytes.TrimSpace(payload.Payload)) == 0 || !json.Valid(payload.Payload) ||
			index > 0 && batchPayloadSortKey(payloads[index-1]) >= batchPayloadSortKey(payload) {
			return nil, ErrInvalidData
		}
		providerRequest := EpochCredentialBatchRequest{CeremonyType: request.CeremonyType,
			OperationID: request.OperationID, PoolID: request.PoolID, Epoch: request.ToEpoch,
			BatchID: payload.BatchID, ResourceAccountID: payload.ResourceAccountID,
			AccountRef: payload.AccountRef, BatchType: payload.BatchType, BatchVersion: payload.BatchVersion,
			RootPublicHandle: root.RootHandle, RootKeyVersion: root.RootKeyVersion,
			RootPublicFingerprint: root.EpochRecoveryKeyFingerprint, RootWrapDomain: root.WrapDomain,
			RootWrapAlgorithm: root.WrapAlgorithm, Payload: append([]byte(nil), payload.Payload...)}
		providerRequest.RequestHash = EpochCredentialBatchRequestHash(providerRequest)
		if err := m.renewLease(ctx, target); err != nil {
			clear(providerRequest.Payload)
			return nil, err
		}
		result, err := m.providers.CredentialBatches.SealCredentialBatch(ctx, providerRequest)
		if err != nil {
			clear(providerRequest.Payload)
			return nil, ErrProviderUnavailable
		}
		if err := VerifyStagedCredentialBatch(ctx, m.providers.Attestation, providerRequest, result); err != nil {
			clear(providerRequest.Payload)
			clearStagedBatch(&result.Batch)
			clear(result.ProviderProof)
			return nil, err
		}
		if err := validateStagedBatchPlanBinding(planBatch, result.Batch); err != nil {
			clear(providerRequest.Payload)
			clearStagedBatch(&result.Batch)
			clear(result.ProviderProof)
			return nil, err
		}
		if err := m.renewLease(ctx, target); err != nil {
			clear(providerRequest.Payload)
			clearStagedBatch(&result.Batch)
			clear(result.ProviderProof)
			return nil, err
		}
		clear(providerRequest.Payload)
		batches[index] = cloneStagedBatch(result.Batch)
		clearStagedBatch(&result.Batch)
		clear(result.ProviderProof)
	}
	_, _, batchSetHash, err := manifestBatchBindings(request.Accounts)
	if err != nil {
		clearStagedBatches(batches)
		return nil, err
	}
	if err := m.renewLease(ctx, target); err != nil {
		clearStagedBatches(batches)
		return nil, err
	}
	plan, err := m.store.CommitStagedBatches(ctx, CommitStagedBatchesInput{Key: target.Operation.Key,
		LeaseOwner: m.config.LeaseOwner, FencingToken: target.Operation.FencingToken,
		BatchSetHash: batchSetHash, Batches: batches})
	clearStagedBatches(batches)
	if err != nil {
		return nil, err
	}
	return planProgress(target, plan), nil
}

func validateStagedBatchPlanBinding(plan ControlBatchPlan, batch StagedCredentialBatch) error {
	expectedCiphertext, ciphertextErr := decodeOptionalHash(plan.ToCiphertextHash)
	expectedRecoveryBinding, recoveryErr := decodeOptionalHash(plan.ToRecoveryWrapHash)
	if ciphertextErr != nil || recoveryErr != nil || sha256.Sum256(batch.Ciphertext) != expectedCiphertext ||
		batch.RecoveryBindingHash != expectedRecoveryBinding {
		return ErrBindingMismatch
	}
	return nil
}

func (m *Manager) VerifyEvidenceAndMarkReady(ctx context.Context, request PlanRequest) (*PlanProgress, error) {
	target, _, err := m.resume(ctx, request)
	if err != nil {
		return nil, err
	}
	if target.Plan.Status == planStatusReady {
		return planProgress(target, target.Plan), nil
	}
	if target.Plan.Status != planStatusBatchesStaged {
		return nil, ErrInvalidState
	}
	bindings, _, _, err := manifestBatchBindings(request.Accounts)
	if err != nil {
		return nil, err
	}
	byAccount := make(map[string][]ControlEvidenceBatchRef, len(request.Accounts))
	for _, binding := range bindings {
		byAccount[binding.ResourceAccountExternalID] = append(byAccount[binding.ResourceAccountExternalID],
			ControlEvidenceBatchRef{EpochRole: binding.EpochRole, BatchType: binding.BatchType,
				BatchExternalID: binding.BatchExternalID})
	}
	for _, account := range request.Accounts {
		if err := m.renewLease(ctx, target); err != nil {
			return nil, err
		}
		key := OperationKey{ClientID: m.config.ClientID,
			OperationID: deterministicExternalID("evidence-op", request.OperationID, account.AccountID)}
		input := IssueControlEvidenceInput{Key: key, LeaseOwner: m.config.LeaseOwner,
			FencingToken: target.Operation.FencingToken, EvidenceExternalID: account.ControlEvidenceID,
			PlanExternalID: request.PlanExternalID, ResourceExternalID: account.AccountID,
			ProviderAttestationRef:             account.ControlEvidenceID,
			ProviderAttestationDigest:          mustDecodeHash(account.ProviderAttestationDigest),
			ProviderAttestationIssuer:          account.ProviderAttestationIssuer,
			ProviderAttestationKeyID:           account.ProviderAttestationKeyID,
			ProviderAttestationVersion:         account.ProviderAttestationVersion,
			ProviderAttestationAlgorithm:       account.ProviderAttestationAlgorithm,
			ProviderAttestationSignature:       append([]byte(nil), account.ProviderAttestationSignature...),
			ProviderAttestationProtocolVersion: account.ProviderAttestationProtocolVersion,
			BatchReferences:                    byAccount[account.AccountID]}
		snapshot, err := controlEvidenceSnapshot(input)
		if err != nil {
			return nil, err
		}
		input.RequestSnapshot, input.RequestHash = snapshot, sha256.Sum256(snapshot)
		if err := m.store.IssueControlEvidence(ctx, input); err != nil {
			return nil, err
		}
	}
	if err := m.renewLease(ctx, target); err != nil {
		return nil, err
	}
	plan, err := m.store.MarkEpochPlanReady(ctx, MarkEpochPlanReadyInput{Key: target.Operation.Key,
		LeaseOwner: m.config.LeaseOwner, FencingToken: target.Operation.FencingToken})
	if err != nil {
		return nil, err
	}
	return planProgress(target, plan), nil
}

func (m *Manager) Get(ctx context.Context, planExternalID string) (*PlanProgress, error) {
	if m == nil || m.store == nil || !validSecurityID(planExternalID) {
		return nil, ErrInvalidData
	}
	target, err := m.store.GetEpochPlanProgress(ctx, planExternalID)
	if err != nil {
		return nil, err
	}
	progress := planProgress(target, target.Plan)
	if progress == nil || progress.FencingToken <= 0 {
		return nil, ErrInvalidState
	}
	return progress, nil
}

type preparedPlan struct {
	members      []RecoveryMember
	previousHash [sha256.Size]byte
	attestation  VerifiedProviderAttestation
	snapshot     []byte
	requestHash  [sha256.Size]byte
}

func (m *Manager) resume(ctx context.Context, request PlanRequest) (*EpochPlanTarget, preparedPlan, error) {
	if m == nil || m.store == nil {
		return nil, preparedPlan{}, ErrInvalidData
	}
	if err := m.Ready(ctx); err != nil {
		return nil, preparedPlan{}, err
	}
	plan, getErr := m.store.GetEpochPlan(ctx, request.PlanExternalID)
	if getErr != nil && !errors.Is(getErr, ErrNotFound) {
		return nil, preparedPlan{}, getErr
	}
	prepared, err := m.prepareIntent(ctx, request, plan)
	if err != nil {
		return nil, preparedPlan{}, err
	}
	input := BeginEpochPlanInput{Key: OperationKey{ClientID: m.config.ClientID, OperationID: request.OperationID},
		CeremonyType: request.CeremonyType, PlanExternalID: request.PlanExternalID,
		PoolExternalID: request.PoolID, FromEpoch: request.FromEpoch, ToEpoch: request.ToEpoch,
		GovernanceThreshold: request.GovernanceThreshold, RecoveryThreshold: request.RecoveryThreshold,
		PreviousManifestHash: prepared.previousHash, Members: cloneEpochMembers(request.Members),
		SeatFreezes:     append([]EpochSeatFreeze(nil), request.SeatFreezes...),
		Replacements:    append([]EpochSeatReplacement(nil), request.Replacements...),
		Accounts:        append([]ResourceAccountPlan(nil), request.Accounts...),
		PortableProfile: m.portableEvidenceProfile(),
		RequestHash:     prepared.requestHash, RequestSnapshot: prepared.snapshot,
		LeaseOwner: m.config.LeaseOwner, LeaseDuration: m.config.LeaseDuration}
	input.BootstrapAttestationRef = prepared.attestation.Reference
	input.BootstrapAttestationDigest = prepared.attestation.CanonicalDigest
	input.BootstrapAttestationIssuer = prepared.attestation.Issuer
	input.BootstrapAttestationKeyID = prepared.attestation.VerificationKeyID
	input.BootstrapAttestationSignature = append([]byte(nil), request.ProviderAttestationEnvelope...)
	input.BootstrapAttestationVersion = uint64(prepared.attestation.Version)
	var target *EpochPlanTarget
	if errors.Is(getErr, ErrNotFound) {
		if request.ExpectedFencingToken != 0 {
			clearEpochMembers(input.Members)
			clear(input.BootstrapAttestationSignature)
			return nil, preparedPlan{}, ErrStaleFence
		}
		target, _, err = m.store.BeginEpochPlan(ctx, input)
	} else if getErr != nil {
		err = getErr
	} else {
		if request.ExpectedFencingToken <= 0 {
			clearEpochMembers(input.Members)
			clear(input.BootstrapAttestationSignature)
			return nil, preparedPlan{}, ErrStaleFence
		}
		operation, acquireErr := m.store.AcquireEpochPlanLease(ctx, AcquireEpochPlanLeaseInput{
			Key:        OperationKey{ClientID: m.config.ClientID, OperationID: request.OperationID},
			LeaseOwner: m.config.LeaseOwner, ExpectedFencingToken: request.ExpectedFencingToken,
			LeaseDuration: m.config.LeaseDuration,
		})
		if acquireErr != nil {
			err = acquireErr
		} else {
			plan, err = m.store.GetEpochPlan(ctx, request.PlanExternalID)
			target = &EpochPlanTarget{Operation: operation, Plan: plan}
		}
	}
	clearEpochMembers(input.Members)
	clear(input.BootstrapAttestationSignature)
	if err != nil {
		return nil, preparedPlan{}, err
	}
	if err := m.validateTarget(target, request, prepared); err != nil {
		return nil, preparedPlan{}, err
	}
	return target, prepared, nil
}

// renewLease 在外部调用前后执行 CAS heartbeat；只有数据库返回的新 fence 才能用于后续提交。
func (m *Manager) renewLease(ctx context.Context, target *EpochPlanTarget) error {
	if target == nil || target.Operation == nil || target.Plan == nil {
		return ErrInvalidData
	}
	operation, err := m.store.AcquireEpochPlanLease(ctx, AcquireEpochPlanLeaseInput{
		Key: target.Operation.Key, LeaseOwner: m.config.LeaseOwner,
		ExpectedFencingToken: target.Operation.FencingToken, LeaseDuration: m.config.LeaseDuration,
	})
	if err != nil {
		return err
	}
	if operation == nil || operation.Key != target.Operation.Key || operation.RequestHash != target.Operation.RequestHash ||
		operation.LeaseOwner != m.config.LeaseOwner || operation.FencingToken < target.Operation.FencingToken ||
		operation.LeaseExpiresAt == nil || !operation.LeaseExpiresAt.After(m.config.Now()) {
		return ErrStaleFence
	}
	target.Operation = operation
	return nil
}

func (m *Manager) prepareIntent(ctx context.Context, request PlanRequest, storedPlan *StoredEpochPlan) (preparedPlan, error) {
	var result preparedPlan
	if !validSecurityID(request.OperationID) || !validSecurityID(request.PlanExternalID) ||
		!validSecurityID(request.RootRequestID) || !validSecurityID(request.RootArtifactExternalID) ||
		!validSecurityID(request.ManifestExternalID) || !validSecurityID(request.PoolID) ||
		request.FromEpoch == 0 || request.ToEpoch != request.FromEpoch+1 ||
		request.GovernanceThreshold == 0 || request.RecoveryThreshold == 0 ||
		request.RecoveryThreshold > request.GovernanceThreshold ||
		int(request.GovernanceThreshold) > len(request.Members) || len(request.ProviderAttestationEnvelope) == 0 {
		return result, ErrInvalidData
	}
	previous, err := decodeOptionalHash(request.PreviousManifestHash)
	if err != nil {
		return result, err
	}
	result.previousHash = previous
	members := make([]RecoveryMember, len(request.Members))
	for index, member := range request.Members {
		members[index] = RecoveryMember{MemberID: member.MemberExternalID, Role: member.Role,
			ShareIndex: member.ShareIndex, SigningAlgorithm: member.SigningAlgorithm,
			SigningKeyID: member.SigningKeyID, SigningKeyFingerprint: member.SigningKeyFingerprint,
			SigningPublicKey:    append([]byte(nil), member.SigningPublicKey...),
			EncryptionAlgorithm: member.RecoveryKeyAlgorithm, EncryptionKeyID: member.RecoveryKeyID,
			EncryptionKeyFingerprint: member.RecoveryKeyFingerprint,
			EncryptionPublicKey:      append([]byte(nil), member.RecoveryEncryptionPublicKey...)}
	}
	sort.Slice(members, func(i, j int) bool { return members[i].MemberID < members[j].MemberID })
	rootRequest := RecoveryPackageRequest{Version: 1, CeremonyType: request.CeremonyType,
		RequestID: request.RootRequestID, OperationID: request.OperationID, PoolID: request.PoolID,
		FromEpoch: request.FromEpoch, ToEpoch: request.ToEpoch, FromEpochStatus: epochStatusActive,
		FromGovernanceState: sourceGovernanceState(request.CeremonyType), RecoveryThreshold: request.RecoveryThreshold,
		PreviousManifestHash: previous, ExpectedProviderID: m.config.ExpectedRootProviderID,
		TrustProfile: m.config.RootTrustProfile, Members: members}
	rootRequest.IntentHash, err = RecoveryIntentHash(rootRequest)
	if err != nil {
		return result, err
	}
	if err := ValidateRecoveryPackageRequest(rootRequest); err != nil {
		return result, err
	}
	seatPlans, replacements, err := planCollections(request)
	if err != nil {
		return result, err
	}
	intent := ProviderAttestationIntent{Version: 1, CeremonyType: request.CeremonyType,
		OperationID: request.OperationID, PoolID: request.PoolID, FromEpoch: request.FromEpoch,
		ToEpoch: request.ToEpoch, FromEpochStatus: epochStatusActive,
		FromGovernanceState: sourceGovernanceState(request.CeremonyType), PreviousManifestHash: previous,
		Replacements: replacements, Seats: seatPlans, Accounts: request.Accounts}
	var attestation VerifiedProviderAttestation
	if storedPlan == nil {
		attestation, err = VerifyProviderControlAttestation(ctx, m.providers.Attestation,
			ProviderAttestationVerifyRequest{Intent: intent, Envelope: request.ProviderAttestationEnvelope}, m.config.Now().UTC())
		if err != nil {
			return result, err
		}
		for _, member := range request.Members {
			if err := VerifyMemberKeyPossession(ctx, m.providers.MemberSignatures, MemberKeyProofIntent{
				Version: 1, CeremonyType: request.CeremonyType, OperationID: request.OperationID,
				PoolID: request.PoolID, Epoch: request.ToEpoch, MemberID: member.MemberExternalID,
				Purpose: "SIGNING", Algorithm: member.SigningProofAlgorithm,
				KeyID: member.SigningKeyID, KeyFingerprint: member.SigningKeyFingerprint,
			}, member.SigningPublicKey, member.SigningProof); err != nil {
				return result, err
			}
			if err := VerifyMemberKeyPossession(ctx, m.providers.MemberSignatures, MemberKeyProofIntent{
				Version: 1, CeremonyType: request.CeremonyType, OperationID: request.OperationID,
				PoolID: request.PoolID, Epoch: request.ToEpoch, MemberID: member.MemberExternalID,
				Purpose: "RECOVERY_ENCRYPTION", Algorithm: member.RecoveryKeyProofAlgorithm,
				KeyID: member.RecoveryKeyID, KeyFingerprint: member.RecoveryKeyFingerprint,
			}, member.RecoveryEncryptionPublicKey, member.RecoveryKeyProof); err != nil {
				return result, err
			}
		}
	} else {
		if storedPlan.ExternalID != request.PlanExternalID || storedPlan.CeremonyType != request.CeremonyType ||
			!validSecurityID(storedPlan.CeremonyAttestationRef) ||
			!nonzeroSecurityHash(storedPlan.CeremonyAttestationDigest) ||
			!validSecurityID(storedPlan.CeremonyAttestationIssuer) ||
			!validSecurityID(storedPlan.CeremonyAttestationKeyID) || storedPlan.CeremonyAttestationVersion == 0 ||
			storedPlan.CeremonyAttestationVersion > uint64(^uint16(0)) {
			return result, ErrBindingMismatch
		}
		purpose := rotationAttestationPurpose
		if request.CeremonyType == CeremonyBootstrap {
			purpose = bootstrapAttestationPurpose
		}
		attestation = VerifiedProviderAttestation{Version: uint16(storedPlan.CeremonyAttestationVersion),
			CeremonyType: request.CeremonyType, Purpose: purpose, OperationID: request.OperationID,
			PoolID: request.PoolID, FromEpoch: request.FromEpoch, ToEpoch: request.ToEpoch,
			FromEpochStatus: epochStatusActive, FromGovernanceState: sourceGovernanceState(request.CeremonyType),
			PreviousManifestHash: previous, Replacements: replacements, Seats: seatPlans, Accounts: request.Accounts,
			Issuer: storedPlan.CeremonyAttestationIssuer, VerificationKeyID: storedPlan.CeremonyAttestationKeyID,
			Reference: storedPlan.CeremonyAttestationRef, CanonicalDigest: storedPlan.CeremonyAttestationDigest}
	}
	profile := m.portableEvidenceProfile()
	if storedPlan != nil && !samePortableEvidenceProfile(storedPlan.PortableProfile, profile) {
		return result, ErrBindingMismatch
	}
	snapshotRequest := request
	snapshotRequest.ExpectedFencingToken = 0
	snapshot, err := canonicalIntentJSON(struct {
		Version         uint16                   `json:"version"`
		Request         PlanRequest              `json:"request"`
		PortableProfile *PortableEvidenceProfile `json:"portable_profile,omitempty"`
	}{Version: 2, Request: snapshotRequest, PortableProfile: profile})
	if err != nil {
		return result, err
	}
	result.members, result.attestation, result.snapshot = members, attestation, snapshot
	result.requestHash = sha256.Sum256(snapshot)
	return result, nil
}

func (m *Manager) portableEvidenceProfile() *PortableEvidenceProfile {
	if !m.config.PortableEvidence {
		return nil
	}
	return &PortableEvidenceProfile{
		FormatVersion: PortableBundleFormatV1, RootTrustProfileID: m.config.RootTrustProfile,
		CryptoSuiteID: m.config.RecoveryCryptoSuiteID, ProviderProofProfile: ProviderProofStatementV1,
		CeremonyAttestationAlgorithm: PortableSignatureAlgorithm,
		PlatformSignatureDomain:      PlatformManifestSignatureV2,
	}
}

func samePortableEvidenceProfile(left, right *PortableEvidenceProfile) bool {
	if left == nil || right == nil {
		return left == nil && right == nil
	}
	return *left == *right
}

func (m *Manager) createRecoveryPackage(ctx context.Context, request PlanRequest,
	members []RecoveryMember, previous [sha256.Size]byte) (EncryptedRecoveryPackage, error) {
	rootRequest := RecoveryPackageRequest{Version: 1, CeremonyType: request.CeremonyType,
		RequestID: request.RootRequestID, OperationID: request.OperationID, PoolID: request.PoolID,
		FromEpoch: request.FromEpoch, ToEpoch: request.ToEpoch, FromEpochStatus: epochStatusActive,
		FromGovernanceState: sourceGovernanceState(request.CeremonyType), PreviousManifestHash: previous,
		ExpectedProviderID: m.config.ExpectedRootProviderID, TrustProfile: m.config.RootTrustProfile,
		RecoveryThreshold: request.RecoveryThreshold, Members: cloneRecoveryMembers(members)}
	var err error
	rootRequest.IntentHash, err = RecoveryIntentHash(rootRequest)
	if err != nil {
		return EncryptedRecoveryPackage{}, err
	}
	pkg, err := m.providers.Root.CreateEncryptedPackage(ctx, rootRequest)
	if err != nil {
		return EncryptedRecoveryPackage{}, ErrProviderUnavailable
	}
	if err := VerifyRecoveryPackage(ctx, m.providers.Attestation, rootRequest, pkg); err != nil {
		clearRecoveryPackage(&pkg)
		return EncryptedRecoveryPackage{}, err
	}
	return pkg, nil
}

func (m *Manager) buildManifest(ctx context.Context, request PlanRequest, prepared preparedPlan,
	pkg EncryptedRecoveryPackage) (CanonicalManifest, []StagedBatchBinding, [sha256.Size]byte, error) {
	manifestMembers := make([]ManifestMember, len(prepared.members))
	manifestShares := make([]ManifestEncryptedShare, len(pkg.EncryptedShares))
	for index, member := range prepared.members {
		manifestMembers[index] = ManifestMember{MemberID: member.MemberID, Role: member.Role,
			ShareIndex: member.ShareIndex, SigningAlgorithm: member.SigningAlgorithm,
			SigningKeyID: member.SigningKeyID, SigningKeyFingerprint: hex.EncodeToString(member.SigningKeyFingerprint[:]),
			SigningPublicKey:            append([]byte(nil), member.SigningPublicKey...),
			RecoveryEncryptionAlgorithm: member.EncryptionAlgorithm, RecoveryEncryptionKeyID: member.EncryptionKeyID,
			RecoveryEncryptionKeyHash:   hex.EncodeToString(member.EncryptionKeyFingerprint[:]),
			RecoveryEncryptionPublicKey: append([]byte(nil), member.EncryptionPublicKey...)}
		share := pkg.EncryptedShares[index]
		manifestShares[index] = ManifestEncryptedShare{MemberID: share.MemberID, ShareIndex: share.ShareIndex,
			CiphertextHash:    hex.EncodeToString(share.CiphertextHash[:]),
			ProviderProofHash: hashHexBytes(share.ProviderProof), ProviderCommitment: hashHexBytes(share.ProviderCommitment)}
	}
	seats, replacements, err := planCollections(request)
	if err != nil {
		return CanonicalManifest{}, nil, [sha256.Size]byte{}, err
	}
	bindings, setHashText, batchSetHash, err := manifestBatchBindings(request.Accounts)
	if err != nil {
		return CanonicalManifest{}, nil, [sha256.Size]byte{}, err
	}
	purpose := rotationAttestationPurpose
	if request.CeremonyType == CeremonyBootstrap {
		purpose = bootstrapAttestationPurpose
	}
	previousText := hex.EncodeToString(prepared.previousHash[:])
	if request.CeremonyType == CeremonyBootstrap {
		previousText = ""
	}
	payload := ManifestPayload{ProtocolVersion: ProtocolVersionV1, CeremonyType: request.CeremonyType,
		OperationID: request.OperationID, PoolID: request.PoolID, FromEpoch: request.FromEpoch,
		FromEpochStatus: epochStatusActive, FromGovernanceState: sourceGovernanceState(request.CeremonyType),
		Epoch: request.ToEpoch, CreatedAt: pkg.CreatedAt.UTC().Format(time.RFC3339Nano),
		GovernanceThreshold: request.GovernanceThreshold, RecoveryThreshold: request.RecoveryThreshold,
		RequiredShareAcknowledges: uint16(len(prepared.members)), PreviousManifestHash: previousText,
		ProviderAttestationSetHash: setHashText,
		CeremonyAttestationDigest:  hex.EncodeToString(prepared.attestation.CanonicalDigest[:]),
		CeremonyAttestationPurpose: purpose, CeremonyAttestationIssuer: prepared.attestation.Issuer,
		CeremonyAttestationKeyID:     prepared.attestation.VerificationKeyID,
		CeremonyAttestationReference: prepared.attestation.Reference,
		CeremonyAttestationVersion:   uint64(prepared.attestation.Version),
		Members:                      manifestMembers, Seats: seats, Replacements: replacements,
		Accounts: request.Accounts, EncryptedShares: manifestShares,
		RecoveryRoot: ManifestRootBinding{PublicAlgorithm: pkg.RootPublicAlgorithm,
			PublicHandle: pkg.RootPublicHandle, PublicFingerprint: hex.EncodeToString(pkg.RootPublicFingerprint[:]),
			WrapDomain: pkg.RootWrapDomain, WrapAlgorithm: pkg.RootWrapAlgorithm,
			ProviderID: pkg.ProviderID, KeyVersion: pkg.RootKeyVersion,
			PrivateCommitmentHash: hashHexBytes(pkg.RootPrivateCommitment), VSSAlgorithm: pkg.VSSAlgorithm,
			VSSCommitmentHash: hashHexBytes(pkg.VSSCommitment), VSSProofHash: hashHexBytes(pkg.VSSProof),
			PackageHash: hex.EncodeToString(pkg.PackageHash[:])}}
	manifest, err := BuildCanonicalManifest(ctx, m.providers.Canonicalizer, payload)
	return manifest, bindings, batchSetHash, err
}

func (m *Manager) validateTarget(target *EpochPlanTarget, request PlanRequest, prepared preparedPlan) error {
	if target == nil || target.Operation == nil || target.Plan == nil || target.Operation.Key.ClientID != m.config.ClientID ||
		target.Operation.Key.OperationID != request.OperationID || target.Operation.RequestHash != prepared.requestHash ||
		target.Operation.LeaseOwner != m.config.LeaseOwner || target.Operation.FencingToken <= 0 ||
		target.Operation.LeaseExpiresAt == nil || !target.Operation.LeaseExpiresAt.After(m.config.Now()) ||
		target.Plan.ExternalID != request.PlanExternalID || target.Plan.PoolExternalID != request.PoolID ||
		target.Plan.CeremonyType != request.CeremonyType || target.Plan.FromEpoch != request.FromEpoch ||
		target.Plan.ToEpoch != request.ToEpoch || target.Plan.PreviousManifestHash != prepared.previousHash ||
		target.Plan.GovernanceThreshold != request.GovernanceThreshold || target.Plan.RecoveryThreshold != request.RecoveryThreshold {
		return ErrHashDrift
	}
	if !validPlanStatus(target.Plan.Status) {
		return ErrInvalidState
	}
	return nil
}

func planCollections(request PlanRequest) ([]SeatPlan, []OwnerReplacementPlan, error) {
	seats := append([]SeatPlan(nil), request.Seats...)
	freezes := make(map[string]EpochSeatFreeze, len(request.SeatFreezes))
	for index, freeze := range request.SeatFreezes {
		if index > 0 && request.SeatFreezes[index-1].SeatExternalID >= freeze.SeatExternalID {
			return nil, nil, ErrDuplicate
		}
		freezes[freeze.SeatExternalID] = freeze
	}
	for index := range seats {
		freeze, exists := freezes[seats[index].SeatID]
		if !exists || seats[index].ExpectedAssignmentEpoch != freeze.ExpectedAssignmentEpoch ||
			seats[index].FreezeOperationID != freeze.FreezeOperationID ||
			seats[index].FreezeSnapshotHash != hex.EncodeToString(freeze.FreezeSnapshotHash[:]) {
			return nil, nil, ErrBindingMismatch
		}
	}
	replacements := make([]OwnerReplacementPlan, len(request.Replacements))
	for index, replacement := range request.Replacements {
		if index > 0 && request.Replacements[index-1].SeatExternalID >= replacement.SeatExternalID {
			return nil, nil, ErrDuplicate
		}
		replacements[index] = OwnerReplacementPlan{SeatID: replacement.SeatExternalID,
			FromMemberID: replacement.FromMemberExternalID, ToMemberID: replacement.ToMemberExternalID,
			ExpectedAssignmentEpoch: replacement.ExpectedAssignmentEpoch,
			FreezeOperationID:       replacement.FreezeOperationID,
			FreezeSnapshotHash:      hex.EncodeToString(replacement.FreezeSnapshotHash[:])}
	}
	previous, err := decodeOptionalHash(request.PreviousManifestHash)
	if err != nil {
		return nil, nil, err
	}
	if err := validateCeremonyPlan(request.CeremonyType, epochStatusActive, sourceGovernanceState(request.CeremonyType),
		previous, seats, replacements); err != nil {
		return nil, nil, err
	}
	return seats, replacements, nil
}

func manifestBatchBindings(accounts []ResourceAccountPlan) ([]StagedBatchBinding, string, [sha256.Size]byte, error) {
	setHash, err := ProviderAttestationSetHash(accounts)
	if err != nil {
		return nil, "", [sha256.Size]byte{}, err
	}
	bindings := make([]StagedBatchBinding, 0, len(accounts)*8)
	for _, account := range accounts {
		for _, batch := range account.Batches {
			fromHash, fromErr := decodeOptionalHash(batch.FromCiphertextHash)
			toHash, toErr := decodeOptionalHash(batch.ToCiphertextHash)
			toRecoveryWrapHash, wrapErr := decodeOptionalHash(batch.ToRecoveryWrapHash)
			if fromErr != nil || toErr != nil || wrapErr != nil || toRecoveryWrapHash == ([sha256.Size]byte{}) {
				return nil, "", [sha256.Size]byte{}, ErrInvalidData
			}
			bindings = append(bindings,
				StagedBatchBinding{EpochRole: "FROM", ResourceAccountExternalID: account.AccountID,
					BatchExternalID: batch.FromBatchID, AccountRef: account.AccountRef,
					BatchType: batch.BatchType, BatchVersion: batch.FromBatchVersion, CiphertextHash: fromHash},
				StagedBatchBinding{EpochRole: "TO", ResourceAccountExternalID: account.AccountID,
					BatchExternalID: batch.ToBatchID, AccountRef: account.AccountRef,
					BatchType: batch.BatchType, BatchVersion: batch.ToBatchVersion, CiphertextHash: toHash,
					RecoveryWrapHash: toRecoveryWrapHash})
		}
	}
	sort.Slice(bindings, func(i, j int) bool { return bindingSortKey(bindings[i]) < bindingSortKey(bindings[j]) })
	encoded, err := canonicalIntentJSON(bindings)
	if err != nil {
		return nil, "", [sha256.Size]byte{}, err
	}
	return bindings, hex.EncodeToString(setHash[:]), sha256.Sum256(encoded), nil
}

func controlEvidenceSnapshot(input IssueControlEvidenceInput) ([]byte, error) {
	type reference struct {
		EpochRole       string `json:"epoch_role"`
		BatchType       string `json:"batch_type"`
		BatchExternalID string `json:"batch_external_id"`
	}
	references := make([]reference, len(input.BatchReferences))
	for index, item := range input.BatchReferences {
		references[index] = reference(item)
	}
	sort.Slice(references, func(i, j int) bool {
		if references[i].EpochRole != references[j].EpochRole {
			return references[i].EpochRole < references[j].EpochRole
		}
		if references[i].BatchType != references[j].BatchType {
			return references[i].BatchType < references[j].BatchType
		}
		return references[i].BatchExternalID < references[j].BatchExternalID
	})
	return canonicalIntentJSON(struct {
		EvidenceExternalID                 string      `json:"evidence_external_id"`
		PlanExternalID                     string      `json:"plan_external_id"`
		ResourceExternalID                 string      `json:"resource_external_id"`
		ProviderAttestationRef             string      `json:"provider_attestation_ref"`
		ProviderAttestationDigest          string      `json:"provider_attestation_digest"`
		ProviderAttestationIssuer          string      `json:"provider_attestation_issuer"`
		ProviderAttestationKeyID           string      `json:"provider_attestation_key_id"`
		ProviderAttestationVersion         uint64      `json:"provider_attestation_version"`
		ProviderAttestationAlgorithm       string      `json:"provider_attestation_algorithm"`
		ProviderAttestationSignature       []byte      `json:"provider_attestation_signature"`
		ProviderAttestationProtocolVersion string      `json:"provider_attestation_protocol_version"`
		BatchReferences                    []reference `json:"batch_references"`
	}{input.EvidenceExternalID, input.PlanExternalID, input.ResourceExternalID,
		input.ProviderAttestationRef, hex.EncodeToString(input.ProviderAttestationDigest[:]),
		input.ProviderAttestationIssuer, input.ProviderAttestationKeyID,
		input.ProviderAttestationVersion, input.ProviderAttestationAlgorithm,
		input.ProviderAttestationSignature, input.ProviderAttestationProtocolVersion, references})
}

func RecoveryRootCommitmentHash(pkg EncryptedRecoveryPackage) [sha256.Size]byte {
	var encoded bytes.Buffer
	writeSecurityString(&encoded, "trusted-pool/recovery-root-commitment/v1")
	writeSecurityString(&encoded, string(pkg.CeremonyType))
	writeSecurityString(&encoded, pkg.ProviderID)
	writeSecurityString(&encoded, pkg.RootPublicAlgorithm)
	writeSecurityString(&encoded, pkg.RootPublicHandle)
	encoded.Write(pkg.RootPublicFingerprint[:])
	writeSecurityString(&encoded, pkg.RootKeyVersion)
	writeSecurityString(&encoded, pkg.RootWrapDomain)
	writeSecurityString(&encoded, pkg.RootWrapAlgorithm)
	privateHash, vssHash, proofHash := sha256.Sum256(pkg.RootPrivateCommitment), sha256.Sum256(pkg.VSSCommitment), sha256.Sum256(pkg.VSSProof)
	encoded.Write(privateHash[:])
	encoded.Write(vssHash[:])
	encoded.Write(proofHash[:])
	encoded.Write(pkg.PackageHash[:])
	encoded.Write(pkg.RequestIntentHash[:])
	return sha256.Sum256(encoded.Bytes())
}

func canonicalIntentJSON(value any) ([]byte, error) {
	if request, ok := value.(PlanRequest); ok {
		request.ExpectedFencingToken = 0
		value = request
	}
	raw, err := json.Marshal(value)
	if err != nil {
		return nil, ErrInvalidData
	}
	decoder := json.NewDecoder(bytes.NewReader(raw))
	decoder.UseNumber()
	var object any
	if err := decoder.Decode(&object); err != nil {
		return nil, ErrInvalidData
	}
	if err := decoder.Decode(&struct{}{}); !errors.Is(err, io.EOF) {
		return nil, ErrInvalidData
	}
	canonical, err := json.Marshal(object)
	if err != nil {
		return nil, ErrInvalidData
	}
	return canonical, nil
}

func validateSecuritySnapshot(snapshot *EpochSecuritySnapshot, plan *StoredEpochPlan, status string,
	requested []EpochMember) error {
	if snapshot == nil || snapshot.Plan == nil || plan == nil || snapshot.Plan.ExternalID != plan.ExternalID ||
		snapshot.Plan.Status != status || snapshot.ManifestHash == ([sha256.Size]byte{}) ||
		len(snapshot.ManifestCanonical) == 0 || sha256.Sum256(snapshot.ManifestCanonical) != snapshot.ManifestHash ||
		len(snapshot.Members) != plan.ExpectedMemberCount || len(snapshot.Deliveries) != plan.ExpectedMemberCount {
		return ErrInvalidData
	}
	requestedByID := make(map[string]EpochMember, len(requested))
	for _, member := range requested {
		if _, exists := requestedByID[member.MemberExternalID]; exists {
			return ErrDuplicate
		}
		requestedByID[member.MemberExternalID] = member
	}
	for _, trusted := range snapshot.Members {
		supplied, exists := requestedByID[trusted.MemberExternalID]
		if !exists || supplied.SeatExternalID != trusted.SeatExternalID || supplied.Role != trusted.Role ||
			supplied.ShareIndex != trusted.ShareIndex || supplied.SigningAlgorithm != trusted.SigningAlgorithm ||
			supplied.SigningKeyID != trusted.SigningKeyID || supplied.SigningKeyFingerprint != trusted.SigningKeyFingerprint ||
			!bytes.Equal(supplied.SigningPublicKey, trusted.SigningPublicKey) ||
			supplied.SigningProofAlgorithm != trusted.SigningProofAlgorithm || !bytes.Equal(supplied.SigningProof, trusted.SigningProof) ||
			supplied.RecoveryKeyAlgorithm != trusted.RecoveryKeyAlgorithm || supplied.RecoveryKeyID != trusted.RecoveryKeyID ||
			supplied.RecoveryKeyFingerprint != trusted.RecoveryKeyFingerprint ||
			!bytes.Equal(supplied.RecoveryEncryptionPublicKey, trusted.RecoveryEncryptionPublicKey) ||
			supplied.RecoveryKeyProofAlgorithm != trusted.RecoveryKeyProofAlgorithm ||
			!bytes.Equal(supplied.RecoveryKeyProof, trusted.RecoveryKeyProof) {
			return ErrBindingMismatch
		}
	}
	return nil
}

func recoveryMembersFromEpoch(values []EpochMember) []RecoveryMember {
	result := make([]RecoveryMember, len(values))
	for index, member := range values {
		result[index] = RecoveryMember{MemberID: member.MemberExternalID, Role: member.Role,
			ShareIndex: member.ShareIndex, SigningAlgorithm: member.SigningAlgorithm,
			SigningKeyID: member.SigningKeyID, SigningKeyFingerprint: member.SigningKeyFingerprint,
			SigningPublicKey:    append([]byte(nil), member.SigningPublicKey...),
			EncryptionAlgorithm: member.RecoveryKeyAlgorithm, EncryptionKeyID: member.RecoveryKeyID,
			EncryptionKeyFingerprint: member.RecoveryKeyFingerprint,
			EncryptionPublicKey:      append([]byte(nil), member.RecoveryEncryptionPublicKey...)}
	}
	return result
}

// validateCommittedRecoveryPackage 防止崩溃重放时把 Root A 与 package/shares B 拼接。
func validateCommittedRecoveryPackage(snapshot *EpochSecuritySnapshot, request PlanRequest,
	pkg EncryptedRecoveryPackage, requireDeliveries bool) error {
	if snapshot == nil || snapshot.Plan == nil || snapshot.Root == nil ||
		snapshot.Plan.ExternalID != request.PlanExternalID || snapshot.Plan.PoolExternalID != request.PoolID {
		return ErrInvalidData
	}
	root := snapshot.Root
	if root.ExternalID != request.RootArtifactExternalID || root.Provider != pkg.ProviderID ||
		root.ProviderKeyRef != pkg.RootPublicHandle || root.RootHandle != pkg.RootPublicHandle ||
		root.RootKeyVersion != pkg.RootKeyVersion || root.EpochRecoveryAlgorithm != pkg.RootPublicAlgorithm ||
		root.EpochRecoveryKeyID != pkg.RootPublicHandle || root.EpochRecoveryKeyFingerprint != pkg.RootPublicFingerprint ||
		root.WrapDomain != pkg.RootWrapDomain || root.WrapAlgorithm != pkg.RootWrapAlgorithm ||
		root.VSSAlgorithm != pkg.VSSAlgorithm || root.VSSCommitmentHash != sha256.Sum256(pkg.VSSCommitment) ||
		root.VSSProofHash != sha256.Sum256(pkg.VSSProof) ||
		root.PrivateKeyCommitmentHash != sha256.Sum256(pkg.RootPrivateCommitment) ||
		root.RootCommitmentHash != RecoveryRootCommitmentHash(pkg) || root.RecoveryPackageHash != pkg.PackageHash ||
		root.RequestIntentHash != pkg.RequestIntentHash || root.ProviderAttestationRef != pkg.ProviderAttestationRef ||
		root.AttestationDigest != pkg.ProviderAttestationDigest ||
		!bytes.Equal(root.AttestationSignature, pkg.ProviderAttestation) || root.AttestationKeyID != pkg.ProviderAttestationKeyID ||
		root.PortableAttestationAlgorithm != pkg.PortableAttestationAlgorithm ||
		root.PortableAttestationIssuer != pkg.PortableAttestationIssuer ||
		root.PortableAttestationKeyID != pkg.PortableAttestationKeyID ||
		root.PortableAttestationProtocolVersion != pkg.PortableAttestationProtocolVersion ||
		!bytes.Equal(root.PortableAttestationSignature, pkg.PortableAttestationSignature) {
		return ErrBindingMismatch
	}
	if !requireDeliveries {
		if len(snapshot.Deliveries) != 0 {
			return ErrBindingMismatch
		}
		return nil
	}
	if len(snapshot.Deliveries) != len(pkg.EncryptedShares) {
		return ErrBindingMismatch
	}
	deliveries := deliveryMap(snapshot.Deliveries)
	for _, share := range pkg.EncryptedShares {
		externalID := deterministicExternalID("share", request.PlanExternalID, share.MemberID)
		delivery, exists := deliveries[externalID]
		if !exists || delivery.MemberExternalID != share.MemberID || delivery.ShareIndex != share.ShareIndex ||
			delivery.EncryptionAlgorithm != share.EncryptionAlgorithm || delivery.RecipientKeyID != share.EncryptionKeyID ||
			delivery.RecipientKeyFingerprint != share.EncryptionKeyFingerprint ||
			delivery.CiphertextHash != share.CiphertextHash ||
			!bytes.Equal(delivery.ProviderShareCommitment, share.ProviderCommitment) ||
			delivery.ProviderProofDigest != sha256.Sum256(share.ProviderProof) ||
			!bytes.Equal(delivery.ProviderProofSignature, share.ProviderProof) ||
			delivery.PortableProofAlgorithm != share.PortableProofAlgorithm ||
			delivery.PortableProofKeyID != share.PortableProofKeyID ||
			delivery.PortableProofProtocolVersion != share.PortableProofProtocolVersion ||
			!bytes.Equal(delivery.PortableProofSignature, share.PortableProofSignature) ||
			delivery.RootCommitmentHash != root.RootCommitmentHash ||
			delivery.VSSCommitmentHash != root.VSSCommitmentHash ||
			delivery.RecoveryPackageHash != pkg.PackageHash || delivery.RequestIntentHash != pkg.RequestIntentHash {
			return ErrBindingMismatch
		}
	}
	return nil
}

func epochMemberMap(members []RecoveryMember) map[string]RecoveryMember {
	result := make(map[string]RecoveryMember, len(members))
	for _, member := range members {
		result[member.MemberID] = member
	}
	return result
}

func deliveryMap(deliveries []StoredShareDelivery) map[string]StoredShareDelivery {
	result := make(map[string]StoredShareDelivery, len(deliveries))
	for _, delivery := range deliveries {
		result[delivery.ExternalID] = delivery
	}
	return result
}

func expectedToBatchMap(accounts []ResourceAccountPlan) map[string]ControlBatchPlan {
	result := make(map[string]ControlBatchPlan, len(accounts)*4)
	for _, account := range accounts {
		for _, batch := range account.Batches {
			result[account.AccountID+"\x00"+batch.BatchType] = batch
		}
	}
	return result
}

func expectedAccountRef(accounts []ResourceAccountPlan, accountID string) string {
	for _, account := range accounts {
		if account.AccountID == accountID {
			return account.AccountRef
		}
	}
	return ""
}

func sourceGovernanceState(ceremony CeremonyType) string {
	if ceremony == CeremonyBootstrap {
		return governanceStateLegacy
	}
	return governanceStateCurrent
}

func planStatusAtLeast(actual, expected string) bool {
	order := map[string]int{planStatusPlanned: 1, planStatusRootCommitted: 2, planStatusSharesCommitted: 3,
		planStatusManifestDraft: 4, planStatusManifestSigned: 5, planStatusAcknowledged: 6,
		planStatusBatchesStaged: 7, planStatusReady: 8}
	return order[actual] >= order[expected] && order[expected] > 0
}

func validPlanStatus(status string) bool { return planStatusAtLeast(status, planStatusPlanned) }

func deterministicExternalID(prefix, first, second string) string {
	hash := sha256.Sum256([]byte(prefix + "\x00" + first + "\x00" + second))
	return prefix + "-" + hex.EncodeToString(hash[:16])
}

func bindingSortKey(binding StagedBatchBinding) string {
	return binding.ResourceAccountExternalID + "\x00" + binding.EpochRole + "\x00" + binding.BatchType
}

func batchPayloadSortKey(payload StagedBatchPayload) string {
	return payload.ResourceAccountID + "\x00" + string(payload.BatchType)
}

func hashHexBytes(value []byte) string {
	hash := sha256.Sum256(value)
	return hex.EncodeToString(hash[:])
}

func mustDecodeHash(value string) [sha256.Size]byte {
	result, _ := decodeOptionalHash(value)
	return result
}

func clonePlan(plan *StoredEpochPlan) *StoredEpochPlan {
	if plan == nil {
		return nil
	}
	clone := *plan
	if plan.PortableProfile != nil {
		profile := *plan.PortableProfile
		clone.PortableProfile = &profile
	}
	return &clone
}

func planProgress(target *EpochPlanTarget, plan *StoredEpochPlan) *PlanProgress {
	if target == nil || target.Operation == nil || target.Operation.LeaseExpiresAt == nil {
		return nil
	}
	return &PlanProgress{Plan: clonePlan(plan), FencingToken: target.Operation.FencingToken,
		LeaseExpiresAt: target.Operation.LeaseExpiresAt.UTC()}
}

func cloneRecoveryMembers(values []RecoveryMember) []RecoveryMember {
	result := append([]RecoveryMember(nil), values...)
	for index := range result {
		result[index].SigningPublicKey = append([]byte(nil), values[index].SigningPublicKey...)
		result[index].EncryptionPublicKey = append([]byte(nil), values[index].EncryptionPublicKey...)
	}
	return result
}

func cloneEpochMembers(values []EpochMember) []EpochMember {
	result := append([]EpochMember(nil), values...)
	for index := range result {
		result[index].SigningPublicKey = append([]byte(nil), values[index].SigningPublicKey...)
		result[index].SigningProof = append([]byte(nil), values[index].SigningProof...)
		result[index].RecoveryEncryptionPublicKey = append([]byte(nil), values[index].RecoveryEncryptionPublicKey...)
		result[index].RecoveryKeyProof = append([]byte(nil), values[index].RecoveryKeyProof...)
	}
	return result
}

func clearEpochMembers(values []EpochMember) {
	for index := range values {
		clear(values[index].SigningPublicKey)
		clear(values[index].SigningProof)
		clear(values[index].RecoveryEncryptionPublicKey)
		clear(values[index].RecoveryKeyProof)
	}
}

func clearRecoveryPackage(pkg *EncryptedRecoveryPackage) {
	if pkg == nil {
		return
	}
	clear(pkg.RootPrivateCommitment)
	clear(pkg.VSSCommitment)
	clear(pkg.VSSProof)
	clear(pkg.ProviderAttestation)
	clear(pkg.PortableAttestationSignature)
	for index := range pkg.EncryptedShares {
		clear(pkg.EncryptedShares[index].Ciphertext)
		clear(pkg.EncryptedShares[index].ProviderCommitment)
		clear(pkg.EncryptedShares[index].ProviderProof)
		clear(pkg.EncryptedShares[index].PortableProofSignature)
	}
}

func clearShareDeliveries(values []ShareDeliveryInput) {
	for index := range values {
		clear(values[index].Ciphertext)
		clear(values[index].ProviderShareCommitment)
		clear(values[index].ProviderProofSignature)
		clear(values[index].PortableProofSignature)
	}
}

func cloneStagedBatch(batch StagedCredentialBatch) StagedCredentialBatch {
	clone := batch
	clone.Ciphertext = append([]byte(nil), batch.Ciphertext...)
	clone.Nonce = append([]byte(nil), batch.Nonce...)
	clone.WrappedDEKKMS = append([]byte(nil), batch.WrappedDEKKMS...)
	clone.WrappedDEKRecovery = append([]byte(nil), batch.WrappedDEKRecovery...)
	clone.ProviderWrapAttestationSignature = append([]byte(nil), batch.ProviderWrapAttestationSignature...)
	return clone
}

func clearStagedBatch(batch *StagedCredentialBatch) {
	if batch == nil {
		return
	}
	clear(batch.Ciphertext)
	clear(batch.Nonce)
	clear(batch.WrappedDEKKMS)
	clear(batch.WrappedDEKRecovery)
	clear(batch.ProviderWrapAttestationSignature)
}

func clearStagedBatches(values []StagedCredentialBatch) {
	for index := range values {
		clearStagedBatch(&values[index])
	}
}

func clearBatchPayloads(values []StagedBatchPayload) {
	for index := range values {
		clear(values[index].Payload)
	}
}

func (r PlanRequest) String() string {
	return fmt.Sprintf("recovery plan %s/%s", r.PoolID, r.PlanExternalID)
}

func newRecoveryClaimToken() (string, error) {
	raw := make([]byte, 32)
	defer clear(raw)
	if _, err := rand.Read(raw); err != nil {
		return "", err
	}
	return base64.RawURLEncoding.EncodeToString(raw), nil
}

func validateFinalizeRequest(request *FinalizeRequest) error {
	if request == nil || !validSecurityID(request.OperationID) || !validSecurityID(request.PlanExternalID) ||
		!validSecurityID(request.CaseExternalID) || request.ExpectedFencingToken < 0 ||
		len(request.EvidenceExternalIDs) == 0 {
		return ErrInvalidData
	}
	sort.Strings(request.EvidenceExternalIDs)
	for index, evidenceID := range request.EvidenceExternalIDs {
		if !validSecurityID(evidenceID) || index > 0 && request.EvidenceExternalIDs[index-1] == evidenceID {
			return ErrInvalidData
		}
	}
	sort.Slice(request.Replacements, func(i, j int) bool {
		return request.Replacements[i].SeatExternalID < request.Replacements[j].SeatExternalID
	})
	for index, replacement := range request.Replacements {
		if !validSecurityID(replacement.SeatExternalID) || !validSecurityID(replacement.TargetMemberExternalID) ||
			index > 0 && request.Replacements[index-1].SeatExternalID == replacement.SeatExternalID {
			return ErrInvalidData
		}
	}
	return nil
}

func validateFinalizationTarget(target *PermanentReplacementTarget, err error) (*PermanentReplacementTarget, error) {
	if err != nil {
		return nil, err
	}
	if target == nil || target.Operation == nil || target.Plan == nil || target.CaseExternalID == "" {
		return nil, ErrInvalidData
	}
	return target, nil
}

func seatPrepareRequest(plan *StoredEpochPlan,
	progress *StoredSeatRotationProgress) (PermanentSeatRotationPrepareRequest, error) {
	if plan == nil || progress == nil || progress.PlanExternalID != plan.ExternalID ||
		progress.PoolExternalID != plan.PoolExternalID || progress.FromEpoch != plan.FromEpoch ||
		progress.ToEpoch != plan.ToEpoch || !validSecurityID(progress.SeatExternalID) ||
		!validSecurityID(progress.TargetMemberExternalID) || progress.ExpectedAssignmentEpoch == 0 ||
		progress.ExpectedPrincipalUserID <= 0 || progress.ExpectedSubscriptionID <= 0 ||
		progress.ExpectedAPIKeyID <= 0 || progress.ExpectedAPIKeyVersion == 0 {
		return PermanentSeatRotationPrepareRequest{}, ErrInvalidData
	}
	operationID := progress.DerivedOperationID
	if operationID == "" {
		operationID = deterministicExternalID("prepare-seat", plan.ExternalID, progress.SeatExternalID)
	}
	request := PermanentSeatRotationPrepareRequest{ProtocolVersion: PermanentSeatRotationProtocolV1,
		OperationID: operationID, PlanID: plan.ExternalID, CeremonyType: plan.CeremonyType,
		PoolID: plan.PoolExternalID, FromEpoch: plan.FromEpoch, ToEpoch: plan.ToEpoch,
		SeatID: progress.SeatExternalID, TargetMemberID: progress.TargetMemberExternalID,
		ExpectedAssignmentEpoch: progress.ExpectedAssignmentEpoch,
		PrincipalUserID:         progress.ExpectedPrincipalUserID, SubscriptionID: progress.ExpectedSubscriptionID,
		APIKeyID: progress.ExpectedAPIKeyID, FromAPIKeyVersion: progress.ExpectedAPIKeyVersion,
		ToAPIKeyVersion: progress.ExpectedAPIKeyVersion + 1}
	request.RequestHash = PermanentSeatRotationPrepareRequestHash(request)
	return request, nil
}

func allSeatsPrepared(seats []SeatRotationTarget) bool {
	if len(seats) == 0 {
		return false
	}
	for _, seat := range seats {
		if seat.Progress == nil || seat.Progress.Status != "PREPARED" {
			return false
		}
	}
	return true
}

func activationBindings(seats []SeatRotationTarget) ([]PermanentSeatActivationBinding, error) {
	bindings := make([]PermanentSeatActivationBinding, len(seats))
	for index, seat := range seats {
		if seat.Progress == nil || seat.Operation == nil ||
			(seat.Progress.Status != "PREPARED" && seat.Progress.Status != "ACTIVATED") ||
			seat.Operation.Status != "SUCCEEDED" {
			return nil, ErrInvalidState
		}
		bindings[index] = PermanentSeatActivationBinding{SeatID: seat.Progress.SeatExternalID,
			TargetMemberID:          seat.Progress.TargetMemberExternalID,
			ExpectedAssignmentEpoch: seat.Progress.ExpectedAssignmentEpoch,
			PrincipalUserID:         seat.Progress.PrincipalUserID, SubscriptionID: seat.Progress.SubscriptionID,
			APIKeyID: seat.Progress.APIKeyID, ActiveAPIKeyVersion: seat.Progress.APIKeyVersion,
			ChildOperationID: seat.Operation.Key.OperationID, ChildRequestHash: seat.Operation.RequestHash,
			CredentialFingerprint: seat.Progress.CredentialFingerprint,
			PreparedRotationRef:   seat.Progress.PreparedReference}
	}
	sort.Slice(bindings, func(i, j int) bool { return bindings[i].SeatID < bindings[j].SeatID })
	return bindings, nil
}

// releaseBindings 只从 structural final 后仍由 Store 保存的不可变字段重建全集合，
// 避免进程重启后依赖内存中的 provider 响应。
func releaseBindings(seats []SeatRotationTarget) ([]PermanentSeatActivationBinding, error) {
	bindings := make([]PermanentSeatActivationBinding, len(seats))
	for index, seat := range seats {
		if seat.Progress == nil || seat.Operation == nil ||
			(seat.Progress.Status != "ACTIVATED" && seat.Progress.Status != "COMMITTED") ||
			seat.Operation.Status != "SUCCEEDED" {
			return nil, ErrInvalidState
		}
		bindings[index] = PermanentSeatActivationBinding{SeatID: seat.Progress.SeatExternalID,
			TargetMemberID:          seat.Progress.TargetMemberExternalID,
			ExpectedAssignmentEpoch: seat.Progress.ExpectedAssignmentEpoch,
			PrincipalUserID:         seat.Progress.PrincipalUserID, SubscriptionID: seat.Progress.SubscriptionID,
			APIKeyID: seat.Progress.APIKeyID, ActiveAPIKeyVersion: seat.Progress.APIKeyVersion,
			ChildOperationID: seat.Operation.Key.OperationID, ChildRequestHash: seat.Operation.RequestHash,
			CredentialFingerprint: seat.Progress.CredentialFingerprint,
			PreparedRotationRef:   seat.Progress.PreparedReference}
	}
	sort.Slice(bindings, func(i, j int) bool { return bindings[i].SeatID < bindings[j].SeatID })
	return bindings, nil
}

func rotationSnapshot(request any, hashField string, setHash [sha256.Size]byte) ([]byte, error) {
	raw, err := json.Marshal(request)
	if err != nil {
		return nil, ErrInvalidData
	}
	var value map[string]any
	decoder := json.NewDecoder(bytes.NewReader(raw))
	decoder.UseNumber()
	if err := decoder.Decode(&value); err != nil {
		return nil, ErrInvalidData
	}
	value[hashField] = hex.EncodeToString(setHash[:])
	return canonicalIntentJSON(value)
}

func replacementClaimFromEnvelope(result PermanentSeatRotationPrepareResult, fingerprint [sha256.Size]byte,
	envelope credentials.Envelope) ReplacementCredentialClaim {
	return ReplacementCredentialClaim{SeatExternalID: result.SeatID,
		TargetMemberExternalID: result.TargetMemberID, PreparedReference: result.PreparedRotationRef,
		ProviderResultDigest:  PermanentSeatRotationPrepareResultDigest(result, fingerprint),
		CredentialFingerprint: fingerprint, EnvelopeAlgorithm: envelope.Algorithm, EnvelopeKeyRef: envelope.KeyRef,
		EnvelopeCiphertext: append([]byte(nil), envelope.Ciphertext...), EnvelopeNonce: append([]byte(nil), envelope.Nonce...),
		EnvelopeAADHash: envelope.AADHash, WrappedDEK: append([]byte(nil), envelope.WrappedDEK...)}
}

func clearCredentialEnvelope(envelope *credentials.Envelope) {
	if envelope == nil {
		return
	}
	clear(envelope.Ciphertext)
	clear(envelope.Nonce)
	clear(envelope.WrappedDEK)
}

func clearPermanentPrepareCredentials(results []PermanentSeatRotationPrepareResult) {
	for index := range results {
		clear(results[index].Credential)
		results[index].Credential = nil
	}
}

func finalizationProgress(target *PermanentReplacementTarget, status string,
	claims []ReplacementClaimToken) *FinalizationProgress {
	if target == nil || target.Plan == nil {
		return nil
	}
	progress := &FinalizationProgress{PlanID: target.Plan.ExternalID, CeremonyType: target.Plan.CeremonyType,
		PoolID: target.Plan.PoolExternalID, FromEpoch: target.Plan.FromEpoch, ToEpoch: target.Plan.ToEpoch,
		Status: status, Claims: claims}
	if target.Operation != nil {
		progress.FencingToken = target.Operation.FencingToken
		if target.Operation.LeaseExpiresAt != nil {
			value := target.Operation.LeaseExpiresAt.UTC()
			progress.LeaseExpiresAt = &value
		}
	}
	return progress
}
