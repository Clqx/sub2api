package recovery

import (
	"bytes"
	"context"
	"crypto/sha256"
	"encoding/binary"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"reflect"
	"strings"
	"time"

	"trusted-pool-platform/backend/internal/credentials"
)

const maxSecurityIdentifierLength = 512

const (
	epochStatusActive           = "ACTIVE"
	governanceStateLegacy       = "LEGACY_UNVERIFIED"
	governanceStateCurrent      = "CURRENT"
	bootstrapAttestationPurpose = "BOOTSTRAP_GENESIS"
	rotationAttestationPurpose  = "ROTATION_CONTROL"
)

func ValidateRecoveryPackageRequest(request RecoveryPackageRequest) error {
	if request.Version == 0 || !validCeremonyType(request.CeremonyType) ||
		!validSecurityID(request.RequestID) || !validSecurityID(request.OperationID) ||
		!validSecurityID(request.PoolID) || request.FromEpoch == 0 || request.ToEpoch != request.FromEpoch+1 ||
		!validSecurityID(request.ExpectedProviderID) || !validSecurityID(request.TrustProfile) ||
		request.RecoveryThreshold == 0 || int(request.RecoveryThreshold) > len(request.Members) ||
		len(request.Members) == 0 || !nonzeroSecurityHash(request.IntentHash) {
		return ErrInvalidData
	}
	if err := validateRecoveryMembers(request.Members); err != nil {
		return err
	}
	if err := validateCeremonySource(request.CeremonyType, request.FromEpochStatus,
		request.FromGovernanceState, request.PreviousManifestHash); err != nil {
		return err
	}
	want, err := RecoveryIntentHash(request)
	if err != nil || want != request.IntentHash {
		return errors.Join(ErrBindingMismatch, err)
	}
	return nil
}

// RecoveryIntentHash 使用有长度前缀的类型化编码绑定 Provider 请求；它不是 Manifest JCS 的替代实现。
func RecoveryIntentHash(request RecoveryPackageRequest) ([sha256.Size]byte, error) {
	var empty [sha256.Size]byte
	copyRequest := request
	copyRequest.IntentHash = empty
	if copyRequest.Version == 0 || !validCeremonyType(copyRequest.CeremonyType) || !validSecurityID(copyRequest.RequestID) ||
		!validSecurityID(copyRequest.OperationID) || !validSecurityID(copyRequest.PoolID) ||
		!validSecurityID(copyRequest.ExpectedProviderID) || !validSecurityID(copyRequest.TrustProfile) ||
		copyRequest.FromEpoch == 0 || copyRequest.ToEpoch != copyRequest.FromEpoch+1 ||
		copyRequest.RecoveryThreshold == 0 || int(copyRequest.RecoveryThreshold) > len(copyRequest.Members) ||
		len(copyRequest.Members) == 0 {
		return empty, ErrInvalidData
	}
	if err := validateRecoveryMembers(copyRequest.Members); err != nil {
		return empty, err
	}
	if err := validateCeremonySource(copyRequest.CeremonyType, copyRequest.FromEpochStatus,
		copyRequest.FromGovernanceState, copyRequest.PreviousManifestHash); err != nil {
		return empty, err
	}

	var encoded bytes.Buffer
	writeSecurityString(&encoded, "trusted-pool/recovery-package-intent/v1")
	writeSecurityUint16(&encoded, copyRequest.Version)
	writeSecurityString(&encoded, string(copyRequest.CeremonyType))
	writeSecurityString(&encoded, copyRequest.RequestID)
	writeSecurityString(&encoded, copyRequest.OperationID)
	writeSecurityString(&encoded, copyRequest.PoolID)
	writeSecurityUint64(&encoded, copyRequest.FromEpoch)
	writeSecurityUint64(&encoded, copyRequest.ToEpoch)
	writeSecurityString(&encoded, copyRequest.FromEpochStatus)
	writeSecurityString(&encoded, copyRequest.FromGovernanceState)
	encoded.Write(copyRequest.PreviousManifestHash[:])
	writeSecurityString(&encoded, copyRequest.ExpectedProviderID)
	writeSecurityString(&encoded, copyRequest.TrustProfile)
	writeSecurityUint16(&encoded, copyRequest.RecoveryThreshold)
	writeSecurityUint32(&encoded, uint32(len(copyRequest.Members)))
	for _, member := range copyRequest.Members {
		writeSecurityString(&encoded, member.MemberID)
		writeSecurityString(&encoded, member.Role)
		writeSecurityUint16(&encoded, member.ShareIndex)
		writeSecurityString(&encoded, member.SigningAlgorithm)
		writeSecurityString(&encoded, member.SigningKeyID)
		encoded.Write(member.SigningKeyFingerprint[:])
		writeSecurityBytes(&encoded, member.SigningPublicKey)
		writeSecurityString(&encoded, member.EncryptionAlgorithm)
		writeSecurityString(&encoded, member.EncryptionKeyID)
		encoded.Write(member.EncryptionKeyFingerprint[:])
		writeSecurityBytes(&encoded, member.EncryptionPublicKey)
	}
	return sha256.Sum256(encoded.Bytes()), nil
}

func ValidateEncryptedRecoveryPackage(request RecoveryPackageRequest, pkg EncryptedRecoveryPackage) error {
	if err := ValidateRecoveryPackageRequest(request); err != nil {
		return err
	}
	if pkg.Version != request.Version || pkg.CeremonyType != request.CeremonyType || pkg.RequestID != request.RequestID ||
		pkg.OperationID != request.OperationID || pkg.PoolID != request.PoolID ||
		pkg.FromEpoch != request.FromEpoch || pkg.Epoch != request.ToEpoch ||
		pkg.FromEpochStatus != request.FromEpochStatus || pkg.FromGovernanceState != request.FromGovernanceState ||
		pkg.PreviousManifestHash != request.PreviousManifestHash ||
		pkg.RequestIntentHash != request.IntentHash || pkg.ProviderID != request.ExpectedProviderID {
		return ErrBindingMismatch
	}
	if !validSecurityID(pkg.ProviderID) || !validSecurityID(pkg.RootPublicAlgorithm) ||
		!validSecurityID(pkg.RootPublicHandle) || !validSecurityID(pkg.RootKeyVersion) ||
		!validSecurityID(pkg.RootWrapDomain) || !validSecurityID(pkg.RootWrapAlgorithm) ||
		!validSecurityID(pkg.VSSAlgorithm) || !nonzeroSecurityHash(pkg.RootPublicFingerprint) ||
		!nonzeroSecurityHash(pkg.PackageHash) || len(pkg.RootPrivateCommitment) == 0 ||
		len(pkg.VSSCommitment) == 0 || len(pkg.VSSProof) == 0 || len(pkg.ProviderAttestation) == 0 ||
		!validSecurityID(pkg.ProviderAttestationRef) || !validSecurityID(pkg.ProviderAttestationKeyID) ||
		!nonzeroSecurityHash(pkg.ProviderAttestationDigest) || sha256.Sum256(pkg.ProviderAttestation) != pkg.ProviderAttestationDigest ||
		!validSecurityID(pkg.PortableAttestationAlgorithm) || !validSecurityID(pkg.PortableAttestationIssuer) ||
		pkg.PortableAttestationIssuer != pkg.ProviderID || !validSecurityID(pkg.PortableAttestationKeyID) ||
		!validSecurityID(pkg.PortableAttestationProtocolVersion) || len(pkg.PortableAttestationSignature) == 0 ||
		pkg.CreatedAt.IsZero() || len(pkg.EncryptedShares) != len(request.Members) {
		return ErrInvalidData
	}
	for i, share := range pkg.EncryptedShares {
		member := request.Members[i]
		if share.MemberID != member.MemberID || share.ShareIndex != member.ShareIndex ||
			share.EncryptionAlgorithm != member.EncryptionAlgorithm || share.EncryptionKeyID != member.EncryptionKeyID ||
			share.EncryptionKeyFingerprint != member.EncryptionKeyFingerprint {
			return ErrBindingMismatch
		}
		if len(share.Ciphertext) == 0 || !nonzeroSecurityHash(share.CiphertextHash) ||
			sha256.Sum256(share.Ciphertext) != share.CiphertextHash ||
			len(share.ProviderCommitment) == 0 || len(share.ProviderProof) == 0 ||
			!validSecurityID(share.PortableProofAlgorithm) || !validSecurityID(share.PortableProofKeyID) ||
			!validSecurityID(share.PortableProofProtocolVersion) || len(share.PortableProofSignature) == 0 {
			return ErrInvalidData
		}
	}
	return nil
}

func VerifyEpochDEKWrap(ctx context.Context, verifier ProviderAttestationVerifier, request EpochDEKWrapRequest, result EpochDEKWrapResult) error {
	if isNilProvider(verifier) {
		return ErrProviderUnavailable
	}
	if err := verifier.Ready(ctx); err != nil {
		return ErrProviderUnavailable
	}
	if !validCeremonyType(request.CeremonyType) || !validSecurityID(request.OperationID) ||
		!validSecurityID(request.PoolID) || request.Epoch == 0 ||
		!validSecurityID(request.BatchID) || !validSecurityID(request.RootPublicHandle) ||
		!validSecurityID(request.RootKeyVersion) || !nonzeroSecurityHash(request.RootPublicFingerprint) ||
		!nonzeroSecurityHash(request.AADHash) || len(request.PlaintextDEK) < 32 {
		return ErrInvalidData
	}
	if result.CeremonyType != request.CeremonyType || result.OperationID != request.OperationID ||
		result.PoolID != request.PoolID || result.Epoch != request.Epoch ||
		result.BatchID != request.BatchID || result.RootPublicHandle != request.RootPublicHandle ||
		result.RootKeyVersion != request.RootKeyVersion || result.RootPublicFingerprint != request.RootPublicFingerprint ||
		result.AADHash != request.AADHash {
		return ErrBindingMismatch
	}
	if !validSecurityID(result.WrapDomain) || !validSecurityID(result.WrapAlgorithm) || len(result.WrappedDEK) == 0 ||
		bytes.Equal(result.WrappedDEK, request.PlaintextDEK) || len(result.ProviderProof) == 0 {
		return ErrInvalidData
	}
	if err := verifier.VerifyCredentialDEKWrap(ctx, EpochDEKWrapVerifyRequest{Request: request, Result: result}); err != nil {
		return ErrSignatureInvalid
	}
	return nil
}

func VerifyStagedCredentialBatch(ctx context.Context, verifier ProviderAttestationVerifier,
	request EpochCredentialBatchRequest, result EpochCredentialBatchResult) error {
	if isNilProvider(verifier) {
		return ErrProviderUnavailable
	}
	if err := verifier.Ready(ctx); err != nil {
		return ErrProviderUnavailable
	}
	if !validCeremonyType(request.CeremonyType) || !validSecurityID(request.OperationID) ||
		!nonzeroSecurityHash(request.RequestHash) || request.RequestHash != EpochCredentialBatchRequestHash(request) ||
		!validSecurityID(request.PoolID) || request.Epoch == 0 || !validSecurityID(request.BatchID) ||
		!validSecurityID(request.ResourceAccountID) || !validSecurityID(request.AccountRef) ||
		!validControlBatchType(request.BatchType) || request.BatchVersion == 0 ||
		!validSecurityID(request.RootPublicHandle) || !validSecurityID(request.RootKeyVersion) ||
		!nonzeroSecurityHash(request.RootPublicFingerprint) || !validSecurityID(request.RootWrapDomain) ||
		!validSecurityID(request.RootWrapAlgorithm) || len(request.Payload) == 0 {
		return ErrInvalidData
	}
	batch := result.Batch
	if result.CeremonyType != request.CeremonyType || result.OperationID != request.OperationID ||
		result.RequestHash != request.RequestHash ||
		result.PoolID != request.PoolID || result.Epoch != request.Epoch ||
		batch.ExternalID != request.BatchID || batch.ResourceAccountExternalID != request.ResourceAccountID ||
		batch.AccountRef != request.AccountRef || batch.Type != request.BatchType ||
		batch.BatchVersion != request.BatchVersion || batch.RecoveryKeyHandle != request.RootPublicHandle ||
		batch.RecoveryKeyVersion != request.RootKeyVersion ||
		batch.RecoveryKeyFingerprint != request.RootPublicFingerprint ||
		batch.RecoveryWrapDomain != request.RootWrapDomain || batch.RecoveryWrapAlgorithm != request.RootWrapAlgorithm {
		return ErrBindingMismatch
	}
	if batch.EncryptionAlgorithm != credentials.BatchEnvelopeAlgorithm || len(batch.Ciphertext) == 0 ||
		len(batch.Nonce) != 12 || !nonzeroSecurityHash(batch.AADHash) ||
		!nonzeroSecurityHash(batch.ContentFingerprint) || !validSecurityID(batch.KMSWrapAlgorithm) ||
		!validSecurityID(batch.KMSKeyRef) || !validSecurityID(batch.KMSWrapperDomain) ||
		len(batch.WrappedDEKKMS) == 0 || len(batch.WrappedDEKRecovery) == 0 ||
		batch.KMSWrapperDomain == batch.RecoveryWrapDomain ||
		bytes.Equal(batch.WrappedDEKKMS, batch.WrappedDEKRecovery) || len(result.ProviderProof) == 0 ||
		sha256.Sum256(result.ProviderProof) != batch.ProviderWrapAttestationDigest ||
		!bytes.Equal(result.ProviderProof, batch.ProviderWrapAttestationSignature) {
		return ErrInvalidData
	}
	aad, err := credentials.CanonicalBatchAAD(request.OperationID, request.BatchID, request.PoolID,
		request.AccountRef, request.BatchType, request.BatchVersion, request.Epoch, batch.ContentFingerprint)
	if err != nil || sha256.Sum256(aad) != batch.AADHash ||
		credentials.RecoveryBindingHash(batch.RecoveryWrapDomain, batch.RecoveryWrapAlgorithm,
			batch.RecoveryKeyHandle, batch.AADHash, batch.WrappedDEKRecovery) != batch.RecoveryBindingHash {
		return ErrBindingMismatch
	}
	if err := verifier.VerifyStagedCredentialBatch(ctx, EpochCredentialBatchVerifyRequest{Request: request, Result: result}); err != nil {
		return ErrSignatureInvalid
	}
	return nil
}

// EpochCredentialBatchRequestHash 固定 provider 幂等请求域；Payload 只以摘要参与，避免明文进入日志或键值。
func EpochCredentialBatchRequestHash(request EpochCredentialBatchRequest) [sha256.Size]byte {
	var encoded bytes.Buffer
	writeSecurityString(&encoded, "trusted-pool/epoch-credential-batch-request/v1")
	writeSecurityString(&encoded, string(request.CeremonyType))
	writeSecurityString(&encoded, request.OperationID)
	writeSecurityString(&encoded, request.PoolID)
	writeSecurityUint64(&encoded, request.Epoch)
	writeSecurityString(&encoded, request.BatchID)
	writeSecurityString(&encoded, request.ResourceAccountID)
	writeSecurityString(&encoded, request.AccountRef)
	writeSecurityString(&encoded, string(request.BatchType))
	writeSecurityUint64(&encoded, request.BatchVersion)
	writeSecurityString(&encoded, request.RootPublicHandle)
	writeSecurityString(&encoded, request.RootKeyVersion)
	encoded.Write(request.RootPublicFingerprint[:])
	writeSecurityString(&encoded, request.RootWrapDomain)
	writeSecurityString(&encoded, request.RootWrapAlgorithm)
	payloadHash := sha256.Sum256(request.Payload)
	encoded.Write(payloadHash[:])
	return sha256.Sum256(encoded.Bytes())
}

// PermanentSeatRotationPrepareRequestHash 固定每个 Seat 的外部准备意图；RequestHash 本身不参与计算。
func PermanentSeatRotationPrepareRequestHash(request PermanentSeatRotationPrepareRequest) [sha256.Size]byte {
	var encoded bytes.Buffer
	writeSecurityString(&encoded, PermanentSeatRotationProtocolV1)
	writeSecurityString(&encoded, request.OperationID)
	writeSecurityString(&encoded, request.PlanID)
	writeSecurityString(&encoded, string(request.CeremonyType))
	writeSecurityString(&encoded, request.PoolID)
	writeSecurityUint64(&encoded, request.FromEpoch)
	writeSecurityUint64(&encoded, request.ToEpoch)
	writeSecurityString(&encoded, request.SeatID)
	writeSecurityString(&encoded, request.TargetMemberID)
	writeSecurityUint64(&encoded, request.ExpectedAssignmentEpoch)
	writeSecurityUint64(&encoded, uint64(request.PrincipalUserID))
	writeSecurityUint64(&encoded, uint64(request.SubscriptionID))
	writeSecurityUint64(&encoded, uint64(request.APIKeyID))
	writeSecurityUint64(&encoded, request.FromAPIKeyVersion)
	writeSecurityUint64(&encoded, request.ToAPIKeyVersion)
	return sha256.Sum256(encoded.Bytes())
}

// ValidatePermanentSeatRotationPrepareResult 拒绝任何错 Pool、错 Epoch、错稳定身份或错子操作的响应。
// Credential 的生命周期由调用方负责，校验函数不会复制或格式化该敏感值。
func ValidatePermanentSeatRotationPrepareResult(request PermanentSeatRotationPrepareRequest, result PermanentSeatRotationPrepareResult) error {
	if request.ProtocolVersion != PermanentSeatRotationProtocolV1 ||
		!validSecurityID(request.OperationID) || !validSecurityID(request.PlanID) ||
		!validCeremonyType(request.CeremonyType) || !validSecurityID(request.PoolID) ||
		request.FromEpoch == 0 || request.ToEpoch != request.FromEpoch+1 ||
		!validSecurityID(request.SeatID) || !validSecurityID(request.TargetMemberID) ||
		request.ExpectedAssignmentEpoch == 0 || request.PrincipalUserID <= 0 ||
		request.SubscriptionID <= 0 || request.APIKeyID <= 0 || request.FromAPIKeyVersion == 0 ||
		request.ToAPIKeyVersion != request.FromAPIKeyVersion+1 ||
		request.ToAPIKeyVersion != request.ExpectedAssignmentEpoch+1 ||
		!nonzeroSecurityHash(request.RequestHash) ||
		request.RequestHash != PermanentSeatRotationPrepareRequestHash(request) {
		return ErrInvalidData
	}
	if result.ProtocolVersion != request.ProtocolVersion || result.OperationID != request.OperationID ||
		result.RequestHash != request.RequestHash || result.PlanID != request.PlanID ||
		result.CeremonyType != request.CeremonyType || result.PoolID != request.PoolID ||
		result.FromEpoch != request.FromEpoch || result.ToEpoch != request.ToEpoch ||
		result.SeatID != request.SeatID || result.TargetMemberID != request.TargetMemberID ||
		result.AssignmentEpoch != request.ExpectedAssignmentEpoch+1 ||
		result.PrincipalUserID != request.PrincipalUserID || result.SubscriptionID != request.SubscriptionID ||
		result.APIKeyID != request.APIKeyID || result.ActiveAPIKeyVersion != request.ToAPIKeyVersion {
		return ErrBindingMismatch
	}
	if !strings.EqualFold(result.State, "ROTATION_PREPARED") || result.CredentialEnabled ||
		result.SubscriptionEnabled || !result.CredentialRotationComplete || len(result.Credential) == 0 ||
		!validSecurityID(result.PreparedRotationRef) || result.CompletedAt.IsZero() {
		return ErrInvalidData
	}
	return nil
}

func PermanentRotationChildSetHash(seats []PermanentSeatRotationPrepareRequest) ([sha256.Size]byte, error) {
	var encoded bytes.Buffer
	writeSecurityString(&encoded, "trusted-pool/permanent-rotation-child-set/v1")
	writeSecurityUint32(&encoded, uint32(len(seats)))
	for index, seat := range seats {
		if seat.RequestHash != PermanentSeatRotationPrepareRequestHash(seat) ||
			index > 0 && seats[index-1].SeatID >= seat.SeatID {
			return [sha256.Size]byte{}, ErrInvalidData
		}
		writeSecurityString(&encoded, seat.SeatID)
		writeSecurityString(&encoded, seat.OperationID)
		encoded.Write(seat.RequestHash[:])
	}
	return sha256.Sum256(encoded.Bytes()), nil
}

func PermanentPoolRotationPrepareRequestHash(request PermanentPoolRotationPrepareRequest) [sha256.Size]byte {
	var encoded bytes.Buffer
	writeSecurityString(&encoded, "trusted-pool/permanent-pool-rotation-prepare/v1")
	writeSecurityString(&encoded, request.OperationID)
	writeSecurityString(&encoded, request.PlanID)
	writeSecurityString(&encoded, string(request.CeremonyType))
	writeSecurityString(&encoded, request.PoolID)
	writeSecurityUint64(&encoded, request.FromEpoch)
	writeSecurityUint64(&encoded, request.ToEpoch)
	encoded.Write(request.ChildSetHash[:])
	return sha256.Sum256(encoded.Bytes())
}

func ValidatePermanentPoolRotationPrepareResult(request PermanentPoolRotationPrepareRequest,
	result PermanentPoolRotationPrepareResult) error {
	wantSetHash, err := PermanentRotationChildSetHash(request.Seats)
	if err != nil || request.ProtocolVersion != PermanentSeatRotationProtocolV1 ||
		!validSecurityID(request.OperationID) || !validSecurityID(request.PlanID) ||
		!validCeremonyType(request.CeremonyType) || !validSecurityID(request.PoolID) ||
		request.FromEpoch == 0 || request.ToEpoch != request.FromEpoch+1 ||
		request.ChildSetHash != wantSetHash || request.RequestHash != PermanentPoolRotationPrepareRequestHash(request) {
		return ErrInvalidData
	}
	if result.ProtocolVersion != request.ProtocolVersion || result.OperationID != request.OperationID ||
		result.RequestHash != request.RequestHash || result.PlanID != request.PlanID ||
		result.CeremonyType != request.CeremonyType || result.PoolID != request.PoolID ||
		result.FromEpoch != request.FromEpoch || result.ToEpoch != request.ToEpoch ||
		result.ChildSetHash != request.ChildSetHash || len(result.Seats) != len(request.Seats) {
		return ErrBindingMismatch
	}
	for index := range request.Seats {
		if err := ValidatePermanentSeatRotationPrepareResult(request.Seats[index], result.Seats[index]); err != nil {
			return err
		}
	}
	return nil
}

// PermanentSeatCredentialAAD 绑定 claim 密文与该 Seat 的完整 rotation intent 和凭据指纹。
func PermanentSeatCredentialAAD(request PermanentSeatRotationPrepareRequest, fingerprint [sha256.Size]byte) []byte {
	return ReplacementCredentialClaimAAD("", request.PlanID, request.OperationID, request.SeatID,
		request.TargetMemberID, request.RequestHash, fingerprint)
}

// PermanentSeatRotationPrepareResultDigest 不包含凭据明文，但通过 fingerprint 将结果绑定到该凭据。
func PermanentSeatRotationPrepareResultDigest(result PermanentSeatRotationPrepareResult,
	fingerprint [sha256.Size]byte) [sha256.Size]byte {
	var encoded bytes.Buffer
	writeSecurityString(&encoded, "trusted-pool/permanent-seat-rotation-prepare-result/v1")
	writeSecurityString(&encoded, result.ProtocolVersion)
	writeSecurityString(&encoded, result.OperationID)
	encoded.Write(result.RequestHash[:])
	writeSecurityString(&encoded, result.PlanID)
	writeSecurityString(&encoded, string(result.CeremonyType))
	writeSecurityString(&encoded, result.PoolID)
	writeSecurityUint64(&encoded, result.FromEpoch)
	writeSecurityUint64(&encoded, result.ToEpoch)
	writeSecurityString(&encoded, result.SeatID)
	writeSecurityString(&encoded, result.TargetMemberID)
	writeSecurityUint64(&encoded, result.AssignmentEpoch)
	writeSecurityUint64(&encoded, uint64(result.PrincipalUserID))
	writeSecurityUint64(&encoded, uint64(result.SubscriptionID))
	writeSecurityUint64(&encoded, uint64(result.APIKeyID))
	writeSecurityUint64(&encoded, result.ActiveAPIKeyVersion)
	writeSecurityString(&encoded, result.State)
	encoded.Write(fingerprint[:])
	writeSecurityString(&encoded, result.PreparedRotationRef)
	writeSecurityString(&encoded, result.CompletedAt.UTC().Format(time.RFC3339Nano))
	return sha256.Sum256(encoded.Bytes())
}

// ReplacementCredentialClaimAAD 可由重启后的领取流程仅用持久化非秘密字段精确重建。
func ReplacementCredentialClaimAAD(clientID, planID, operationID, seatID, targetMemberID string,
	intentHash, fingerprint [sha256.Size]byte) []byte {
	var encoded bytes.Buffer
	writeSecurityString(&encoded, "trusted-pool/permanent-seat-credential-claim/v1")
	writeSecurityString(&encoded, clientID)
	writeSecurityString(&encoded, planID)
	writeSecurityString(&encoded, operationID)
	writeSecurityString(&encoded, seatID)
	writeSecurityString(&encoded, targetMemberID)
	encoded.Write(intentHash[:])
	encoded.Write(fingerprint[:])
	return encoded.Bytes()
}

func PermanentPreparedSeatSetHash(seats []PermanentSeatActivationBinding) ([sha256.Size]byte, error) {
	var encoded bytes.Buffer
	writeSecurityString(&encoded, "trusted-pool/permanent-prepared-seat-set/v1")
	writeSecurityUint32(&encoded, uint32(len(seats)))
	for index, seat := range seats {
		if !validSecurityID(seat.SeatID) || !validSecurityID(seat.TargetMemberID) ||
			seat.ExpectedAssignmentEpoch == 0 || seat.PrincipalUserID <= 0 || seat.SubscriptionID <= 0 || seat.APIKeyID <= 0 ||
			seat.ActiveAPIKeyVersion != seat.ExpectedAssignmentEpoch+1 || !nonzeroSecurityHash(seat.CredentialFingerprint) ||
			!validSecurityID(seat.ChildOperationID) || !nonzeroSecurityHash(seat.ChildRequestHash) ||
			!validSecurityID(seat.PreparedRotationRef) || index > 0 && seats[index-1].SeatID >= seat.SeatID {
			return [sha256.Size]byte{}, ErrInvalidData
		}
		writeSecurityString(&encoded, seat.SeatID)
		writeSecurityString(&encoded, seat.TargetMemberID)
		writeSecurityUint64(&encoded, seat.ExpectedAssignmentEpoch)
		writeSecurityUint64(&encoded, uint64(seat.PrincipalUserID))
		writeSecurityUint64(&encoded, uint64(seat.SubscriptionID))
		writeSecurityUint64(&encoded, uint64(seat.APIKeyID))
		writeSecurityUint64(&encoded, seat.ActiveAPIKeyVersion)
		encoded.Write(seat.CredentialFingerprint[:])
		writeSecurityString(&encoded, seat.PreparedRotationRef)
		writeSecurityString(&encoded, seat.ChildOperationID)
		encoded.Write(seat.ChildRequestHash[:])
	}
	return sha256.Sum256(encoded.Bytes()), nil
}

func PermanentPoolRotationActivateRequestHash(request PermanentPoolRotationActivateRequest) [sha256.Size]byte {
	var encoded bytes.Buffer
	writeSecurityString(&encoded, "trusted-pool/permanent-pool-rotation-activate/v1")
	writeSecurityString(&encoded, request.OperationID)
	writeSecurityString(&encoded, request.PrepareOperationID)
	writeSecurityString(&encoded, request.PlanID)
	writeSecurityString(&encoded, string(request.CeremonyType))
	writeSecurityString(&encoded, request.PoolID)
	writeSecurityUint64(&encoded, request.FromEpoch)
	writeSecurityUint64(&encoded, request.ToEpoch)
	encoded.Write(request.PreparedSetHash[:])
	return sha256.Sum256(encoded.Bytes())
}

func VerifyPermanentPoolRotationActivateResult(ctx context.Context, verifier PermanentSeatActivationVerifier,
	request PermanentPoolRotationActivateRequest, result PermanentPoolRotationActivateResult) error {
	if isNilProvider(verifier) {
		return ErrProviderUnavailable
	}
	if err := verifier.Ready(ctx); err != nil {
		return ErrProviderUnavailable
	}
	wantSetHash, err := PermanentPreparedSeatSetHash(request.Seats)
	if err != nil || request.ProtocolVersion != PermanentSeatRotationProtocolV1 || !validSecurityID(request.OperationID) ||
		!validSecurityID(request.PrepareOperationID) || !validSecurityID(request.PlanID) ||
		!validCeremonyType(request.CeremonyType) || !validSecurityID(request.PoolID) ||
		request.FromEpoch == 0 || request.ToEpoch != request.FromEpoch+1 || request.PreparedSetHash != wantSetHash ||
		!nonzeroSecurityHash(request.RequestHash) || request.RequestHash != PermanentPoolRotationActivateRequestHash(request) {
		return ErrInvalidData
	}
	if result.ProtocolVersion != request.ProtocolVersion || result.OperationID != request.OperationID ||
		result.PrepareOperationID != request.PrepareOperationID ||
		result.RequestHash != request.RequestHash || result.PlanID != request.PlanID ||
		result.CeremonyType != request.CeremonyType || result.PoolID != request.PoolID ||
		result.FromEpoch != request.FromEpoch || result.ToEpoch != request.ToEpoch ||
		result.PreparedSetHash != request.PreparedSetHash || len(result.Seats) != len(request.Seats) {
		return ErrBindingMismatch
	}
	for index := range request.Seats {
		seat := result.Seats[index]
		if !reflect.DeepEqual(seat.PermanentSeatActivationBinding, request.Seats[index]) ||
			seat.AssignmentEpoch != request.Seats[index].ExpectedAssignmentEpoch+1 ||
			!strings.EqualFold(seat.State, "ROTATION_ACTIVATED_PENDING_COMMIT") ||
			seat.CurrentConcurrency != 0 || seat.PendingSettlements != 0 {
			return ErrBindingMismatch
		}
	}
	if !strings.EqualFold(result.State, "ACTIVATED_PENDING_COMMIT") || result.AllCredentialsEnabled ||
		result.AllSubscriptionsEnabled || !result.OldCredentialSetInvalidated || result.AuthorizationCacheInvalidated ||
		!result.CredentialFingerprintGateEnforced || !result.AuthCacheDurableOutbox ||
		result.AuthCacheMinimumEvents < 2*len(request.Seats) || !validSecurityID(result.AttestationAlgorithm) ||
		!validSecurityID(result.AttestationIssuer) || !validSecurityID(result.AttestationRef) ||
		!validSecurityID(result.AttestationKeyID) || result.AttestationVersion == 0 ||
		!nonzeroSecurityHash(result.AttestationDigest) || len(result.Attestation) == 0 || result.ActivatedAt.IsZero() {
		return ErrInvalidData
	}
	if err := verifier.VerifyPoolActivation(ctx, PermanentPoolActivationVerifyRequest{
		Request: request, Result: result,
	}); err != nil {
		return ErrSignatureInvalid
	}
	return nil
}

func PermanentPoolRotationCommitRequestHash(request PermanentPoolRotationCommitRequest) [sha256.Size]byte {
	var encoded bytes.Buffer
	writeSecurityString(&encoded, "trusted-pool/permanent-pool-rotation-commit/v1")
	writeSecurityString(&encoded, request.OperationID)
	writeSecurityString(&encoded, request.PrepareOperationID)
	writeSecurityString(&encoded, request.ActivationOperationID)
	encoded.Write(request.ActivationRequestHash[:])
	writeSecurityString(&encoded, request.PlanID)
	writeSecurityString(&encoded, string(request.CeremonyType))
	writeSecurityString(&encoded, request.PoolID)
	writeSecurityUint64(&encoded, request.FromEpoch)
	writeSecurityUint64(&encoded, request.ToEpoch)
	encoded.Write(request.PreparedSetHash[:])
	return sha256.Sum256(encoded.Bytes())
}

func VerifyPermanentPoolRotationCommitResult(ctx context.Context, verifier PermanentSeatActivationVerifier,
	request PermanentPoolRotationCommitRequest, result PermanentPoolRotationCommitResult) error {
	if isNilProvider(verifier) {
		return ErrProviderUnavailable
	}
	if err := verifier.Ready(ctx); err != nil {
		return ErrProviderUnavailable
	}
	wantSetHash, err := PermanentPreparedSeatSetHash(request.Seats)
	if err != nil || request.ProtocolVersion != PermanentSeatRotationProtocolV1 ||
		!validSecurityID(request.OperationID) || !validSecurityID(request.PrepareOperationID) ||
		!validSecurityID(request.ActivationOperationID) || !nonzeroSecurityHash(request.ActivationRequestHash) ||
		!validSecurityID(request.PlanID) || !validCeremonyType(request.CeremonyType) ||
		!validSecurityID(request.PoolID) || request.FromEpoch == 0 || request.ToEpoch != request.FromEpoch+1 ||
		request.PreparedSetHash != wantSetHash || request.RequestHash != PermanentPoolRotationCommitRequestHash(request) {
		return ErrInvalidData
	}
	if result.ProtocolVersion != request.ProtocolVersion || result.OperationID != request.OperationID ||
		result.PrepareOperationID != request.PrepareOperationID ||
		result.ActivationOperationID != request.ActivationOperationID ||
		result.ActivationRequestHash != request.ActivationRequestHash || result.RequestHash != request.RequestHash ||
		result.PlanID != request.PlanID || result.CeremonyType != request.CeremonyType || result.PoolID != request.PoolID ||
		result.FromEpoch != request.FromEpoch || result.ToEpoch != request.ToEpoch ||
		result.PreparedSetHash != request.PreparedSetHash || len(result.Seats) != len(request.Seats) {
		return ErrBindingMismatch
	}
	for index := range request.Seats {
		seat := result.Seats[index]
		if !reflect.DeepEqual(seat.PermanentSeatActivationBinding, request.Seats[index]) ||
			seat.AssignmentEpoch != request.Seats[index].ExpectedAssignmentEpoch+1 ||
			!strings.EqualFold(seat.State, "ACTIVE") || seat.CurrentConcurrency != 0 || seat.PendingSettlements != 0 {
			return ErrBindingMismatch
		}
	}
	if !strings.EqualFold(result.State, "COMMITTED") || !result.AllCredentialsEnabled ||
		!result.AllSubscriptionsEnabled || !result.OldCredentialSetInvalidated ||
		result.AuthorizationCacheInvalidated || !result.CredentialFingerprintGateEnforced ||
		!result.AuthCacheDurableOutbox || result.AuthCacheMinimumEvents < len(request.Seats) ||
		!validSecurityID(result.AttestationAlgorithm) || !validSecurityID(result.AttestationIssuer) ||
		!validSecurityID(result.AttestationRef) || !validSecurityID(result.AttestationKeyID) ||
		result.AttestationVersion == 0 || !nonzeroSecurityHash(result.AttestationDigest) ||
		len(result.Attestation) == 0 || result.CommittedAt.IsZero() {
		return ErrInvalidData
	}
	if err := verifier.VerifyPoolCommit(ctx, PermanentPoolCommitVerifyRequest{Request: request, Result: result}); err != nil {
		return ErrSignatureInvalid
	}
	return nil
}

// PermanentPoolRotationActivationAttestationDigest 与 Sub2API 的 Ed25519 签名输入逐字节一致。
func PermanentPoolRotationActivationAttestationDigest(result PermanentPoolRotationActivateResult) ([sha256.Size]byte, error) {
	if result.ProtocolVersion != PermanentSeatRotationProtocolV1 || len(result.Seats) == 0 {
		return [sha256.Size]byte{}, ErrInvalidData
	}
	var encoded bytes.Buffer
	writeSecurityString(&encoded, "trusted-pool/permanent-pool-rotation-activate-attestation/v1")
	writeSecurityString(&encoded, result.ProtocolVersion)
	writeSecurityString(&encoded, result.OperationID)
	writeSecurityString(&encoded, result.PrepareOperationID)
	encoded.Write(result.RequestHash[:])
	writeSecurityString(&encoded, result.PlanID)
	writeSecurityString(&encoded, string(result.CeremonyType))
	writeSecurityString(&encoded, result.PoolID)
	writeSecurityUint64(&encoded, result.FromEpoch)
	writeSecurityUint64(&encoded, result.ToEpoch)
	encoded.Write(result.PreparedSetHash[:])
	writeSecurityString(&encoded, result.State)
	writeSecurityBool(&encoded, result.AllCredentialsEnabled)
	writeSecurityBool(&encoded, result.AllSubscriptionsEnabled)
	writeSecurityBool(&encoded, result.OldCredentialSetInvalidated)
	writeSecurityBool(&encoded, result.AuthorizationCacheInvalidated)
	writeSecurityBool(&encoded, result.CredentialFingerprintGateEnforced)
	writeSecurityBool(&encoded, result.AuthCacheDurableOutbox)
	writeSecurityUint64(&encoded, uint64(result.AuthCacheMinimumEvents))
	writeSecurityString(&encoded, result.ActivatedAt.UTC().Format(time.RFC3339Nano))
	writeSecurityUint32(&encoded, uint32(len(result.Seats)))
	for index, seat := range result.Seats {
		if index > 0 && result.Seats[index-1].SeatID >= seat.SeatID || seat.CurrentConcurrency != 0 ||
			seat.PendingSettlements != 0 {
			return [sha256.Size]byte{}, ErrInvalidData
		}
		writeSecurityString(&encoded, seat.SeatID)
		writeSecurityString(&encoded, seat.TargetMemberID)
		writeSecurityUint64(&encoded, seat.ExpectedAssignmentEpoch)
		writeSecurityUint64(&encoded, seat.AssignmentEpoch)
		writeSecurityUint64(&encoded, uint64(seat.PrincipalUserID))
		writeSecurityUint64(&encoded, uint64(seat.SubscriptionID))
		writeSecurityUint64(&encoded, uint64(seat.APIKeyID))
		writeSecurityUint64(&encoded, seat.ActiveAPIKeyVersion)
		encoded.Write(seat.CredentialFingerprint[:])
		writeSecurityString(&encoded, seat.PreparedRotationRef)
		writeSecurityString(&encoded, seat.ChildOperationID)
		encoded.Write(seat.ChildRequestHash[:])
		writeSecurityUint64(&encoded, seat.CurrentConcurrency)
		writeSecurityUint64(&encoded, seat.PendingSettlements)
	}
	return sha256.Sum256(encoded.Bytes()), nil
}

func PermanentPoolRotationCommitAttestationDigest(result PermanentPoolRotationCommitResult) ([sha256.Size]byte, error) {
	if result.ProtocolVersion != PermanentSeatRotationProtocolV1 || len(result.Seats) == 0 {
		return [sha256.Size]byte{}, ErrInvalidData
	}
	var encoded bytes.Buffer
	writeSecurityString(&encoded, "trusted-pool/permanent-pool-rotation-commit-attestation/v1")
	writeSecurityString(&encoded, result.ProtocolVersion)
	writeSecurityString(&encoded, result.OperationID)
	writeSecurityString(&encoded, result.PrepareOperationID)
	writeSecurityString(&encoded, result.ActivationOperationID)
	encoded.Write(result.RequestHash[:])
	encoded.Write(result.ActivationRequestHash[:])
	writeSecurityString(&encoded, result.PlanID)
	writeSecurityString(&encoded, string(result.CeremonyType))
	writeSecurityString(&encoded, result.PoolID)
	writeSecurityUint64(&encoded, result.FromEpoch)
	writeSecurityUint64(&encoded, result.ToEpoch)
	encoded.Write(result.PreparedSetHash[:])
	writeSecurityString(&encoded, result.State)
	writeSecurityBool(&encoded, result.AllCredentialsEnabled)
	writeSecurityBool(&encoded, result.AllSubscriptionsEnabled)
	writeSecurityBool(&encoded, result.OldCredentialSetInvalidated)
	writeSecurityBool(&encoded, result.AuthorizationCacheInvalidated)
	writeSecurityBool(&encoded, result.CredentialFingerprintGateEnforced)
	writeSecurityBool(&encoded, result.AuthCacheDurableOutbox)
	writeSecurityUint64(&encoded, uint64(result.AuthCacheMinimumEvents))
	writeSecurityString(&encoded, result.CommittedAt.UTC().Format(time.RFC3339Nano))
	writeSecurityUint32(&encoded, uint32(len(result.Seats)))
	for index, seat := range result.Seats {
		if index > 0 && result.Seats[index-1].SeatID >= seat.SeatID ||
			seat.CurrentConcurrency != 0 || seat.PendingSettlements != 0 {
			return [sha256.Size]byte{}, ErrInvalidData
		}
		writeSecurityString(&encoded, seat.SeatID)
		writeSecurityString(&encoded, seat.TargetMemberID)
		writeSecurityUint64(&encoded, seat.ExpectedAssignmentEpoch)
		writeSecurityUint64(&encoded, seat.AssignmentEpoch)
		writeSecurityUint64(&encoded, uint64(seat.PrincipalUserID))
		writeSecurityUint64(&encoded, uint64(seat.SubscriptionID))
		writeSecurityUint64(&encoded, uint64(seat.APIKeyID))
		writeSecurityUint64(&encoded, seat.ActiveAPIKeyVersion)
		encoded.Write(seat.CredentialFingerprint[:])
		writeSecurityString(&encoded, seat.PreparedRotationRef)
		writeSecurityString(&encoded, seat.ChildOperationID)
		encoded.Write(seat.ChildRequestHash[:])
		writeSecurityUint64(&encoded, seat.CurrentConcurrency)
		writeSecurityUint64(&encoded, seat.PendingSettlements)
	}
	return sha256.Sum256(encoded.Bytes()), nil
}

func writeSecurityBool(target *bytes.Buffer, value bool) {
	if value {
		target.WriteByte(1)
		return
	}
	target.WriteByte(0)
}

func VerifyRecoveryPackage(ctx context.Context, verifier ProviderAttestationVerifier, request RecoveryPackageRequest, pkg EncryptedRecoveryPackage) error {
	if isNilProvider(verifier) {
		return ErrProviderUnavailable
	}
	if err := verifier.Ready(ctx); err != nil {
		return ErrProviderUnavailable
	}
	if err := ValidateEncryptedRecoveryPackage(request, pkg); err != nil {
		return err
	}
	if err := verifier.VerifyRecoveryPackage(ctx, RecoveryPackageVerifyRequest{Request: request, Package: pkg}); err != nil {
		return ErrSignatureInvalid
	}
	for i, share := range pkg.EncryptedShares {
		verifyRequest := EncryptedShareVerifyRequest{
			CeremonyType: request.CeremonyType, OperationID: request.OperationID, PoolID: request.PoolID, Epoch: request.ToEpoch,
			ProviderID: pkg.ProviderID, RootPublicHandle: pkg.RootPublicHandle,
			RootPublicFingerprint: pkg.RootPublicFingerprint, PackageHash: pkg.PackageHash,
			Member: request.Members[i], Share: share, VSSCommitment: pkg.VSSCommitment,
		}
		if err := verifier.VerifyEncryptedShare(ctx, verifyRequest); err != nil {
			return ErrSignatureInvalid
		}
	}
	return nil
}

func ValidateProviderAttestation(intent ProviderAttestationIntent, verified VerifiedProviderAttestation, now time.Time) error {
	if intent.Version == 0 || !validCeremonyType(intent.CeremonyType) ||
		!validSecurityID(intent.OperationID) || !validSecurityID(intent.PoolID) ||
		intent.FromEpoch == 0 || intent.ToEpoch != intent.FromEpoch+1 {
		return ErrInvalidData
	}
	if err := validatePlanCollections(intent.Seats, intent.Accounts, nil); err != nil {
		return err
	}
	if err := validateCeremonyPlan(intent.CeremonyType, intent.FromEpochStatus, intent.FromGovernanceState,
		intent.PreviousManifestHash, intent.Seats, intent.Replacements); err != nil {
		return err
	}
	wantPurpose := rotationAttestationPurpose
	if intent.CeremonyType == CeremonyBootstrap {
		wantPurpose = bootstrapAttestationPurpose
	}
	if verified.Version != intent.Version || verified.CeremonyType != intent.CeremonyType ||
		verified.Purpose != wantPurpose || verified.OperationID != intent.OperationID ||
		verified.PoolID != intent.PoolID || verified.FromEpoch != intent.FromEpoch || verified.ToEpoch != intent.ToEpoch ||
		verified.FromEpochStatus != intent.FromEpochStatus || verified.FromGovernanceState != intent.FromGovernanceState ||
		verified.PreviousManifestHash != intent.PreviousManifestHash ||
		!reflect.DeepEqual(verified.Replacements, intent.Replacements) ||
		!reflect.DeepEqual(verified.Seats, intent.Seats) || !reflect.DeepEqual(verified.Accounts, intent.Accounts) {
		return ErrBindingMismatch
	}
	if !validSecurityID(verified.Issuer) || !validSecurityID(verified.VerificationKeyID) ||
		!validSecurityID(verified.Reference) || !nonzeroSecurityHash(verified.CanonicalDigest) ||
		verified.IssuedAt.IsZero() || verified.ExpiresAt.IsZero() || !verified.ExpiresAt.After(verified.IssuedAt) ||
		now.Before(verified.IssuedAt) || !now.Before(verified.ExpiresAt) {
		return ErrInvalidData
	}
	return nil
}

func VerifyProviderControlAttestation(ctx context.Context, verifier ProviderAttestationVerifier,
	request ProviderAttestationVerifyRequest, now time.Time) (VerifiedProviderAttestation, error) {
	if isNilProvider(verifier) {
		return VerifiedProviderAttestation{}, ErrProviderUnavailable
	}
	if err := verifier.Ready(ctx); err != nil {
		return VerifiedProviderAttestation{}, ErrProviderUnavailable
	}
	verified, err := verifier.VerifyControlAttestation(ctx, request)
	if err != nil {
		return VerifiedProviderAttestation{}, ErrSignatureInvalid
	}
	if err := ValidateProviderAttestation(request.Intent, verified, now); err != nil {
		return VerifiedProviderAttestation{}, err
	}
	return verified, nil
}

func BuildCanonicalManifest(ctx context.Context, canonicalizer ManifestCanonicalizer, payload ManifestPayload) (CanonicalManifest, error) {
	if isNilProvider(canonicalizer) {
		return CanonicalManifest{}, ErrProviderUnavailable
	}
	if err := canonicalizer.Ready(ctx); err != nil {
		return CanonicalManifest{}, ErrProviderUnavailable
	}
	if err := ValidateManifestPayload(payload); err != nil {
		return CanonicalManifest{}, err
	}
	raw, err := json.Marshal(payload)
	if err != nil {
		return CanonicalManifest{}, errors.Join(ErrCanonicalization, err)
	}
	canonical, err := canonicalizer.Canonicalize(ctx, raw)
	if err != nil || len(canonical) == 0 || !json.Valid(canonical) {
		return CanonicalManifest{}, ErrCanonicalization
	}
	again, err := canonicalizer.Canonicalize(ctx, canonical)
	if err != nil || !bytes.Equal(canonical, again) {
		return CanonicalManifest{}, ErrCanonicalization
	}
	rawValue, err := decodeSingleJSON(raw)
	if err != nil {
		return CanonicalManifest{}, errors.Join(ErrCanonicalization, err)
	}
	canonicalValue, err := decodeSingleJSON(canonical)
	if err != nil || !reflect.DeepEqual(rawValue, canonicalValue) {
		return CanonicalManifest{}, errors.Join(ErrCanonicalization, ErrBindingMismatch, err)
	}
	result := CanonicalManifest{Payload: payload, Bytes: append([]byte(nil), canonical...)}
	result.Hash = sha256.Sum256(result.Bytes)
	return result, nil
}

func ValidateManifestPayload(payload ManifestPayload) error {
	if payload.ProtocolVersion != ProtocolVersionV1 || !validCeremonyType(payload.CeremonyType) ||
		!validSecurityID(payload.OperationID) ||
		!validSecurityID(payload.PoolID) || payload.FromEpoch == 0 || payload.Epoch != payload.FromEpoch+1 ||
		payload.GovernanceThreshold == 0 || payload.RecoveryThreshold == 0 ||
		int(payload.GovernanceThreshold) > len(payload.Members) || int(payload.RecoveryThreshold) > len(payload.Members) ||
		int(payload.RequiredShareAcknowledges) != len(payload.Members) || len(payload.Members) == 0 {
		return ErrInvalidData
	}
	createdAt, err := time.Parse(time.RFC3339Nano, payload.CreatedAt)
	if err != nil || createdAt.UTC().Format(time.RFC3339Nano) != payload.CreatedAt {
		return ErrInvalidData
	}
	previousHash, err := decodeOptionalHash(payload.PreviousManifestHash)
	if err != nil {
		return ErrBindingMismatch
	}
	setHash, err := ProviderAttestationSetHash(payload.Accounts)
	if err != nil || hex.EncodeToString(setHash[:]) != payload.ProviderAttestationSetHash {
		return ErrInvalidData
	}
	if err := validateManifestMembers(payload.Members); err != nil {
		return err
	}
	if err := validatePlanCollections(payload.Seats, payload.Accounts, manifestMemberIDs(payload.Members)); err != nil {
		return err
	}
	if err := validateCeremonyPlan(payload.CeremonyType, payload.FromEpochStatus, payload.FromGovernanceState,
		previousHash, payload.Seats, payload.Replacements); err != nil {
		return err
	}
	wantPurpose := rotationAttestationPurpose
	if payload.CeremonyType == CeremonyBootstrap {
		wantPurpose = bootstrapAttestationPurpose
	}
	if !validLowerHash(payload.CeremonyAttestationDigest) || payload.CeremonyAttestationPurpose != wantPurpose ||
		!validSecurityID(payload.CeremonyAttestationIssuer) ||
		!validSecurityID(payload.CeremonyAttestationKeyID) || !validSecurityID(payload.CeremonyAttestationReference) ||
		payload.CeremonyAttestationVersion == 0 {
		return ErrInvalidData
	}
	if err := validateManifestShares(payload.EncryptedShares, payload.Members); err != nil {
		return err
	}
	root := payload.RecoveryRoot
	if !validSecurityID(root.PublicAlgorithm) || !validSecurityID(root.PublicHandle) ||
		!validLowerHash(root.PublicFingerprint) || !validSecurityID(root.WrapDomain) ||
		!validSecurityID(root.WrapAlgorithm) || !validSecurityID(root.ProviderID) ||
		!validSecurityID(root.KeyVersion) || !validLowerHash(root.PrivateCommitmentHash) ||
		!validSecurityID(root.VSSAlgorithm) || !validLowerHash(root.VSSCommitmentHash) ||
		!validLowerHash(root.VSSProofHash) || !validLowerHash(root.PackageHash) {
		return ErrInvalidData
	}
	return nil
}

func validatePlatformManifestSignature(request PlatformManifestSignRequest, result PlatformManifestSignature) error {
	if !validCeremonyType(request.CeremonyType) || !validSecurityID(request.OperationID) ||
		!validSecurityID(request.PoolID) || request.Epoch == 0 ||
		!nonzeroSecurityHash(request.ManifestHash) || len(request.Canonical) == 0 ||
		sha256.Sum256(request.Canonical) != request.ManifestHash ||
		(request.SignatureDomain != "" && request.SignatureDomain != PlatformManifestSignatureV2) {
		return ErrInvalidData
	}
	if result.CeremonyType != request.CeremonyType || result.OperationID != request.OperationID || result.PoolID != request.PoolID ||
		result.Epoch != request.Epoch || result.ManifestHash != request.ManifestHash ||
		result.SignatureDomain != request.SignatureDomain {
		return ErrBindingMismatch
	}
	if !validSecurityID(result.Algorithm) || !validSecurityID(result.KeyID) || len(result.Signature) == 0 || result.SignedAt.IsZero() {
		return ErrSignatureInvalid
	}
	return nil
}

// BuildPlatformManifestSignatureMessageV2 freezes the portable HSM signature transcript.
func BuildPlatformManifestSignatureMessageV2(canonicalManifest []byte) ([]byte, error) {
	if len(canonicalManifest) == 0 {
		return nil, ErrInvalidData
	}
	message := make([]byte, 0, len(PlatformManifestSignatureV2)+1+len(canonicalManifest))
	message = append(message, PlatformManifestSignatureV2...)
	message = append(message, 0)
	message = append(message, canonicalManifest...)
	return message, nil
}

func VerifyPlatformManifestSignature(ctx context.Context, signer PlatformSigner, request PlatformManifestSignRequest, result PlatformManifestSignature) error {
	if isNilProvider(signer) {
		return ErrProviderUnavailable
	}
	if err := signer.Ready(ctx); err != nil {
		return ErrProviderUnavailable
	}
	if err := validatePlatformManifestSignature(request, result); err != nil {
		return err
	}
	if err := signer.VerifyManifestSignature(ctx, PlatformManifestVerifyRequest{Request: request, Signature: result}); err != nil {
		return ErrSignatureInvalid
	}
	return nil
}

func VerifyMemberKeyPossession(ctx context.Context, verifier MemberSignatureVerifier, intent MemberKeyProofIntent,
	publicKey, proof []byte) error {
	if isNilProvider(verifier) {
		return ErrProviderUnavailable
	}
	if err := verifier.Ready(ctx); err != nil {
		return ErrProviderUnavailable
	}
	if len(publicKey) == 0 || sha256.Sum256(publicKey) != intent.KeyFingerprint || len(proof) == 0 {
		return ErrInvalidData
	}
	message, err := BuildMemberKeyProofMessage(intent)
	if err != nil {
		return err
	}
	request := MemberKeyProofVerifyRequest{MemberID: intent.MemberID, Purpose: intent.Purpose,
		Algorithm: intent.Algorithm, KeyID: intent.KeyID, PublicKey: publicKey, Message: message, Proof: proof}
	if err := verifier.VerifyMemberKeyProof(ctx, request); err != nil {
		return ErrSignatureInvalid
	}
	return nil
}

func VerifyMemberManifestApproval(ctx context.Context, verifier MemberSignatureVerifier, member RecoveryMember,
	approval MemberManifestApproval, algorithm, keyID string, signature []byte) ([sha256.Size]byte, error) {
	if isNilProvider(verifier) {
		return [sha256.Size]byte{}, ErrProviderUnavailable
	}
	if err := verifier.Ready(ctx); err != nil {
		return [sha256.Size]byte{}, ErrProviderUnavailable
	}
	if approval.MemberID != member.MemberID || algorithm != member.SigningAlgorithm || keyID != member.SigningKeyID ||
		len(member.SigningPublicKey) == 0 || sha256.Sum256(member.SigningPublicKey) != member.SigningKeyFingerprint || len(signature) == 0 {
		return [sha256.Size]byte{}, ErrBindingMismatch
	}
	message, err := BuildMemberManifestSignatureMessage(approval)
	if err != nil {
		return [sha256.Size]byte{}, err
	}
	request := MemberSignatureVerifyRequest{MemberID: member.MemberID, Algorithm: algorithm, KeyID: keyID,
		PublicKey: member.SigningPublicKey, Message: message, Signature: signature}
	if err := verifier.VerifyMemberSignature(ctx, request); err != nil {
		return [sha256.Size]byte{}, ErrSignatureInvalid
	}
	return sha256.Sum256(message), nil
}

func VerifyShareAcknowledgementSignature(ctx context.Context, verifier MemberSignatureVerifier, member RecoveryMember,
	ack ShareAcknowledgement, algorithm, keyID string, signature []byte) ([sha256.Size]byte, error) {
	if isNilProvider(verifier) {
		return [sha256.Size]byte{}, ErrProviderUnavailable
	}
	if err := verifier.Ready(ctx); err != nil {
		return [sha256.Size]byte{}, ErrProviderUnavailable
	}
	if ack.MemberID != member.MemberID || algorithm != member.SigningAlgorithm || keyID != member.SigningKeyID ||
		len(member.SigningPublicKey) == 0 || sha256.Sum256(member.SigningPublicKey) != member.SigningKeyFingerprint || len(signature) == 0 {
		return [sha256.Size]byte{}, ErrBindingMismatch
	}
	message, err := BuildShareAcknowledgementMessage(ack)
	if err != nil {
		return [sha256.Size]byte{}, err
	}
	request := MemberSignatureVerifyRequest{MemberID: member.MemberID, Algorithm: algorithm, KeyID: keyID,
		PublicKey: member.SigningPublicKey, Message: message, Signature: signature}
	if err := verifier.VerifyMemberSignature(ctx, request); err != nil {
		return [sha256.Size]byte{}, ErrSignatureInvalid
	}
	return sha256.Sum256(message), nil
}

func BuildMemberManifestSignatureMessage(approval MemberManifestApproval) ([]byte, error) {
	if approval.Version == 0 || !validCeremonyType(approval.CeremonyType) ||
		!validSecurityID(approval.OperationID) || !validSecurityID(approval.PoolID) ||
		approval.Epoch == 0 || !validSecurityID(approval.MemberID) || !nonzeroSecurityHash(approval.ManifestHash) {
		return nil, ErrInvalidData
	}
	return marshalDomainMessage(MemberManifestSignatureDomain, approval)
}

func BuildShareAcknowledgementMessage(ack ShareAcknowledgement) ([]byte, error) {
	if ack.Version == 0 || !validCeremonyType(ack.CeremonyType) ||
		!validSecurityID(ack.OperationID) || !validSecurityID(ack.DeliveryID) ||
		!validSecurityID(ack.PoolID) || ack.Epoch == 0 || !validSecurityID(ack.MemberID) || ack.ShareIndex == 0 ||
		!nonzeroSecurityHash(ack.CiphertextHash) || !nonzeroSecurityHash(ack.ManifestHash) ||
		!nonzeroSecurityHash(ack.RootCommitmentHash) || !nonzeroSecurityHash(ack.VSSCommitmentHash) ||
		!ack.VerifiedCommitment {
		return nil, ErrInvalidData
	}
	return marshalDomainMessage(ShareAcknowledgementDomain, ack)
}

func BuildMemberKeyProofMessage(intent MemberKeyProofIntent) ([]byte, error) {
	domain := ""
	switch intent.Purpose {
	case "SIGNING":
		domain = SigningKeyPossessionDomain
	case "RECOVERY_ENCRYPTION":
		domain = RecoveryKeyPossessionDomain
	default:
		return nil, ErrInvalidData
	}
	if intent.Version == 0 || !validCeremonyType(intent.CeremonyType) ||
		!validSecurityID(intent.OperationID) || !validSecurityID(intent.PoolID) ||
		intent.Epoch == 0 || !validSecurityID(intent.MemberID) || !validSecurityID(intent.Algorithm) ||
		!validSecurityID(intent.KeyID) || !nonzeroSecurityHash(intent.KeyFingerprint) {
		return nil, ErrInvalidData
	}
	return marshalDomainMessage(domain, intent)
}

func validateRecoveryMembers(members []RecoveryMember) error {
	seenIndexes := make(map[uint16]struct{}, len(members))
	for i, member := range members {
		if !validSecurityID(member.MemberID) || !validSecurityID(member.Role) || member.ShareIndex == 0 ||
			!validSecurityID(member.SigningAlgorithm) || !validSecurityID(member.SigningKeyID) ||
			len(member.SigningPublicKey) == 0 || sha256.Sum256(member.SigningPublicKey) != member.SigningKeyFingerprint ||
			!validSecurityID(member.EncryptionAlgorithm) || !validSecurityID(member.EncryptionKeyID) ||
			len(member.EncryptionPublicKey) == 0 || sha256.Sum256(member.EncryptionPublicKey) != member.EncryptionKeyFingerprint {
			return ErrInvalidData
		}
		if member.SigningKeyID == member.EncryptionKeyID ||
			member.SigningKeyFingerprint == member.EncryptionKeyFingerprint ||
			bytes.Equal(member.SigningPublicKey, member.EncryptionPublicKey) {
			return ErrBindingMismatch
		}
		if i > 0 && members[i-1].MemberID >= member.MemberID {
			return ErrDuplicate
		}
		if _, exists := seenIndexes[member.ShareIndex]; exists {
			return ErrDuplicate
		}
		seenIndexes[member.ShareIndex] = struct{}{}
	}
	return nil
}

func validateManifestMembers(members []ManifestMember) error {
	seenIndexes := make(map[uint16]struct{}, len(members))
	for i, member := range members {
		if !validSecurityID(member.MemberID) || !validSecurityID(member.Role) || member.ShareIndex == 0 ||
			!validSecurityID(member.SigningAlgorithm) || !validSecurityID(member.SigningKeyID) ||
			!validLowerHash(member.SigningKeyFingerprint) || len(member.SigningPublicKey) == 0 ||
			hex.EncodeToString(sha256Sum(member.SigningPublicKey)) != member.SigningKeyFingerprint ||
			!validSecurityID(member.RecoveryEncryptionAlgorithm) || !validSecurityID(member.RecoveryEncryptionKeyID) ||
			!validLowerHash(member.RecoveryEncryptionKeyHash) || len(member.RecoveryEncryptionPublicKey) == 0 ||
			hex.EncodeToString(sha256Sum(member.RecoveryEncryptionPublicKey)) != member.RecoveryEncryptionKeyHash {
			return ErrInvalidData
		}
		if member.SigningKeyID == member.RecoveryEncryptionKeyID ||
			member.SigningKeyFingerprint == member.RecoveryEncryptionKeyHash ||
			bytes.Equal(member.SigningPublicKey, member.RecoveryEncryptionPublicKey) {
			return ErrBindingMismatch
		}
		if i > 0 && members[i-1].MemberID >= member.MemberID {
			return ErrDuplicate
		}
		if _, exists := seenIndexes[member.ShareIndex]; exists {
			return ErrDuplicate
		}
		seenIndexes[member.ShareIndex] = struct{}{}
	}
	return nil
}

func validateManifestShares(shares []ManifestEncryptedShare, members []ManifestMember) error {
	if len(shares) != len(members) {
		return ErrBindingMismatch
	}
	for i, share := range shares {
		if share.MemberID != members[i].MemberID || share.ShareIndex != members[i].ShareIndex ||
			!validLowerHash(share.CiphertextHash) || !validLowerHash(share.ProviderProofHash) ||
			!validLowerHash(share.ProviderCommitment) {
			return ErrBindingMismatch
		}
	}
	return nil
}

func validatePlanCollections(seats []SeatPlan, accounts []ResourceAccountPlan, memberIDs map[string]struct{}) error {
	if len(seats) == 0 || len(accounts) == 0 {
		return ErrInvalidData
	}
	seenMembers := make(map[string]struct{}, len(seats))
	seatIDs := make(map[string]struct{}, len(seats))
	for i, seat := range seats {
		if !validSecurityID(seat.SeatID) || !validSecurityID(seat.MemberID) || seat.PrincipalUserID <= 0 ||
			seat.SubscriptionID <= 0 || seat.APIKeyID <= 0 || seat.ExpectedAssignmentEpoch == 0 ||
			(seat.FreezeOperationID == "") != (seat.FreezeSnapshotHash == "") ||
			(seat.FreezeSnapshotHash != "" && !validLowerHash(seat.FreezeSnapshotHash)) {
			return ErrInvalidData
		}
		if i > 0 && seats[i-1].SeatID >= seat.SeatID {
			return ErrDuplicate
		}
		if _, exists := seenMembers[seat.MemberID]; exists {
			return ErrDuplicate
		}
		if memberIDs != nil {
			if _, exists := memberIDs[seat.MemberID]; !exists {
				return ErrBindingMismatch
			}
		}
		seenMembers[seat.MemberID] = struct{}{}
		seatIDs[seat.SeatID] = struct{}{}
	}
	if memberIDs != nil && len(seenMembers) != len(memberIDs) {
		return ErrBindingMismatch
	}
	coveredSeats := make(map[string]struct{}, len(seats))
	canonicalBatchTypes := [...]string{"LOGIN", "MFA", "RECOVERY", "OWNERSHIP"}
	for i, account := range accounts {
		if !validSecurityID(account.AccountID) || !validSecurityID(account.AccountRef) ||
			!validSecurityID(account.ProviderBinding) || !validSecurityID(account.ControlEvidenceID) ||
			!validLowerHash(account.ProviderAttestationDigest) || !validSecurityID(account.ProviderAttestationIssuer) ||
			!validSecurityID(account.ProviderAttestationKeyID) || account.ProviderAttestationVersion == 0 ||
			!validSecurityID(account.ProviderAttestationAlgorithm) ||
			len(account.ProviderAttestationSignature) == 0 ||
			!validSecurityID(account.ProviderAttestationProtocolVersion) ||
			len(account.SeatIDs) == 0 || len(account.Batches) != len(canonicalBatchTypes) {
			return ErrInvalidData
		}
		for seatIndex, seatID := range account.SeatIDs {
			if !validSecurityID(seatID) || seatIndex > 0 && account.SeatIDs[seatIndex-1] >= seatID {
				return ErrDuplicate
			}
			if _, exists := seatIDs[seatID]; !exists {
				return ErrBindingMismatch
			}
			coveredSeats[seatID] = struct{}{}
		}
		if i > 0 && accounts[i-1].AccountID >= account.AccountID {
			return ErrDuplicate
		}
		for j, batch := range account.Batches {
			if batch.BatchType != canonicalBatchTypes[j] || !validSecurityID(batch.FromBatchID) || batch.FromBatchVersion == 0 ||
				!validSecurityID(batch.ToBatchID) || batch.ToBatchVersion <= batch.FromBatchVersion ||
				!validLowerHash(batch.ToCiphertextHash) || !validLowerHash(batch.ToRecoveryWrapHash) ||
				!validLowerHash(batch.FromCiphertextHash) {
				return ErrInvalidData
			}
			if batch.FromBatchID == batch.ToBatchID || batch.FromCiphertextHash == batch.ToCiphertextHash {
				return ErrBindingMismatch
			}
		}
	}
	if len(coveredSeats) != len(seatIDs) {
		return ErrBindingMismatch
	}
	return nil
}

func validCeremonyType(value CeremonyType) bool {
	return value == CeremonyBootstrap || value == CeremonyRotate
}

func validControlBatchType(value credentials.BatchType) bool {
	return value == credentials.BatchLogin || value == credentials.BatchMFA ||
		value == credentials.BatchRecovery || value == credentials.BatchOwnership
}

func validateCeremonySource(ceremony CeremonyType, fromStatus, governanceState string,
	previousHash [sha256.Size]byte) error {
	if !validCeremonyType(ceremony) || fromStatus != epochStatusActive {
		return ErrInvalidData
	}
	switch ceremony {
	case CeremonyBootstrap:
		if governanceState != governanceStateLegacy || nonzeroSecurityHash(previousHash) {
			return ErrBindingMismatch
		}
	case CeremonyRotate:
		if governanceState != governanceStateCurrent || !nonzeroSecurityHash(previousHash) {
			return ErrBindingMismatch
		}
	}
	return nil
}

func validateCeremonyPlan(ceremony CeremonyType, fromStatus, governanceState string,
	previousHash [sha256.Size]byte, seats []SeatPlan, replacements []OwnerReplacementPlan) error {
	if err := validateCeremonySource(ceremony, fromStatus, governanceState, previousHash); err != nil {
		return err
	}
	// Bootstrap 同样在全 Pool 冻结屏障内重包全部控制凭据；它只是不改变 Seat owner。
	for _, seat := range seats {
		if seat.ExpectedAssignmentEpoch == 0 || !validSecurityID(seat.FreezeOperationID) ||
			!validLowerHash(seat.FreezeSnapshotHash) {
			return ErrBindingMismatch
		}
	}
	if ceremony == CeremonyBootstrap {
		if len(replacements) != 0 {
			return ErrBindingMismatch
		}
		return nil
	}
	if len(replacements) == 0 {
		return ErrBindingMismatch
	}
	seatByID := make(map[string]SeatPlan, len(seats))
	for _, seat := range seats {
		seatByID[seat.SeatID] = seat
	}
	replaced := make(map[string]struct{}, len(replacements))
	for i, replacement := range replacements {
		if !validSecurityID(replacement.SeatID) || !validSecurityID(replacement.FromMemberID) ||
			!validSecurityID(replacement.ToMemberID) || replacement.FromMemberID == replacement.ToMemberID ||
			replacement.ExpectedAssignmentEpoch == 0 || !validSecurityID(replacement.FreezeOperationID) ||
			!validLowerHash(replacement.FreezeSnapshotHash) || i > 0 && replacements[i-1].SeatID >= replacement.SeatID {
			return ErrInvalidData
		}
		seat, exists := seatByID[replacement.SeatID]
		if !exists || seat.MemberID != replacement.ToMemberID ||
			seat.ExpectedAssignmentEpoch != replacement.ExpectedAssignmentEpoch ||
			seat.FreezeOperationID != replacement.FreezeOperationID ||
			seat.FreezeSnapshotHash != replacement.FreezeSnapshotHash {
			return ErrBindingMismatch
		}
		replaced[replacement.SeatID] = struct{}{}
	}
	return nil
}

func decodeOptionalHash(value string) ([sha256.Size]byte, error) {
	var result [sha256.Size]byte
	if value == "" {
		return result, nil
	}
	if len(value) != sha256.Size*2 || strings.ToLower(value) != value {
		return result, ErrInvalidData
	}
	decoded, err := hex.DecodeString(value)
	if err != nil {
		return result, ErrInvalidData
	}
	copy(result[:], decoded)
	return result, nil
}

// ProviderAttestationSetHash 绑定每个账号的独立供应商证明元数据；输入必须先通过规范排序校验。
func ProviderAttestationSetHash(accounts []ResourceAccountPlan) ([sha256.Size]byte, error) {
	var empty [sha256.Size]byte
	if len(accounts) == 0 {
		return empty, ErrInvalidData
	}
	var encoded bytes.Buffer
	writeSecurityString(&encoded, "trusted-pool/provider-attestation-set/v2")
	writeSecurityUint32(&encoded, uint32(len(accounts)))
	for i, account := range accounts {
		if !validSecurityID(account.AccountID) || !validLowerHash(account.ProviderAttestationDigest) ||
			!validSecurityID(account.ProviderAttestationIssuer) || !validSecurityID(account.ProviderAttestationKeyID) ||
			account.ProviderAttestationVersion == 0 || !validSecurityID(account.ProviderAttestationAlgorithm) ||
			len(account.ProviderAttestationSignature) == 0 ||
			!validSecurityID(account.ProviderAttestationProtocolVersion) ||
			i > 0 && accounts[i-1].AccountID >= account.AccountID {
			return empty, ErrInvalidData
		}
		decoded, err := hex.DecodeString(account.ProviderAttestationDigest)
		if err != nil {
			return empty, ErrInvalidData
		}
		writeSecurityString(&encoded, account.AccountID)
		writeSecurityString(&encoded, account.ControlEvidenceID)
		encoded.Write(decoded)
		writeSecurityString(&encoded, account.ProviderAttestationIssuer)
		writeSecurityString(&encoded, account.ProviderAttestationKeyID)
		writeSecurityUint64(&encoded, account.ProviderAttestationVersion)
		writeSecurityString(&encoded, account.ProviderAttestationAlgorithm)
		writeSecurityBytes(&encoded, account.ProviderAttestationSignature)
		writeSecurityString(&encoded, account.ProviderAttestationProtocolVersion)
	}
	return sha256.Sum256(encoded.Bytes()), nil
}

func manifestMemberIDs(members []ManifestMember) map[string]struct{} {
	result := make(map[string]struct{}, len(members))
	for _, member := range members {
		result[member.MemberID] = struct{}{}
	}
	return result
}

func marshalDomainMessage(domain string, value any) ([]byte, error) {
	payload, err := json.Marshal(value)
	if err != nil {
		return nil, errors.Join(ErrInvalidData, err)
	}
	message := make([]byte, 0, len(domain)+1+len(payload))
	message = append(message, domain...)
	message = append(message, 0)
	message = append(message, payload...)
	return message, nil
}

func decodeSingleJSON(data []byte) (any, error) {
	decoder := json.NewDecoder(bytes.NewReader(data))
	decoder.UseNumber()
	var value any
	if err := decoder.Decode(&value); err != nil {
		return nil, err
	}
	var trailing any
	if err := decoder.Decode(&trailing); !errors.Is(err, io.EOF) {
		if err == nil {
			return nil, fmt.Errorf("multiple JSON values")
		}
		return nil, err
	}
	return value, nil
}

func validSecurityID(value string) bool {
	return value != "" && value == strings.TrimSpace(value) && len(value) <= maxSecurityIdentifierLength
}

func nonzeroSecurityHash(value [sha256.Size]byte) bool {
	return value != ([sha256.Size]byte{})
}

func validLowerHash(value string) bool {
	if len(value) != sha256.Size*2 || strings.ToLower(value) != value {
		return false
	}
	decoded, err := hex.DecodeString(value)
	return err == nil && !bytes.Equal(decoded, make([]byte, sha256.Size))
}

func sha256Sum(value []byte) []byte {
	hash := sha256.Sum256(value)
	return hash[:]
}

func writeSecurityString(target *bytes.Buffer, value string) {
	writeSecurityBytes(target, []byte(value))
}

func writeSecurityBytes(target *bytes.Buffer, value []byte) {
	writeSecurityUint32(target, uint32(len(value)))
	target.Write(value)
}

func writeSecurityUint16(target *bytes.Buffer, value uint16) {
	_ = binary.Write(target, binary.BigEndian, value)
}

func writeSecurityUint32(target *bytes.Buffer, value uint32) {
	_ = binary.Write(target, binary.BigEndian, value)
}

func writeSecurityUint64(target *bytes.Buffer, value uint64) {
	_ = binary.Write(target, binary.BigEndian, value)
}
