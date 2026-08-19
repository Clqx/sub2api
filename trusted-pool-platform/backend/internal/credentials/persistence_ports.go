package credentials

import (
	"context"
	"crypto/sha256"
	"encoding/binary"
	"encoding/json"
	"errors"
	"time"
)

var (
	ErrBatchNotFound       = errors.New("credential batch not found")
	ErrBatchHashDrift      = errors.New("credential batch request hash drift")
	ErrBatchLeaseHeld      = errors.New("credential batch operation lease is held")
	ErrBatchStaleFence     = errors.New("credential batch operation fencing token is stale")
	ErrBatchInvalidState   = errors.New("credential batch state is invalid")
	ErrBatchInvalidData    = errors.New("credential batch persistence data is invalid")
	ErrBatchLegacy         = errors.New("legacy credential batch is unrecoverable")
	ErrBatchTargetConflict = errors.New("credential batch target already exists")
)

const (
	BatchMigrationCurrent = "CURRENT"
	BatchMigrationLegacy  = "LEGACY_UNRECOVERABLE"
)

type BatchOperationKey struct {
	ClientID    string
	OperationID string
}

type StoredBatchOperation struct {
	AggregateID      string
	Key              BatchOperationKey
	Kind             string
	Status           string
	FencingToken     int64
	LeaseOwner       string
	LeaseExpiresAt   *time.Time
	RequestHash      [sha256.Size]byte
	RequestSnapshot  []byte
	ResponseSnapshot []byte
	ErrorCode        string
	CreatedAt        time.Time
	UpdatedAt        time.Time
}

// StoredCredentialBatch 只返回去敏元数据；密文和 wrapped DEK 不通过 metadata 端口披露。
type StoredCredentialBatch struct {
	ID                    string
	ExternalID            string
	PoolID                string
	PoolExternalID        string
	AccountRef            string
	Type                  BatchType
	BatchVersion          uint64
	MembershipEpoch       uint64
	State                 BatchState
	MigrationState        string
	AADVersion            uint16
	EncryptionAlgorithm   string
	AADHash               [sha256.Size]byte
	ContentFingerprint    [sha256.Size]byte
	KMSWrapAlgorithm      string
	KMSKeyRef             string
	KMSWrapperDomain      string
	RecoveryWrapAlgorithm string
	RecoveryKeyRef        string
	RecoveryWrapperDomain string
	RecoveryBindingHash   [sha256.Size]byte
	Version               int64
	SealedAt              *time.Time
	ActivatedAt           *time.Time
	RetiredAt             *time.Time
	CreatedAt             time.Time
	UpdatedAt             time.Time
}

type BeginSealCredentialBatchInput struct {
	Key                BatchOperationKey
	BatchExternalID    string
	PoolExternalID     string
	AccountRef         string
	Type               BatchType
	BatchVersion       uint64
	MembershipEpoch    uint64
	ContentFingerprint [sha256.Size]byte
	RequestHash        [sha256.Size]byte
	RequestSnapshot    []byte
	LeaseOwner         string
	LeaseDuration      time.Duration
}

type SealCredentialBatchTarget struct {
	Operation *StoredBatchOperation
	Batch     *StoredCredentialBatch
}

// DualWrappedBatchEnvelope 必须由同一 DEK 生成两个独立安全域的包装结果。
// Store 只验证结构、domain 分离和 AAD 绑定，不负责调用任何外部 KMS/Recovery 服务。
type DualWrappedBatchEnvelope struct {
	EncryptionAlgorithm   string
	Ciphertext            []byte
	Nonce                 []byte
	AADHash               [sha256.Size]byte
	ContentFingerprint    [sha256.Size]byte
	KMSWrapAlgorithm      string
	KMSKeyRef             string
	KMSWrapperDomain      string
	WrappedDEKKMS         []byte
	RecoveryWrapAlgorithm string
	RecoveryKeyRef        string
	RecoveryWrapperDomain string
	WrappedDEKRecovery    []byte
	RecoveryBindingHash   [sha256.Size]byte
}

type CommitSealCredentialBatchInput struct {
	Key          BatchOperationKey
	LeaseOwner   string
	FencingToken int64
	Envelope     DualWrappedBatchEnvelope
}

type CredentialBatchTransitionInput struct {
	Key             BatchOperationKey
	BatchExternalID string
	ExpectedVersion int64
	RequestHash     [sha256.Size]byte
	RequestSnapshot []byte
}

type BatchStore interface {
	BeginSealCredentialBatch(context.Context, BeginSealCredentialBatchInput) (*SealCredentialBatchTarget, bool, error)
	CommitSealCredentialBatch(context.Context, CommitSealCredentialBatchInput) (*StoredCredentialBatch, error)
	GetCredentialBatch(context.Context, string) (*StoredCredentialBatch, error)
	ActivateCredentialBatch(context.Context, CredentialBatchTransitionInput) (*StoredCredentialBatch, bool, error)
	RetireCredentialBatch(context.Context, CredentialBatchTransitionInput) (*StoredCredentialBatch, bool, error)
}

// CanonicalBatchAAD 是内容 AEAD 的唯一 AAD 规范。Recovery wrapper 应把其 hash 纳入自己的绑定证明。
func CanonicalBatchAAD(operationID, batchID, poolID, accountRef string, batchType BatchType,
	batchVersion, membershipEpoch uint64, contentFingerprint [sha256.Size]byte) ([]byte, error) {
	return json.Marshal(struct {
		AADVersion         int       `json:"aad_version"`
		OperationID        string    `json:"operation_id"`
		BatchID            string    `json:"batch_id"`
		PoolID             string    `json:"pool_id"`
		AccountRef         string    `json:"account_ref"`
		BatchType          BatchType `json:"batch_type"`
		BatchVersion       uint64    `json:"batch_version"`
		MembershipEpoch    uint64    `json:"membership_epoch"`
		ContentFingerprint string    `json:"content_fingerprint"`
	}{
		AADVersion: 1, OperationID: operationID, BatchID: batchID, PoolID: poolID, AccountRef: accountRef,
		BatchType: batchType, BatchVersion: batchVersion, MembershipEpoch: membershipEpoch,
		ContentFingerprint: encodeFingerprint(contentFingerprint),
	})
}

// RecoveryBindingHash 把独立 Recovery wrapper 的来源、key、AAD 与包装结果绑定。
// 长度前缀使用网络字节序，与 migration 007 的 credential_recovery_binding_hash 完全一致。
func RecoveryBindingHash(domain, algorithm, keyRef string, aadHash [sha256.Size]byte, wrapped []byte) [sha256.Size]byte {
	hash := sha256.New()
	_, _ = hash.Write([]byte("trusted-pool/recovery-binding/v1"))
	for _, value := range [][]byte{[]byte(domain), []byte(algorithm), []byte(keyRef), aadHash[:], wrapped} {
		var length [4]byte
		binary.BigEndian.PutUint32(length[:], uint32(len(value)))
		_, _ = hash.Write(length[:])
		_, _ = hash.Write(value)
	}
	var result [sha256.Size]byte
	copy(result[:], hash.Sum(nil))
	return result
}

func encodeFingerprint(value [sha256.Size]byte) string {
	const digits = "0123456789abcdef"
	encoded := make([]byte, len(value)*2)
	for i, item := range value {
		encoded[i*2], encoded[i*2+1] = digits[item>>4], digits[item&0x0f]
	}
	return string(encoded)
}
