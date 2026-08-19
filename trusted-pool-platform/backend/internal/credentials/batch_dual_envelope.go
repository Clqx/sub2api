package credentials

import (
	"context"
	"crypto/aes"
	"crypto/cipher"
	"crypto/hmac"
	"crypto/rand"
	"crypto/sha256"
	"errors"
	"fmt"
	"io"
	"strings"
)

const (
	BatchEnvelopeAlgorithm = "AES-256-GCM"
	batchDEKSize           = 32
)

var ErrRecoveryRootUnavailable = errors.New("recovery root wrapping is unavailable")

// BatchDEKWrapRequest 将包装动作绑定到稳定业务上下文；包装实现不得记录 DEK 或 Context。
type BatchDEKWrapRequest struct {
	Domain  string
	KeyRef  string
	Context []byte
	DEK     []byte
}

// OnlineBatchDEKWrapper 是在线 KMS/HSM 的窄接口，不允许应用绕过 context 直接包装。
type OnlineBatchDEKWrapper interface {
	Ready(context.Context) error
	WrapOnlineDEK(context.Context, BatchDEKWrapRequest) ([]byte, error)
}

// RecoveryBatchDEKWrapper 仅允许包装，在线服务没有 Recovery Root 解包能力。
type RecoveryBatchDEKWrapper interface {
	Ready(context.Context) error
	WrapRecoveryDEK(context.Context, BatchDEKWrapRequest) ([]byte, error)
}

type BatchEnvelopeScope struct {
	BatchExternalID string
	SealOperationID string
	PoolID          string
	AccountRef      string
	Type            BatchType
	Version         uint64
	MembershipEpoch uint64
}

type BatchDualEnvelopeConfig struct {
	OnlineWrapAlgorithm   string
	OnlineWrapDomain      string
	OnlineKeyRef          string
	RecoveryWrapAlgorithm string
	RecoveryWrapDomain    string
	RecoveryKeyRef        string
	FingerprintKeyRef     string
	FingerprintKey        []byte
}

type BatchDualEnvelopeSealer struct {
	online      OnlineBatchDEKWrapper
	recovery    RecoveryBatchDEKWrapper
	config      BatchDualEnvelopeConfig
	fingerprint []byte
	random      io.Reader
}

func NewBatchDualEnvelopeSealer(online OnlineBatchDEKWrapper, recovery RecoveryBatchDEKWrapper, config BatchDualEnvelopeConfig, random io.Reader) (*BatchDualEnvelopeSealer, error) {
	config.OnlineWrapDomain = strings.TrimSpace(config.OnlineWrapDomain)
	config.OnlineWrapAlgorithm = strings.TrimSpace(config.OnlineWrapAlgorithm)
	config.OnlineKeyRef = strings.TrimSpace(config.OnlineKeyRef)
	config.RecoveryWrapDomain = strings.TrimSpace(config.RecoveryWrapDomain)
	config.RecoveryWrapAlgorithm = strings.TrimSpace(config.RecoveryWrapAlgorithm)
	config.RecoveryKeyRef = strings.TrimSpace(config.RecoveryKeyRef)
	config.FingerprintKeyRef = strings.TrimSpace(config.FingerprintKeyRef)
	if online == nil || recovery == nil || !validEnvelopeReference(config.OnlineWrapAlgorithm) ||
		!validEnvelopeReference(config.OnlineWrapDomain) ||
		!validEnvelopeReference(config.OnlineKeyRef) || !validEnvelopeReference(config.RecoveryWrapDomain) ||
		!validEnvelopeReference(config.RecoveryWrapAlgorithm) ||
		!validEnvelopeReference(config.RecoveryKeyRef) || !validEnvelopeReference(config.FingerprintKeyRef) ||
		len(config.FingerprintKey) < 32 || config.OnlineWrapDomain == config.RecoveryWrapDomain ||
		config.OnlineKeyRef == config.RecoveryKeyRef {
		return nil, errors.New("independent online, recovery and fingerprint wrapping configuration is required")
	}
	if random == nil {
		random = rand.Reader
	}
	return &BatchDualEnvelopeSealer{
		online: online, recovery: recovery, config: config,
		fingerprint: append([]byte(nil), config.FingerprintKey...), random: random,
	}, nil
}

func (s *BatchDualEnvelopeSealer) Ready(ctx context.Context) error {
	if s == nil || s.online == nil || s.recovery == nil {
		return ErrRecoveryRootUnavailable
	}
	if err := s.online.Ready(ctx); err != nil {
		return fmt.Errorf("online batch KMS is not ready: %w", err)
	}
	if err := s.recovery.Ready(ctx); err != nil {
		return fmt.Errorf("%w: %v", ErrRecoveryRootUnavailable, err)
	}
	return nil
}

// ContentFingerprint 使用独立密钥生成不可逆指纹，避免低熵凭据被裸摘要离线枚举。
func (s *BatchDualEnvelopeSealer) ContentFingerprint(payload []byte) ([sha256.Size]byte, error) {
	if s == nil || len(s.fingerprint) < 32 || len(payload) == 0 {
		return [sha256.Size]byte{}, errors.New("credential batch payload is required")
	}
	mac := hmac.New(sha256.New, s.fingerprint)
	_, _ = mac.Write(payload)
	var result [sha256.Size]byte
	copy(result[:], mac.Sum(nil))
	return result, nil
}

// Seal 消费并清零 payload。调用方不得在返回后继续使用该切片。
func (s *BatchDualEnvelopeSealer) Seal(ctx context.Context, scope BatchEnvelopeScope, payload []byte) (DualWrappedBatchEnvelope, error) {
	defer clear(payload)
	if s == nil || len(payload) == 0 || !validBatchEnvelopeScope(scope) {
		return DualWrappedBatchEnvelope{}, errors.New("valid credential batch scope and payload are required")
	}
	if err := s.Ready(ctx); err != nil {
		return DualWrappedBatchEnvelope{}, err
	}
	payloadFingerprint, err := s.ContentFingerprint(payload)
	if err != nil {
		return DualWrappedBatchEnvelope{}, err
	}
	aad, err := CanonicalBatchAAD(scope.SealOperationID, scope.BatchExternalID, scope.PoolID, scope.AccountRef, scope.Type,
		scope.Version, scope.MembershipEpoch, payloadFingerprint)
	if err != nil {
		return DualWrappedBatchEnvelope{}, err
	}

	dek := make([]byte, batchDEKSize)
	if _, err := io.ReadFull(s.random, dek); err != nil {
		return DualWrappedBatchEnvelope{}, fmt.Errorf("generate credential batch DEK: %w", err)
	}
	defer clear(dek)
	block, err := aes.NewCipher(dek)
	if err != nil {
		return DualWrappedBatchEnvelope{}, errors.New("initialize credential batch cipher")
	}
	gcm, err := cipher.NewGCM(block)
	if err != nil {
		return DualWrappedBatchEnvelope{}, errors.New("initialize credential batch AEAD")
	}
	nonce := make([]byte, gcm.NonceSize())
	if _, err := io.ReadFull(s.random, nonce); err != nil {
		return DualWrappedBatchEnvelope{}, fmt.Errorf("generate credential batch nonce: %w", err)
	}
	ciphertext := gcm.Seal(nil, nonce, payload, aad)
	completed := false
	defer func() {
		if !completed {
			clear(ciphertext)
			clear(nonce)
		}
	}()

	onlineRequest := BatchDEKWrapRequest{
		Domain: s.config.OnlineWrapDomain, KeyRef: s.config.OnlineKeyRef,
		Context: append([]byte(nil), aad...), DEK: append([]byte(nil), dek...),
	}
	onlineResult, err := s.online.WrapOnlineDEK(ctx, onlineRequest)
	invalidOnline := err != nil || !nonzeroWrappedMaterial(onlineResult) ||
		hmac.Equal(onlineResult, onlineRequest.DEK) || hmac.Equal(onlineResult, onlineRequest.Context)
	var wrappedOnline []byte
	if !invalidOnline {
		wrappedOnline = append([]byte(nil), onlineResult...)
	}
	clear(onlineResult)
	clear(onlineRequest.Context)
	clear(onlineRequest.DEK)
	if invalidOnline {
		return DualWrappedBatchEnvelope{}, errors.New("wrap credential batch DEK with online KMS")
	}
	recoveryRequest := BatchDEKWrapRequest{
		Domain: s.config.RecoveryWrapDomain, KeyRef: s.config.RecoveryKeyRef,
		Context: append([]byte(nil), aad...), DEK: append([]byte(nil), dek...),
	}
	recoveryResult, err := s.recovery.WrapRecoveryDEK(ctx, recoveryRequest)
	invalidRecovery := err != nil || !nonzeroWrappedMaterial(recoveryResult) ||
		hmac.Equal(recoveryResult, recoveryRequest.DEK) || hmac.Equal(recoveryResult, recoveryRequest.Context)
	var wrappedRecovery []byte
	if !invalidRecovery {
		wrappedRecovery = append([]byte(nil), recoveryResult...)
	}
	clear(recoveryResult)
	clear(recoveryRequest.Context)
	clear(recoveryRequest.DEK)
	if invalidRecovery {
		clear(wrappedOnline)
		return DualWrappedBatchEnvelope{}, fmt.Errorf("%w: wrap credential batch recovery DEK", ErrRecoveryRootUnavailable)
	}
	if hmac.Equal(wrappedOnline, wrappedRecovery) {
		clear(wrappedOnline)
		clear(wrappedRecovery)
		return DualWrappedBatchEnvelope{}, errors.New("online and recovery wrappers returned identical material")
	}
	aadHash := sha256.Sum256(aad)
	recoveryBindingHash := RecoveryBindingHash(s.config.RecoveryWrapDomain, s.config.RecoveryWrapAlgorithm,
		s.config.RecoveryKeyRef, aadHash, wrappedRecovery)
	completed = true
	return DualWrappedBatchEnvelope{
		EncryptionAlgorithm: BatchEnvelopeAlgorithm, Ciphertext: ciphertext, Nonce: nonce,
		AADHash: aadHash, ContentFingerprint: payloadFingerprint,
		KMSWrapAlgorithm: s.config.OnlineWrapAlgorithm, KMSKeyRef: s.config.OnlineKeyRef,
		KMSWrapperDomain: s.config.OnlineWrapDomain, WrappedDEKKMS: wrappedOnline,
		RecoveryWrapAlgorithm: s.config.RecoveryWrapAlgorithm, RecoveryKeyRef: s.config.RecoveryKeyRef,
		RecoveryWrapperDomain: s.config.RecoveryWrapDomain, WrappedDEKRecovery: wrappedRecovery,
		RecoveryBindingHash: recoveryBindingHash,
	}, nil
}

func validBatchEnvelopeScope(scope BatchEnvelopeScope) bool {
	return validEnvelopeReference(scope.BatchExternalID) && validEnvelopeReference(scope.SealOperationID) &&
		validEnvelopeReference(scope.PoolID) && validEnvelopeReference(scope.AccountRef) &&
		validBatchType(scope.Type) && scope.Version > 0 && scope.MembershipEpoch > 0
}

func validEnvelopeReference(value string) bool {
	value = strings.TrimSpace(value)
	return value != "" && len(value) <= 256
}

func nonzeroWrappedMaterial(value []byte) bool {
	if len(value) == 0 {
		return false
	}
	var combined byte
	for _, item := range value {
		combined |= item
	}
	return combined != 0
}
