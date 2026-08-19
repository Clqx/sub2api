package runtime

import (
	"context"
	"crypto/sha256"
	"encoding/hex"
	"errors"

	"trusted-pool-platform/backend/internal/credentials"
)

type developmentOnlineWrapper struct {
	wrapper credentials.KMSKeyWrapper
}

func (w developmentOnlineWrapper) Ready(ctx context.Context) error {
	if w.wrapper == nil {
		return errors.New("online batch KMS is not configured")
	}
	return w.wrapper.Ready(ctx)
}

func (w developmentOnlineWrapper) WrapOnlineDEK(ctx context.Context, request credentials.BatchDEKWrapRequest) ([]byte, error) {
	if err := w.Ready(ctx); err != nil {
		return nil, err
	}
	return w.wrapper.Wrap(ctx, contextBoundKeyRef(request.KeyRef, request.Context), request.DEK)
}

type developmentRecoveryWrapper struct {
	wrapper *credentials.LocalKeyWrapper
}

func (w developmentRecoveryWrapper) Ready(context.Context) error {
	if w.wrapper == nil {
		return credentials.ErrRecoveryRootUnavailable
	}
	return nil
}

func (w developmentRecoveryWrapper) WrapRecoveryDEK(ctx context.Context, request credentials.BatchDEKWrapRequest) ([]byte, error) {
	if err := w.Ready(ctx); err != nil {
		return nil, err
	}
	return w.wrapper.Wrap(ctx, contextBoundKeyRef(request.KeyRef, request.Context), request.DEK)
}

func contextBoundKeyRef(keyRef string, contextValue []byte) string {
	digest := sha256.Sum256(contextValue)
	return keyRef + "#ctx-sha256:" + hex.EncodeToString(digest[:])
}

// BuildBatchSealer 只在开发模式构造本地 Recovery wrapper；生产必须由组合根注入 wrap-only 适配器。

func BuildBatchSealer(config Config, developmentOnline credentials.KMSKeyWrapper,
	productionOnline credentials.OnlineBatchDEKWrapper,
	productionRecovery credentials.RecoveryBatchDEKWrapper) (*credentials.BatchDualEnvelopeSealer, error) {
	var online credentials.OnlineBatchDEKWrapper
	var recovery credentials.RecoveryBatchDEKWrapper
	switch config.Mode {
	case ModeProduction:
		if productionOnline == nil || productionRecovery == nil {
			return nil, credentials.ErrRecoveryRootUnavailable
		}
		online, recovery = productionOnline, productionRecovery
	case ModeDevelopment:
		if developmentOnline == nil {
			return nil, errors.New("development online credential batch wrapper is required")
		}
		local, err := credentials.NewLocalKeyWrapper(config.LocalRecoveryKEK, nil)
		if err != nil {
			return nil, err
		}
		online, recovery = developmentOnlineWrapper{wrapper: developmentOnline}, developmentRecoveryWrapper{wrapper: local}
	default:
		return nil, errors.New("unsupported runtime mode")
	}
	return credentials.NewBatchDualEnvelopeSealer(online, recovery,
		credentials.BatchDualEnvelopeConfig{
			OnlineWrapAlgorithm: config.BatchOnlineWrapAlgorithm,
			OnlineWrapDomain:    config.BatchOnlineDomain, OnlineKeyRef: config.BatchOnlineKeyRef,
			RecoveryWrapAlgorithm: config.BatchRecoveryWrapAlgorithm,
			RecoveryWrapDomain:    config.BatchRecoveryDomain, RecoveryKeyRef: config.BatchRecoveryKeyRef,
			FingerprintKeyRef: config.BatchFingerprintKeyRef, FingerprintKey: config.BatchFingerprintKey,
		}, nil)
}

type BatchProbe struct {
	Manager *credentials.PersistentManager
}

func (p BatchProbe) Check(ctx context.Context) error {
	if p.Manager == nil {
		return errors.New("persistent credential batch manager is not configured")
	}
	return p.Manager.Ready(ctx)
}
