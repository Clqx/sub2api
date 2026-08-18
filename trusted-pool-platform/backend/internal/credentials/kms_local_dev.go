package credentials

import (
	"context"
	"errors"
	"io"
)

// DevelopmentLocalKMS 仅用于显式开发模式，生产组合根不得构造该类型。
type DevelopmentLocalKMS struct {
	wrapper *LocalKeyWrapper
}

func NewDevelopmentLocalKMS(key []byte, random io.Reader) (*DevelopmentLocalKMS, error) {
	wrapper, err := NewLocalKeyWrapper(key, random)
	if err != nil {
		return nil, err
	}
	return &DevelopmentLocalKMS{wrapper: wrapper}, nil
}

func (k *DevelopmentLocalKMS) Ready(context.Context) error {
	if k == nil || k.wrapper == nil {
		return errors.New("development local KMS is not configured")
	}
	return nil
}

func (k *DevelopmentLocalKMS) Wrap(ctx context.Context, keyRef string, plaintext []byte) ([]byte, error) {
	if err := k.Ready(ctx); err != nil {
		return nil, err
	}
	return k.wrapper.Wrap(ctx, keyRef, plaintext)
}

func (k *DevelopmentLocalKMS) Unwrap(ctx context.Context, keyRef string, wrapped []byte) ([]byte, error) {
	if err := k.Ready(ctx); err != nil {
		return nil, err
	}
	return k.wrapper.Unwrap(ctx, keyRef, wrapped)
}
