package credentials

import (
	"bytes"
	"context"
	"crypto/aes"
	"crypto/cipher"
	"crypto/hmac"
	"crypto/sha256"
	"errors"
	"testing"
)

type onlineBatchWrapperStub struct {
	request   BatchDEKWrapRequest
	readyErr  error
	wrapErr   error
	result    []byte
	onWrap    func()
	returnDEK bool
}

func (s *onlineBatchWrapperStub) Ready(context.Context) error { return s.readyErr }
func (s *onlineBatchWrapperStub) WrapOnlineDEK(_ context.Context, request BatchDEKWrapRequest) ([]byte, error) {
	if s.onWrap != nil {
		s.onWrap()
	}
	s.request = cloneBatchWrapRequest(request)
	if s.result == nil {
		s.result = []byte("online-wrapped")
	}
	if s.returnDEK {
		return request.DEK, s.wrapErr
	}
	return s.result, s.wrapErr
}

type recoveryBatchWrapperStub struct {
	request   BatchDEKWrapRequest
	readyErr  error
	wrapErr   error
	result    []byte
	onWrap    func()
	returnDEK bool
}

func (s *recoveryBatchWrapperStub) Ready(context.Context) error { return s.readyErr }
func (s *recoveryBatchWrapperStub) WrapRecoveryDEK(_ context.Context, request BatchDEKWrapRequest) ([]byte, error) {
	if s.onWrap != nil {
		s.onWrap()
	}
	s.request = cloneBatchWrapRequest(request)
	if s.result == nil {
		s.result = []byte("recovery-wrapped")
	}
	if s.returnDEK {
		return request.DEK, s.wrapErr
	}
	return s.result, s.wrapErr
}

func TestBatchDualEnvelopeUsesOneDEKAndIndependentWrapContexts(t *testing.T) {
	online, recovery := &onlineBatchWrapperStub{}, &recoveryBatchWrapperStub{}
	fingerprintKey := bytes.Repeat([]byte{9}, 32)
	sealer, err := NewBatchDualEnvelopeSealer(online, recovery, testDualEnvelopeConfig(fingerprintKey),
		bytes.NewReader(bytes.Repeat([]byte{7}, 64)))
	if err != nil {
		t.Fatal(err)
	}
	payload := []byte(`{"username":"member@example.com","password":"canary-secret"}`)
	wantPayload := append([]byte(nil), payload...)
	envelope, err := sealer.Seal(context.Background(), testBatchEnvelopeScope(), payload)
	if err != nil {
		t.Fatalf("Seal(): %v", err)
	}
	if !allZero(payload) {
		t.Fatal("Seal did not clear the consumed plaintext buffer")
	}
	if !bytes.Equal(online.request.DEK, recovery.request.DEK) || len(online.request.DEK) != batchDEKSize {
		t.Fatal("online and recovery wrappers did not receive the same single DEK")
	}
	if online.request.Domain != "batch/online/v1" || recovery.request.Domain != "batch/recovery/v1" ||
		online.request.KeyRef != "kms/online/key-1" || recovery.request.KeyRef != "recovery/root/epoch-2" ||
		!bytes.Equal(online.request.Context, recovery.request.Context) {
		t.Fatalf("wrap domains are not independently bound: online=%+v recovery=%+v", online.request, recovery.request)
	}
	if envelope.KMSWrapperDomain == envelope.RecoveryWrapperDomain || envelope.KMSKeyRef == envelope.RecoveryKeyRef ||
		bytes.Contains(envelope.Ciphertext, []byte("canary-secret")) {
		t.Fatalf("unsafe dual envelope: %+v", envelope)
	}
	mac := hmac.New(sha256.New, fingerprintKey)
	_, _ = mac.Write(wantPayload)
	if !hmac.Equal(envelope.ContentFingerprint[:], mac.Sum(nil)) {
		t.Fatal("payload fingerprint is not keyed HMAC-SHA256")
	}
	wantBinding := RecoveryBindingHash(envelope.RecoveryWrapperDomain, envelope.RecoveryWrapAlgorithm,
		envelope.RecoveryKeyRef, envelope.AADHash, envelope.WrappedDEKRecovery)
	if !hmac.Equal(envelope.RecoveryBindingHash[:], wantBinding[:]) || envelope.RecoveryBindingHash == envelope.AADHash {
		t.Fatal("recovery binding does not bind wrapper metadata and wrapped material")
	}
	block, _ := aes.NewCipher(online.request.DEK)
	gcm, _ := cipher.NewGCM(block)
	opened, err := gcm.Open(nil, envelope.Nonce, envelope.Ciphertext, online.request.Context)
	if err != nil || !bytes.Equal(opened, wantPayload) {
		t.Fatalf("canonical AAD did not authenticate ciphertext: opened=%q err=%v", opened, err)
	}
	wrongAAD, err := CanonicalBatchAAD("different-operation", "batch-1", "pool-1", "account-9", BatchLogin,
		2, 2, envelope.ContentFingerprint)
	if err != nil {
		t.Fatal(err)
	}
	if _, err := gcm.Open(nil, envelope.Nonce, envelope.Ciphertext, wrongAAD); err == nil {
		t.Fatal("ciphertext authenticated after seal operation id drift")
	}
}

func TestBatchDualEnvelopeFailsClosedWhenEitherWrapperFails(t *testing.T) {
	tests := []struct {
		name         string
		onlineErr    error
		recoveryErr  error
		wantRecovery bool
	}{
		{name: "online KMS", onlineErr: errors.New("kms unavailable")},
		{name: "recovery root", recoveryErr: errors.New("root unavailable"), wantRecovery: true},
	}
	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			online := &onlineBatchWrapperStub{wrapErr: test.onlineErr, result: []byte("online-wrapped")}
			recovery := &recoveryBatchWrapperStub{wrapErr: test.recoveryErr}
			sealer, err := NewBatchDualEnvelopeSealer(online, recovery, testDualEnvelopeConfig(bytes.Repeat([]byte{3}, 32)),
				bytes.NewReader(bytes.Repeat([]byte{4}, 64)))
			if err != nil {
				t.Fatal(err)
			}
			payload := []byte("canary-plaintext")
			envelope, err := sealer.Seal(context.Background(), testBatchEnvelopeScope(), payload)
			if err == nil || len(envelope.Ciphertext) != 0 || !allZero(payload) {
				t.Fatalf("partial envelope escaped: envelope=%+v err=%v", envelope, err)
			}
			if test.wantRecovery && !errors.Is(err, ErrRecoveryRootUnavailable) {
				t.Fatalf("recovery failure lost stable classification: %v", err)
			}
			if test.wantRecovery && !allZero(online.result) {
				t.Fatal("online wrapped result was retained after recovery wrap failure")
			}
		})
	}
}

func TestBatchDualEnvelopeReadyAndConfigurationFailClosed(t *testing.T) {
	config := testDualEnvelopeConfig(bytes.Repeat([]byte{1}, 32))
	config.RecoveryKeyRef = config.OnlineKeyRef
	if _, err := NewBatchDualEnvelopeSealer(&onlineBatchWrapperStub{}, &recoveryBatchWrapperStub{}, config, nil); err == nil {
		t.Fatal("accepted reused online/recovery key reference")
	}
	config = testDualEnvelopeConfig(bytes.Repeat([]byte{1}, 32))
	config.RecoveryWrapDomain = config.OnlineWrapDomain
	if _, err := NewBatchDualEnvelopeSealer(&onlineBatchWrapperStub{}, &recoveryBatchWrapperStub{}, config, nil); err == nil {
		t.Fatal("accepted reused online/recovery wrapper domain")
	}
	config = testDualEnvelopeConfig(bytes.Repeat([]byte{1}, 32))
	recoveryErr := errors.New("recovery ceremony unavailable")
	sealer, err := NewBatchDualEnvelopeSealer(&onlineBatchWrapperStub{}, &recoveryBatchWrapperStub{readyErr: recoveryErr}, config, nil)
	if err != nil {
		t.Fatal(err)
	}
	if err := sealer.Ready(context.Background()); !errors.Is(err, ErrRecoveryRootUnavailable) {
		t.Fatalf("Ready() did not fail closed for missing recovery root: %v", err)
	}
}

func TestBatchDualEnvelopeRejectsIdenticalWrappedMaterial(t *testing.T) {
	shared := []byte("same-wrapped-dek")
	online := &onlineBatchWrapperStub{result: append([]byte(nil), shared...)}
	recovery := &recoveryBatchWrapperStub{result: append([]byte(nil), shared...)}
	sealer, err := NewBatchDualEnvelopeSealer(online, recovery, testDualEnvelopeConfig(bytes.Repeat([]byte{5}, 32)),
		bytes.NewReader(bytes.Repeat([]byte{6}, 64)))
	if err != nil {
		t.Fatal(err)
	}
	payload := []byte("sensitive")
	if _, err := sealer.Seal(context.Background(), testBatchEnvelopeScope(), payload); err == nil {
		t.Fatal("accepted identical online and recovery wrapped material")
	}
	if !allZero(online.result) || !allZero(recovery.result) || !allZero(payload) {
		t.Fatal("failed seal retained secret or wrapped material")
	}
}

func TestBatchDualEnvelopeRejectsWrapperReturningRawDEK(t *testing.T) {
	tests := []struct {
		name     string
		online   *onlineBatchWrapperStub
		recovery *recoveryBatchWrapperStub
	}{
		{name: "online", online: &onlineBatchWrapperStub{returnDEK: true}, recovery: &recoveryBatchWrapperStub{}},
		{name: "recovery", online: &onlineBatchWrapperStub{}, recovery: &recoveryBatchWrapperStub{returnDEK: true}},
	}
	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			sealer, err := NewBatchDualEnvelopeSealer(test.online, test.recovery,
				testDualEnvelopeConfig(bytes.Repeat([]byte{5}, 32)), bytes.NewReader(bytes.Repeat([]byte{6}, 64)))
			if err != nil {
				t.Fatal(err)
			}
			payload := []byte("sensitive")
			if _, err := sealer.Seal(context.Background(), testBatchEnvelopeScope(), payload); err == nil {
				t.Fatal("accepted wrapper output that exposed the raw DEK")
			}
			if !allZero(payload) {
				t.Fatal("failed seal retained plaintext")
			}
		})
	}
}

func TestBatchAADAndRecoveryBindingDetectEveryScopeDrift(t *testing.T) {
	fingerprint := sha256.Sum256([]byte("payload"))
	scope := testBatchEnvelopeScope()
	base, err := CanonicalBatchAAD(scope.SealOperationID, scope.BatchExternalID, scope.PoolID, scope.AccountRef,
		scope.Type, scope.Version, scope.MembershipEpoch, fingerprint)
	if err != nil {
		t.Fatal(err)
	}
	changed, err := CanonicalBatchAAD("another-operation", scope.BatchExternalID, scope.PoolID, scope.AccountRef,
		scope.Type, scope.Version, scope.MembershipEpoch, fingerprint)
	if err != nil {
		t.Fatal(err)
	}
	if bytes.Equal(base, changed) || sha256.Sum256(base) == sha256.Sum256(changed) {
		t.Fatal("seal operation drift did not change canonical AAD")
	}
	aadHash := sha256.Sum256(base)
	wrapped := []byte("wrapped-recovery-dek")
	want := RecoveryBindingHash("domain", "algorithm", "key-ref", aadHash, wrapped)
	checks := [][32]byte{
		RecoveryBindingHash("other-domain", "algorithm", "key-ref", aadHash, wrapped),
		RecoveryBindingHash("domain", "other-algorithm", "key-ref", aadHash, wrapped),
		RecoveryBindingHash("domain", "algorithm", "other-key", aadHash, wrapped),
		RecoveryBindingHash("domain", "algorithm", "key-ref", sha256.Sum256([]byte("other-aad")), wrapped),
		RecoveryBindingHash("domain", "algorithm", "key-ref", aadHash, []byte("other-wrapped")),
	}
	for i, got := range checks {
		if got == want {
			t.Fatalf("recovery binding mutation %d was not detected", i)
		}
	}
}

func testDualEnvelopeConfig(fingerprintKey []byte) BatchDualEnvelopeConfig {
	return BatchDualEnvelopeConfig{
		OnlineWrapAlgorithm: "KMS-AES-KW", OnlineWrapDomain: "batch/online/v1", OnlineKeyRef: "kms/online/key-1",
		RecoveryWrapAlgorithm: "RECOVERY-AES-KW", RecoveryWrapDomain: "batch/recovery/v1", RecoveryKeyRef: "recovery/root/epoch-2",
		FingerprintKeyRef: "hmac/batch/v1", FingerprintKey: fingerprintKey,
	}
}

func testBatchEnvelopeScope() BatchEnvelopeScope {
	return BatchEnvelopeScope{
		BatchExternalID: "batch-1", SealOperationID: "seal-op-1",
		PoolID: "pool-1", AccountRef: "account-9", Type: BatchLogin, Version: 2, MembershipEpoch: 2,
	}
}

func cloneBatchWrapRequest(request BatchDEKWrapRequest) BatchDEKWrapRequest {
	request.Context = append([]byte(nil), request.Context...)
	request.DEK = append([]byte(nil), request.DEK...)
	return request
}

func allZero(value []byte) bool {
	for _, item := range value {
		if item != 0 {
			return false
		}
	}
	return true
}
