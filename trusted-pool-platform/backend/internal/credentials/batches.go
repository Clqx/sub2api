package credentials

import (
	"context"
	"crypto/aes"
	"crypto/cipher"
	"crypto/rand"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"strings"
	"sync"
	"time"
)

type BatchType string

const (
	BatchOperational BatchType = "OPERATIONAL"
	BatchLogin       BatchType = "LOGIN"
	BatchMFA         BatchType = "MFA"
	BatchRecovery    BatchType = "RECOVERY"
	BatchOwnership   BatchType = "OWNERSHIP"
)

type BatchState string

const (
	BatchSealed  BatchState = "SEALED"
	BatchActive  BatchState = "ACTIVE"
	BatchRetired BatchState = "RETIRED"
)

type Batch struct {
	ID              string
	PoolID          string
	AccountRef      string
	Type            BatchType
	Version         uint64
	MembershipEpoch uint64
	State           BatchState
	Algorithm       string
	KeyRef          string
	Nonce           []byte
	Ciphertext      []byte
	WrappedDEK      []byte
	AADHash         string
	CreatedAt       time.Time
	ActivatedAt     *time.Time
	RetiredAt       *time.Time
}

// ControlRotationEvidence 将永久换员证明绑定到同一 Pool/账号的两代控制凭据批次。
// 它只引用元数据，不包含任何凭据明文。
type ControlRotationEvidence struct {
	ID                     string               `json:"id"`
	PoolID                 string               `json:"pool_id"`
	AccountRef             string               `json:"account_ref"`
	FromEpoch              uint64               `json:"from_membership_epoch"`
	ToEpoch                uint64               `json:"to_membership_epoch"`
	ProviderAttestationRef string               `json:"provider_attestation_ref"`
	RetiredBatchIDs        map[BatchType]string `json:"retired_batch_ids"`
	ActiveBatchIDs         map[BatchType]string `json:"active_batch_ids"`
	CreatedAt              time.Time            `json:"created_at"`
}

type SealRequest struct {
	PoolID          string
	AccountRef      string
	Type            BatchType
	Version         uint64
	MembershipEpoch uint64
	KeyRef          string
	Plaintext       []byte
}

type KeyWrapper interface {
	Wrap(context.Context, string, []byte) ([]byte, error)
	Unwrap(context.Context, string, []byte) ([]byte, error)
}

type Manager struct {
	mu           sync.Mutex
	wrapper      KeyWrapper
	random       io.Reader
	now          func() time.Time
	batches      map[string]*Batch
	evidence     map[string]*ControlRotationEvidence
	minimumEpoch map[string]uint64
}

func NewManager(wrapper KeyWrapper, random io.Reader, now func() time.Time) (*Manager, error) {
	if wrapper == nil {
		return nil, errors.New("key wrapper is required")
	}
	if random == nil {
		random = rand.Reader
	}
	if now == nil {
		now = time.Now
	}
	return &Manager{
		wrapper: wrapper, random: random, now: now,
		batches: make(map[string]*Batch), evidence: make(map[string]*ControlRotationEvidence), minimumEpoch: make(map[string]uint64),
	}, nil
}

var controlBatchTypes = []BatchType{BatchLogin, BatchMFA, BatchRecovery, BatchOwnership}

// IssueControlRotationEvidence 仅在旧 epoch 的四类控制凭据均已退役、且新 epoch 的对应批次均已激活时签发证明。
func (m *Manager) IssueControlRotationEvidence(poolID, accountRef string, fromEpoch, toEpoch uint64, providerAttestationRef string) (*ControlRotationEvidence, error) {
	poolID, accountRef, providerAttestationRef = strings.TrimSpace(poolID), strings.TrimSpace(accountRef), strings.TrimSpace(providerAttestationRef)
	if !validReference(poolID) || !validReference(accountRef) || fromEpoch == 0 || toEpoch != fromEpoch+1 || !validReference(providerAttestationRef) {
		return nil, errors.New("pool, account, consecutive membership epochs and provider attestation reference are required")
	}
	m.mu.Lock()
	defer m.mu.Unlock()
	retired := make(map[BatchType]string, len(controlBatchTypes))
	active := make(map[BatchType]string, len(controlBatchTypes))
	for _, batch := range m.batches {
		if batch.PoolID != poolID || batch.AccountRef != accountRef {
			continue
		}
		for _, batchType := range controlBatchTypes {
			if batch.Type != batchType {
				continue
			}
			if batch.MembershipEpoch == fromEpoch && batch.State == BatchRetired {
				retired[batchType] = batch.ID
			}
			if batch.MembershipEpoch == toEpoch && batch.State == BatchActive {
				active[batchType] = batch.ID
			}
		}
	}
	for _, batchType := range controlBatchTypes {
		if retired[batchType] == "" || active[batchType] == "" {
			return nil, fmt.Errorf("control credential type %s is not retired/activated across epochs", batchType)
		}
	}
	id, err := randomID(m.random)
	if err != nil {
		return nil, err
	}
	evidence := &ControlRotationEvidence{
		ID: id, PoolID: poolID, AccountRef: accountRef, FromEpoch: fromEpoch, ToEpoch: toEpoch,
		ProviderAttestationRef: providerAttestationRef,
		RetiredBatchIDs:        retired, ActiveBatchIDs: active, CreatedAt: m.now().UTC(),
	}
	m.evidence[id] = evidence
	return cloneControlRotationEvidence(evidence), nil
}

// ValidateControlRotationEvidence 复核证明范围及其引用批次的当前状态，防止跨 Pool/epoch 复用。
func (m *Manager) ValidateControlRotationEvidence(reference, poolID string, fromEpoch, toEpoch uint64) error {
	m.mu.Lock()
	defer m.mu.Unlock()
	return m.validateControlRotationEvidenceLocked(reference, poolID, fromEpoch, toEpoch)
}

func (m *Manager) validateControlRotationEvidenceLocked(reference, poolID string, fromEpoch, toEpoch uint64) error {
	evidence, ok := m.evidence[reference]
	if !ok || evidence.PoolID != poolID || evidence.FromEpoch != fromEpoch || evidence.ToEpoch != toEpoch || evidence.ProviderAttestationRef == "" {
		return errors.New("control credential rotation evidence is invalid for this seat epoch")
	}
	for _, batchType := range controlBatchTypes {
		oldBatch, oldOK := m.batches[evidence.RetiredBatchIDs[batchType]]
		newBatch, newOK := m.batches[evidence.ActiveBatchIDs[batchType]]
		if !oldOK || !newOK || oldBatch.AccountRef != evidence.AccountRef || newBatch.AccountRef != evidence.AccountRef ||
			oldBatch.PoolID != poolID || newBatch.PoolID != poolID || oldBatch.Type != batchType || newBatch.Type != batchType ||
			oldBatch.MembershipEpoch != fromEpoch || newBatch.MembershipEpoch != toEpoch ||
			oldBatch.State != BatchRetired || newBatch.State != BatchActive {
			return fmt.Errorf("control credential type %s no longer satisfies rotation evidence", batchType)
		}
	}
	return nil
}

// CommitControlRotationEvidence 在永久换员的上游访问密钥已轮换后推进 Pool epoch 写屏障。
// 即使随后发生进程内错误，也宁可阻止旧 epoch 写入，不能重新制造旧成员可用凭据。
func (m *Manager) CommitControlRotationEvidence(reference, poolID string, fromEpoch, toEpoch uint64) error {
	m.mu.Lock()
	defer m.mu.Unlock()
	if err := m.validateControlRotationEvidenceLocked(reference, poolID, fromEpoch, toEpoch); err != nil {
		return err
	}
	if current := m.minimumEpoch[poolID]; current > toEpoch {
		return errors.New("control rotation evidence is older than the committed membership epoch")
	}
	m.minimumEpoch[poolID] = toEpoch
	return nil
}

func (m *Manager) Seal(ctx context.Context, request SealRequest) (*Batch, error) {
	request.PoolID = strings.TrimSpace(request.PoolID)
	request.AccountRef = strings.TrimSpace(request.AccountRef)
	request.KeyRef = strings.TrimSpace(request.KeyRef)
	if !validReference(request.PoolID) || !validReference(request.AccountRef) || !validReference(request.KeyRef) || request.Version == 0 || request.MembershipEpoch == 0 {
		return nil, errors.New("pool, account, key reference, version and membership epoch are required")
	}
	if !validBatchType(request.Type) {
		return nil, errors.New("unsupported credential batch type")
	}
	if len(request.Plaintext) == 0 {
		return nil, errors.New("credential batch plaintext is empty")
	}
	m.mu.Lock()
	defer m.mu.Unlock()
	if floor := m.minimumEpoch[request.PoolID]; floor > 0 && request.MembershipEpoch < floor {
		return nil, errors.New("credential batch membership epoch is retired")
	}
	aad, err := additionalData(request.PoolID, request.AccountRef, request.Type, request.Version, request.MembershipEpoch)
	if err != nil {
		return nil, err
	}
	dek := make([]byte, 32)
	if _, err := io.ReadFull(m.random, dek); err != nil {
		return nil, fmt.Errorf("generate data encryption key: %w", err)
	}
	defer wipe(dek)
	block, err := aes.NewCipher(dek)
	if err != nil {
		return nil, err
	}
	gcm, err := cipher.NewGCM(block)
	if err != nil {
		return nil, err
	}
	nonce := make([]byte, gcm.NonceSize())
	if _, err := io.ReadFull(m.random, nonce); err != nil {
		return nil, fmt.Errorf("generate credential nonce: %w", err)
	}
	// AAD 将密文绑定到 Pool、账号、批次、版本和成员 epoch，防止跨上下文替换密文。
	ciphertext := gcm.Seal(nil, nonce, request.Plaintext, aad)
	wrappedDEK, err := m.wrapper.Wrap(ctx, request.KeyRef, dek)
	if err != nil {
		return nil, fmt.Errorf("wrap data encryption key: %w", err)
	}
	id, err := randomID(m.random)
	if err != nil {
		return nil, err
	}
	digest := sha256.Sum256(aad)
	batch := &Batch{
		ID: id, PoolID: request.PoolID, AccountRef: request.AccountRef, Type: request.Type,
		Version: request.Version, MembershipEpoch: request.MembershipEpoch, State: BatchSealed,
		Algorithm: "AES-256-GCM", KeyRef: request.KeyRef, Nonce: nonce, Ciphertext: ciphertext,
		WrappedDEK: wrappedDEK, AADHash: hex.EncodeToString(digest[:]), CreatedAt: m.now().UTC(),
	}
	for _, existing := range m.batches {
		if existing.PoolID == batch.PoolID && existing.AccountRef == batch.AccountRef && existing.Type == batch.Type &&
			existing.MembershipEpoch == batch.MembershipEpoch && existing.Version == batch.Version {
			return nil, errors.New("credential batch version already exists")
		}
	}
	m.batches[id] = batch
	return cloneBatch(batch), nil
}

func (m *Manager) Open(ctx context.Context, id string) ([]byte, error) {
	m.mu.Lock()
	batch, ok := m.batches[id]
	if !ok {
		m.mu.Unlock()
		return nil, errors.New("credential batch not found")
	}
	if floor := m.minimumEpoch[batch.PoolID]; floor > 0 && batch.MembershipEpoch < floor {
		m.mu.Unlock()
		return nil, errors.New("credential batch membership epoch is retired")
	}
	copy := cloneBatch(batch)
	m.mu.Unlock()
	if copy.State == BatchRetired {
		return nil, errors.New("retired credential batch cannot be opened")
	}
	aad, err := additionalData(copy.PoolID, copy.AccountRef, copy.Type, copy.Version, copy.MembershipEpoch)
	if err != nil {
		return nil, err
	}
	digest := sha256.Sum256(aad)
	if copy.AADHash != hex.EncodeToString(digest[:]) {
		return nil, errors.New("credential batch AAD metadata mismatch")
	}
	dek, err := m.wrapper.Unwrap(ctx, copy.KeyRef, copy.WrappedDEK)
	if err != nil {
		return nil, fmt.Errorf("unwrap data encryption key: %w", err)
	}
	defer wipe(dek)
	block, err := aes.NewCipher(dek)
	if err != nil {
		return nil, err
	}
	gcm, err := cipher.NewGCM(block)
	if err != nil {
		return nil, err
	}
	plaintext, err := gcm.Open(nil, copy.Nonce, copy.Ciphertext, aad)
	if err != nil {
		return nil, errors.New("credential batch authentication failed")
	}
	return plaintext, nil
}

func (m *Manager) Get(id string) (*Batch, bool) {
	m.mu.Lock()
	defer m.mu.Unlock()
	batch, ok := m.batches[id]
	return cloneBatch(batch), ok
}

func (m *Manager) Activate(id string) (*Batch, error) {
	m.mu.Lock()
	defer m.mu.Unlock()
	batch, ok := m.batches[id]
	if !ok {
		return nil, errors.New("credential batch not found")
	}
	if floor := m.minimumEpoch[batch.PoolID]; floor > 0 && batch.MembershipEpoch < floor {
		return nil, errors.New("credential batch membership epoch is retired")
	}
	if batch.State == BatchActive {
		return cloneBatch(batch), nil
	}
	if batch.State != BatchSealed {
		return nil, fmt.Errorf("cannot activate credential batch in state %s", batch.State)
	}
	for _, existing := range m.batches {
		if existing.ID != batch.ID && existing.PoolID == batch.PoolID && existing.AccountRef == batch.AccountRef &&
			existing.Type == batch.Type && existing.MembershipEpoch == batch.MembershipEpoch && existing.State == BatchActive {
			return nil, errors.New("another credential batch is already active for this membership epoch")
		}
	}
	now := m.now().UTC()
	batch.State = BatchActive
	batch.ActivatedAt = &now
	return cloneBatch(batch), nil
}

func (m *Manager) Retire(id string) (*Batch, error) {
	m.mu.Lock()
	defer m.mu.Unlock()
	batch, ok := m.batches[id]
	if !ok {
		return nil, errors.New("credential batch not found")
	}
	if batch.State == BatchRetired {
		return cloneBatch(batch), nil
	}
	if batch.State != BatchActive {
		return nil, fmt.Errorf("cannot retire credential batch in state %s", batch.State)
	}
	now := m.now().UTC()
	batch.State = BatchRetired
	batch.RetiredAt = &now
	return cloneBatch(batch), nil
}

type LocalKeyWrapper struct {
	key    []byte
	random io.Reader
}

func NewLocalKeyWrapper(key []byte, random io.Reader) (*LocalKeyWrapper, error) {
	if len(key) != 32 {
		return nil, errors.New("local key encryption key must be exactly 32 bytes")
	}
	if random == nil {
		random = rand.Reader
	}
	return &LocalKeyWrapper{key: append([]byte(nil), key...), random: random}, nil
}

func (w *LocalKeyWrapper) Wrap(_ context.Context, keyRef string, plaintext []byte) ([]byte, error) {
	block, err := aes.NewCipher(w.key)
	if err != nil {
		return nil, err
	}
	gcm, err := cipher.NewGCM(block)
	if err != nil {
		return nil, err
	}
	nonce := make([]byte, gcm.NonceSize())
	if _, err := io.ReadFull(w.random, nonce); err != nil {
		return nil, err
	}
	return append(nonce, gcm.Seal(nil, nonce, plaintext, []byte(keyRef))...), nil
}

func (w *LocalKeyWrapper) Unwrap(_ context.Context, keyRef string, wrapped []byte) ([]byte, error) {
	block, err := aes.NewCipher(w.key)
	if err != nil {
		return nil, err
	}
	gcm, err := cipher.NewGCM(block)
	if err != nil {
		return nil, err
	}
	if len(wrapped) < gcm.NonceSize()+gcm.Overhead() {
		return nil, errors.New("wrapped key is truncated")
	}
	nonce := wrapped[:gcm.NonceSize()]
	return gcm.Open(nil, nonce, wrapped[gcm.NonceSize():], []byte(keyRef))
}

func additionalData(poolID, accountRef string, batchType BatchType, version, epoch uint64) ([]byte, error) {
	return json.Marshal(struct {
		PoolID          string    `json:"pool_id"`
		AccountRef      string    `json:"account_ref"`
		Type            BatchType `json:"batch_type"`
		Version         uint64    `json:"version"`
		MembershipEpoch uint64    `json:"membership_epoch"`
	}{poolID, accountRef, batchType, version, epoch})
}

func validBatchType(value BatchType) bool {
	switch value {
	case BatchOperational, BatchLogin, BatchMFA, BatchRecovery, BatchOwnership:
		return true
	default:
		return false
	}
}

func validReference(value string) bool {
	return len(value) > 0 && len(value) <= 128
}

func randomID(random io.Reader) (string, error) {
	value := make([]byte, 16)
	if _, err := io.ReadFull(random, value); err != nil {
		return "", err
	}
	return hex.EncodeToString(value), nil
}

func cloneBatch(batch *Batch) *Batch {
	if batch == nil {
		return nil
	}
	copy := *batch
	copy.Nonce = append([]byte(nil), batch.Nonce...)
	copy.Ciphertext = append([]byte(nil), batch.Ciphertext...)
	copy.WrappedDEK = append([]byte(nil), batch.WrappedDEK...)
	return &copy
}

func cloneControlRotationEvidence(evidence *ControlRotationEvidence) *ControlRotationEvidence {
	if evidence == nil {
		return nil
	}
	copy := *evidence
	copy.RetiredBatchIDs = make(map[BatchType]string, len(evidence.RetiredBatchIDs))
	copy.ActiveBatchIDs = make(map[BatchType]string, len(evidence.ActiveBatchIDs))
	for batchType, id := range evidence.RetiredBatchIDs {
		copy.RetiredBatchIDs[batchType] = id
	}
	for batchType, id := range evidence.ActiveBatchIDs {
		copy.ActiveBatchIDs[batchType] = id
	}
	return &copy
}

func wipe(value []byte) {
	for index := range value {
		value[index] = 0
	}
}
