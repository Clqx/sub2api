package runtime

import (
	"encoding/hex"
	"errors"
	"fmt"
	"os"
	"strconv"
	"strings"
	"time"

	"trusted-pool-platform/backend/internal/credentials"
	"trusted-pool-platform/backend/internal/persistence/postgres"
)

const (
	ModeProduction  = "production"
	ModeDevelopment = "development"

	EnvelopeModeKMS   = "kms"
	EnvelopeModeLocal = "local"
)

type Config struct {
	Mode                        string
	Database                    postgres.DBConfig
	MigrationDatabase           postgres.DBConfig
	MigrationsDir               string
	MigrationLimit              time.Duration
	WorkerID                    string
	WorkflowLease               time.Duration
	ClaimTTL                    time.Duration
	RecoveryBackoff             time.Duration
	RecoveryIdleBackoff         time.Duration
	EnvelopeMode                string
	KMSProvider                 string
	KMSKeyRef                   string
	AllowLocalKEK               bool
	LocalKEK                    []byte
	BatchClientID               string
	RecoveryClientID            string
	RecoveryGovernanceEnabled   bool
	RecoveryPortableEvidence    bool
	RecoveryCryptoSuiteID       string
	RecoveryEvidenceExport      bool
	RecoveryEvidenceClientID    string
	RecoveryEvidenceSigner      string
	RecoveryEvidenceSignerKey   string
	RecoveryRootProviderID      string
	RecoveryRootTrustProfile    string
	RecoveryReplacementClaimTTL time.Duration
	BatchOnlineWrapAlgorithm    string
	BatchOnlineDomain           string
	BatchOnlineKeyRef           string
	BatchRecoveryWrapAlgorithm  string
	BatchRecoveryDomain         string
	BatchRecoveryKeyRef         string
	BatchFingerprintKeyRef      string
	BatchFingerprintKey         []byte
	LocalRecoveryKEK            []byte
}

func LoadConfig() (Config, error) {
	return loadConfig(os.LookupEnv)
}

func loadConfig(lookup func(string) (string, bool)) (Config, error) {
	mode := valueOrDefault(lookup, "TRUSTED_POOL_RUNTIME_MODE", ModeProduction)
	envelopeMode := valueOrDefault(lookup, "TRUSTED_POOL_ENVELOPE_MODE", EnvelopeModeKMS)
	migrationLimit, err := durationValue(lookup, "TRUSTED_POOL_MIGRATION_TIMEOUT", 2*time.Minute)
	if err != nil {
		return Config{}, err
	}
	workflowLease, err := durationValue(lookup, "TRUSTED_POOL_WORKFLOW_LEASE_DURATION", 30*time.Second)
	if err != nil {
		return Config{}, err
	}
	claimTTL, err := durationValue(lookup, "TRUSTED_POOL_CLAIM_TTL", 10*time.Minute)
	if err != nil {
		return Config{}, err
	}
	recoveryBackoff, err := durationValue(lookup, "TRUSTED_POOL_RECOVERY_BACKOFF", time.Minute)
	if err != nil {
		return Config{}, err
	}
	recoveryIdleBackoff, err := durationValue(lookup, "TRUSTED_POOL_RECOVERY_IDLE_BACKOFF", time.Second)
	if err != nil {
		return Config{}, err
	}
	maxOpen, err := intValue(lookup, "TRUSTED_POOL_DB_MAX_OPEN", 20)
	if err != nil {
		return Config{}, err
	}
	maxIdle, err := intValue(lookup, "TRUSTED_POOL_DB_MAX_IDLE", 5)
	if err != nil {
		return Config{}, err
	}
	recoveryGovernanceEnabled, err := boolValue(lookup, "TRUSTED_POOL_RECOVERY_GOVERNANCE_ENABLED", false)
	if err != nil {
		return Config{}, err
	}
	recoveryPortableEvidence, err := boolValue(lookup, "TRUSTED_POOL_RECOVERY_PORTABLE_EVIDENCE_ENABLED", false)
	if err != nil {
		return Config{}, err
	}
	recoveryEvidenceExport, err := boolValue(lookup, "TRUSTED_POOL_RECOVERY_EVIDENCE_EXPORT_ENABLED", false)
	if err != nil {
		return Config{}, err
	}
	recoveryReplacementClaimTTL, err := durationValue(lookup,
		"TRUSTED_POOL_RECOVERY_REPLACEMENT_CLAIM_TTL", 10*time.Minute)
	if err != nil {
		return Config{}, err
	}
	databaseURL := value(lookup, "TRUSTED_POOL_DATABASE_URL")
	migrationDatabaseURL := value(lookup, "TRUSTED_POOL_MIGRATION_DATABASE_URL")
	if migrationDatabaseURL == "" && mode == ModeDevelopment {
		migrationDatabaseURL = databaseURL
	}
	config := Config{
		Mode: mode,
		Database: postgres.DBConfig{
			URL: databaseURL, MaxOpenConns: maxOpen, MaxIdleConns: maxIdle,
		},
		MigrationDatabase: postgres.DBConfig{
			URL: migrationDatabaseURL, MaxOpenConns: 1, MaxIdleConns: 1,
		},
		MigrationsDir:               valueOrDefault(lookup, "TRUSTED_POOL_MIGRATIONS_DIR", "../migrations"),
		MigrationLimit:              migrationLimit,
		WorkerID:                    value(lookup, "TRUSTED_POOL_WORKER_ID"),
		WorkflowLease:               workflowLease,
		ClaimTTL:                    claimTTL,
		RecoveryBackoff:             recoveryBackoff,
		RecoveryIdleBackoff:         recoveryIdleBackoff,
		EnvelopeMode:                envelopeMode,
		KMSProvider:                 value(lookup, "TRUSTED_POOL_KMS_PROVIDER"),
		KMSKeyRef:                   value(lookup, "TRUSTED_POOL_KMS_KEY_REF"),
		BatchClientID:               value(lookup, "TRUSTED_POOL_BATCH_CLIENT_ID"),
		RecoveryClientID:            value(lookup, "TRUSTED_POOL_RECOVERY_CLIENT_ID"),
		RecoveryGovernanceEnabled:   recoveryGovernanceEnabled,
		RecoveryPortableEvidence:    recoveryPortableEvidence,
		RecoveryCryptoSuiteID:       value(lookup, "TRUSTED_POOL_RECOVERY_CRYPTO_SUITE_ID"),
		RecoveryEvidenceExport:      recoveryEvidenceExport,
		RecoveryEvidenceClientID:    value(lookup, "TRUSTED_POOL_RECOVERY_EVIDENCE_CLIENT_ID"),
		RecoveryEvidenceSigner:      value(lookup, "TRUSTED_POOL_RECOVERY_EVIDENCE_SIGNER_PROVIDER"),
		RecoveryEvidenceSignerKey:   value(lookup, "TRUSTED_POOL_RECOVERY_EVIDENCE_SIGNER_KEY_REF"),
		RecoveryRootProviderID:      value(lookup, "TRUSTED_POOL_RECOVERY_ROOT_PROVIDER_ID"),
		RecoveryRootTrustProfile:    value(lookup, "TRUSTED_POOL_RECOVERY_ROOT_TRUST_PROFILE"),
		RecoveryReplacementClaimTTL: recoveryReplacementClaimTTL,
		BatchOnlineWrapAlgorithm:    value(lookup, "TRUSTED_POOL_BATCH_KMS_WRAP_ALGORITHM"),
		BatchOnlineDomain:           value(lookup, "TRUSTED_POOL_BATCH_KMS_DOMAIN"),
		BatchOnlineKeyRef:           value(lookup, "TRUSTED_POOL_BATCH_KMS_KEY_REF"),
		BatchRecoveryWrapAlgorithm:  value(lookup, "TRUSTED_POOL_BATCH_RECOVERY_WRAP_ALGORITHM"),
		BatchRecoveryDomain:         value(lookup, "TRUSTED_POOL_BATCH_RECOVERY_DOMAIN"),
		BatchRecoveryKeyRef:         value(lookup, "TRUSTED_POOL_BATCH_RECOVERY_KEY_REF"),
		BatchFingerprintKeyRef:      value(lookup, "TRUSTED_POOL_BATCH_FINGERPRINT_KEY_REF"),
	}
	allow, err := boolValue(lookup, "TRUSTED_POOL_ALLOW_INSECURE_LOCAL_KEK", false)
	if err != nil {
		return Config{}, err
	}
	config.AllowLocalKEK = allow
	if raw := value(lookup, "TRUSTED_POOL_KEK_HEX"); raw != "" {
		decoded, decodeErr := hex.DecodeString(raw)
		if decodeErr != nil || len(decoded) != 32 {
			return Config{}, errors.New("TRUSTED_POOL_KEK_HEX must encode exactly 32 bytes")
		}
		config.LocalKEK = decoded
	}
	if raw := value(lookup, "TRUSTED_POOL_BATCH_FINGERPRINT_HMAC_KEY_HEX"); raw != "" {
		decoded, decodeErr := hex.DecodeString(raw)
		if decodeErr != nil || len(decoded) != 32 {
			return Config{}, errors.New("TRUSTED_POOL_BATCH_FINGERPRINT_HMAC_KEY_HEX must encode exactly 32 bytes")
		}
		config.BatchFingerprintKey = decoded
	}
	if raw := value(lookup, "TRUSTED_POOL_RECOVERY_KEK_HEX"); raw != "" {
		decoded, decodeErr := hex.DecodeString(raw)
		if decodeErr != nil || len(decoded) != 32 {
			return Config{}, errors.New("TRUSTED_POOL_RECOVERY_KEK_HEX must encode exactly 32 bytes")
		}
		config.LocalRecoveryKEK = decoded
	}
	if err := config.validate(); err != nil {
		return Config{}, err
	}
	return config, nil
}

func (c Config) validate() error {
	if c.Mode != ModeProduction && c.Mode != ModeDevelopment {
		return errors.New("TRUSTED_POOL_RUNTIME_MODE must be production or development")
	}
	if c.Database.URL == "" {
		return errors.New("TRUSTED_POOL_DATABASE_URL is required; memory fallback is forbidden")
	}
	if c.MigrationDatabase.URL == "" {
		return errors.New("TRUSTED_POOL_MIGRATION_DATABASE_URL is required in production")
	}
	if c.MigrationsDir == "" || c.MigrationLimit <= 0 {
		return errors.New("migration directory and positive timeout are required")
	}
	if c.WorkerID == "" {
		return errors.New("TRUSTED_POOL_WORKER_ID is required for persistent lease ownership")
	}
	if c.WorkflowLease <= 0 || c.ClaimTTL <= 0 || c.ClaimTTL > 24*time.Hour ||
		c.RecoveryBackoff <= 0 || c.RecoveryIdleBackoff <= 0 {
		return errors.New("workflow durations must be positive and claim TTL must not exceed 24h")
	}
	if c.KMSKeyRef == "" {
		return errors.New("TRUSTED_POOL_KMS_KEY_REF is required")
	}
	if c.BatchClientID == "" || c.BatchOnlineWrapAlgorithm == "" || c.BatchOnlineDomain == "" ||
		c.BatchOnlineKeyRef == "" || c.BatchRecoveryWrapAlgorithm == "" || c.BatchRecoveryDomain == "" ||
		c.BatchRecoveryKeyRef == "" || c.BatchFingerprintKeyRef == "" || len(c.BatchFingerprintKey) != 32 {
		return errors.New("credential batch client, dual wrapping and fingerprint configuration are required")
	}
	if c.RecoveryGovernanceEnabled && (c.RecoveryClientID == "" || c.RecoveryRootProviderID == "" ||
		c.RecoveryRootTrustProfile == "" || c.WorkflowLease < 30*time.Second || c.WorkflowLease > 5*time.Minute ||
		c.RecoveryReplacementClaimTTL <= 0 || c.RecoveryReplacementClaimTTL > 30*time.Minute) {
		return errors.New("recovery governance client, root provider trust profile and lease up to 5m are required")
	}
	if c.RecoveryPortableEvidence && (!c.RecoveryGovernanceEnabled || c.RecoveryCryptoSuiteID == "") {
		return errors.New("portable recovery evidence requires enabled governance and an explicit crypto suite")
	}
	if c.RecoveryEvidenceExport && (!c.RecoveryPortableEvidence || c.RecoveryEvidenceClientID == "" ||
		c.RecoveryEvidenceSigner == "" || c.RecoveryEvidenceSignerKey == "" ||
		c.RecoveryEvidenceClientID == c.RecoveryClientID) {
		return errors.New("recovery evidence export requires portable governance, an independent client and external signer")
	}
	if c.BatchOnlineDomain == c.BatchRecoveryDomain || c.BatchOnlineKeyRef == c.BatchRecoveryKeyRef {
		return errors.New("online and Recovery credential batch wrappers must use independent domains and keys")
	}
	if c.Mode == ModeProduction {
		if c.MigrationDatabase.URL == c.Database.URL {
			return errors.New("production migration and runtime database identities must be separate")
		}
		if c.EnvelopeMode != EnvelopeModeKMS {
			return errors.New("production mode requires TRUSTED_POOL_ENVELOPE_MODE=kms")
		}
		if c.KMSProvider == "" {
			return errors.New("production mode requires TRUSTED_POOL_KMS_PROVIDER")
		}
		if c.AllowLocalKEK || len(c.LocalKEK) != 0 || len(c.LocalRecoveryKEK) != 0 {
			return errors.New("production mode forbids environment local KEK or Recovery KEK")
		}
		return nil
	}
	if c.EnvelopeMode != EnvelopeModeLocal {
		return errors.New("development runtime currently requires TRUSTED_POOL_ENVELOPE_MODE=local")
	}
	if !c.AllowLocalKEK || len(c.LocalKEK) != 32 || len(c.LocalRecoveryKEK) != 32 {
		return errors.New("local online and Recovery KEKs require development mode and TRUSTED_POOL_ALLOW_INSECURE_LOCAL_KEK=true")
	}
	if string(c.LocalKEK) == string(c.LocalRecoveryKEK) {
		return errors.New("development online and Recovery KEKs must differ")
	}
	return nil
}

type Crypto struct {
	Wrapper credentials.KMSKeyWrapper
	Cipher  credentials.EnvelopeCipher
}

// BuildCrypto 要求生产组合根显式注入 KMS adapter；nil 时直接失败，绝不退回环境 KEK。
func BuildCrypto(config Config, productionWrapper credentials.KMSKeyWrapper) (Crypto, error) {
	var wrapper credentials.KMSKeyWrapper
	switch config.Mode {
	case ModeProduction:
		if productionWrapper == nil {
			return Crypto{}, fmt.Errorf("KMS provider %q adapter is not linked", config.KMSProvider)
		}
		wrapper = productionWrapper
	case ModeDevelopment:
		local, err := credentials.NewDevelopmentLocalKMS(config.LocalKEK, nil)
		if err != nil {
			return Crypto{}, err
		}
		wrapper = local
	default:
		return Crypto{}, errors.New("unsupported runtime mode")
	}
	cipher, err := credentials.NewKMSEnvelopeCipher(wrapper, config.KMSKeyRef, nil)
	if err != nil {
		return Crypto{}, err
	}
	return Crypto{Wrapper: wrapper, Cipher: cipher}, nil
}

func value(lookup func(string) (string, bool), name string) string {
	raw, _ := lookup(name)
	return strings.TrimSpace(raw)
}

func valueOrDefault(lookup func(string) (string, bool), name, fallback string) string {
	if raw := value(lookup, name); raw != "" {
		return raw
	}
	return fallback
}

func intValue(lookup func(string) (string, bool), name string, fallback int) (int, error) {
	raw := value(lookup, name)
	if raw == "" {
		return fallback, nil
	}
	parsed, err := strconv.Atoi(raw)
	if err != nil || parsed <= 0 {
		return 0, fmt.Errorf("%s must be a positive integer", name)
	}
	return parsed, nil
}

func boolValue(lookup func(string) (string, bool), name string, fallback bool) (bool, error) {
	raw := value(lookup, name)
	if raw == "" {
		return fallback, nil
	}
	parsed, err := strconv.ParseBool(raw)
	if err != nil {
		return false, fmt.Errorf("%s must be a boolean", name)
	}
	return parsed, nil
}

func durationValue(lookup func(string) (string, bool), name string, fallback time.Duration) (time.Duration, error) {
	raw := value(lookup, name)
	if raw == "" {
		return fallback, nil
	}
	parsed, err := time.ParseDuration(raw)
	if err != nil || parsed <= 0 {
		return 0, fmt.Errorf("%s must be a positive Go duration", name)
	}
	return parsed, nil
}
