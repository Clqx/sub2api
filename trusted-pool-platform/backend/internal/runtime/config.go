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
	Mode                string
	Database            postgres.DBConfig
	MigrationsDir       string
	MigrationLimit      time.Duration
	WorkerID            string
	WorkflowLease       time.Duration
	ClaimTTL            time.Duration
	RecoveryBackoff     time.Duration
	RecoveryIdleBackoff time.Duration
	EnvelopeMode        string
	KMSProvider         string
	KMSKeyRef           string
	AllowLocalKEK       bool
	LocalKEK            []byte
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
	config := Config{
		Mode: mode,
		Database: postgres.DBConfig{
			URL: value(lookup, "TRUSTED_POOL_DATABASE_URL"), MaxOpenConns: maxOpen, MaxIdleConns: maxIdle,
		},
		MigrationsDir:       valueOrDefault(lookup, "TRUSTED_POOL_MIGRATIONS_DIR", "../migrations"),
		MigrationLimit:      migrationLimit,
		WorkerID:            value(lookup, "TRUSTED_POOL_WORKER_ID"),
		WorkflowLease:       workflowLease,
		ClaimTTL:            claimTTL,
		RecoveryBackoff:     recoveryBackoff,
		RecoveryIdleBackoff: recoveryIdleBackoff,
		EnvelopeMode:        envelopeMode,
		KMSProvider:         value(lookup, "TRUSTED_POOL_KMS_PROVIDER"),
		KMSKeyRef:           value(lookup, "TRUSTED_POOL_KMS_KEY_REF"),
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
	if c.Mode == ModeProduction {
		if c.EnvelopeMode != EnvelopeModeKMS {
			return errors.New("production mode requires TRUSTED_POOL_ENVELOPE_MODE=kms")
		}
		if c.KMSProvider == "" {
			return errors.New("production mode requires TRUSTED_POOL_KMS_PROVIDER")
		}
		if c.AllowLocalKEK || len(c.LocalKEK) != 0 {
			return errors.New("production mode forbids environment local KEK")
		}
		return nil
	}
	if c.EnvelopeMode != EnvelopeModeLocal {
		return errors.New("development runtime currently requires TRUSTED_POOL_ENVELOPE_MODE=local")
	}
	if !c.AllowLocalKEK || len(c.LocalKEK) != 32 {
		return errors.New("local KEK requires development mode and TRUSTED_POOL_ALLOW_INSECURE_LOCAL_KEK=true")
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
