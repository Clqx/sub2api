package main

import (
	"context"
	"crypto/ed25519"
	"encoding/base64"
	"errors"
	"log"
	"net/http"
	"net/url"
	"os"
	"os/signal"
	"strings"
	"syscall"
	"time"

	"trusted-pool-platform/backend/internal/application"
	"trusted-pool-platform/backend/internal/credentials"
	"trusted-pool-platform/backend/internal/httpapi"
	"trusted-pool-platform/backend/internal/integration/sub2api"
	"trusted-pool-platform/backend/internal/persistence/postgres"
	"trusted-pool-platform/backend/internal/recovery"
	"trusted-pool-platform/backend/internal/recovery/exporter"
	"trusted-pool-platform/backend/internal/risk"
	appRuntime "trusted-pool-platform/backend/internal/runtime"
)

func main() {
	if err := run(); err != nil {
		log.Fatal(err)
	}
}

func run() error {
	runtimeConfig, err := appRuntime.LoadConfig()
	if err != nil {
		return err
	}
	migrationConnectContext, cancelMigrationConnect := context.WithTimeout(context.Background(), 10*time.Second)
	migrationDB, err := postgres.OpenDB(migrationConnectContext, runtimeConfig.MigrationDatabase)
	cancelMigrationConnect()
	if err != nil {
		return err
	}
	migrationContext, cancelMigration := context.WithTimeout(context.Background(), runtimeConfig.MigrationLimit)
	err = postgres.Migrate(migrationContext, migrationDB, os.DirFS(runtimeConfig.MigrationsDir))
	cancelMigration()
	closeMigrationErr := migrationDB.Close()
	if err != nil {
		return err
	}
	if closeMigrationErr != nil {
		return closeMigrationErr
	}
	connectContext, cancelConnect := context.WithTimeout(context.Background(), 10*time.Second)
	db, err := postgres.OpenDB(connectContext, runtimeConfig.Database)
	cancelConnect()
	if err != nil {
		return err
	}
	defer db.Close()
	workflowStore, err := postgres.NewStore(db)
	if err != nil {
		return err
	}
	cryptoRuntime, err := appRuntime.BuildCrypto(runtimeConfig, nil)
	if err != nil {
		return err
	}
	batchSealer, err := appRuntime.BuildBatchSealer(runtimeConfig, cryptoRuntime.Wrapper, nil, nil)
	if err != nil {
		return err
	}

	apiKey, err := requiredSecret("TRUSTED_POOL_API_KEY", 32)
	if err != nil {
		return err
	}
	settlementAPIKey, err := requiredSecret("TRUSTED_POOL_SETTLEMENT_API_KEY", 32)
	if err != nil {
		return err
	}
	batchAPIKey, err := requiredSecret("TRUSTED_POOL_BATCH_API_KEY", 32)
	if err != nil {
		return err
	}
	var recoveryAPIKey string
	if runtimeConfig.RecoveryGovernanceEnabled {
		recoveryAPIKey, err = requiredSecret("TRUSTED_POOL_RECOVERY_API_KEY", 32)
		if err != nil {
			return err
		}
	}
	fingerprintKey, err := requiredSecret("TRUSTED_POOL_FINGERPRINT_HMAC_KEY", 32)
	if err != nil {
		return err
	}
	baseURL := os.Getenv("SUB2API_BASE_URL")
	if err := validateSub2APITransport(runtimeConfig.Mode, baseURL); err != nil {
		return err
	}
	integrationClientID, err := requiredSecret("SUB2API_INTEGRATION_CLIENT_ID", 1)
	if err != nil {
		return err
	}
	integrationClientID = strings.TrimSpace(integrationClientID)
	integrationSecret, err := requiredSecret("SUB2API_INTEGRATION_SECRET", 16)
	if err != nil {
		return err
	}
	upstream, err := sub2api.NewClient(baseURL, integrationClientID, integrationSecret, nil)
	if err != nil {
		return err
	}
	settlementReadClientID, err := requiredSecret("SUB2API_SETTLEMENT_READ_CLIENT_ID", 1)
	if err != nil {
		return err
	}
	settlementReadClientID = strings.TrimSpace(settlementReadClientID)
	settlementReadSecret, err := requiredSecret("SUB2API_SETTLEMENT_READ_SECRET", 16)
	if err != nil {
		return err
	}
	settlementResolveClientID, err := requiredSecret("SUB2API_SETTLEMENT_RESOLVE_CLIENT_ID", 1)
	if err != nil {
		return err
	}
	settlementResolveClientID = strings.TrimSpace(settlementResolveClientID)
	settlementResolveSecret, err := requiredSecret("SUB2API_SETTLEMENT_RESOLVE_SECRET", 16)
	if err != nil {
		return err
	}
	if err := validateIndependentSettlementCredentials(
		integrationClientID, integrationSecret,
		settlementReadClientID, settlementReadSecret,
		settlementResolveClientID, settlementResolveSecret,
	); err != nil {
		return err
	}
	if err := validateIndependentBatchClient(runtimeConfig.BatchClientID,
		integrationClientID, settlementReadClientID, settlementResolveClientID); err != nil {
		return err
	}
	if runtimeConfig.RecoveryGovernanceEnabled {
		if err := validateIndependentRecoveryClient(runtimeConfig.RecoveryClientID,
			runtimeConfig.BatchClientID, integrationClientID, settlementReadClientID, settlementResolveClientID); err != nil {
			return err
		}
	}
	if runtimeConfig.RecoveryEvidenceExport {
		if err := validateIndependentEvidenceExportClient(runtimeConfig.RecoveryEvidenceClientID,
			runtimeConfig.RecoveryClientID, runtimeConfig.BatchClientID, integrationClientID,
			settlementReadClientID, settlementResolveClientID); err != nil {
			return err
		}
	}
	var recoveryRotation *sub2api.RecoveryRotationClient
	if runtimeConfig.RecoveryGovernanceEnabled {
		rotationClientID, rotationErr := requiredSecret("SUB2API_RECOVERY_ROTATION_CLIENT_ID", 1)
		if rotationErr != nil {
			return rotationErr
		}
		rotationClientID = strings.TrimSpace(rotationClientID)
		rotationSecret, rotationErr := requiredSecret("SUB2API_RECOVERY_ROTATION_SECRET", 16)
		if rotationErr != nil {
			return rotationErr
		}
		if rotationErr = validateIndependentRecoveryRotationCredentials(rotationClientID, rotationSecret,
			[]string{integrationClientID, settlementReadClientID, settlementResolveClientID},
			[]string{integrationSecret, settlementReadSecret, settlementResolveSecret}); rotationErr != nil {
			return rotationErr
		}
		attestationKeyID, rotationErr := requiredSecret("SUB2API_RECOVERY_ROTATION_ATTESTATION_KEY_ID", 1)
		if rotationErr != nil {
			return rotationErr
		}
		publicKey, rotationErr := decodeEd25519PublicKey(
			os.Getenv("SUB2API_RECOVERY_ROTATION_ATTESTATION_PUBLIC_KEY_BASE64"))
		if rotationErr != nil {
			return rotationErr
		}
		recoveryRotation, rotationErr = sub2api.NewRecoveryRotationClient(baseURL, rotationClientID,
			rotationSecret, strings.TrimSpace(attestationKeyID), publicKey, nil)
		if rotationErr != nil {
			return rotationErr
		}
	}
	settlementRead, err := sub2api.NewSettlementReadClient(baseURL, settlementReadClientID, settlementReadSecret, nil)
	if err != nil {
		return err
	}
	settlementResolve, err := sub2api.NewSettlementResolveClient(baseURL, settlementResolveClientID, settlementResolveSecret, nil)
	if err != nil {
		return err
	}
	riskAggregator, err := risk.NewAggregator([]byte(fingerprintKey), risk.DefaultPolicy())
	if err != nil {
		return err
	}
	applicationCipher, err := appRuntime.NewApplicationEnvelopeCipher(cryptoRuntime.Cipher)
	if err != nil {
		return err
	}
	coordinator, err := application.NewPersistentCoordinator(workflowStore, upstream, applicationCipher,
		application.PersistentCoordinatorOptions{
			IntegrationClientID: integrationClientID,
			SettlementActorID:   settlementResolveClientID,
			SettlementRead:      settlementRead,
			SettlementResolve:   settlementResolve,
			WorkerID:            runtimeConfig.WorkerID,
			LeaseDuration:       runtimeConfig.WorkflowLease,
			ClaimTTL:            runtimeConfig.ClaimTTL,
			RecoveryBackoff:     runtimeConfig.RecoveryBackoff,
			Now:                 time.Now,
		})
	if err != nil {
		return err
	}
	credentialBatchManager, err := credentials.NewPersistentManager(workflowStore, batchSealer,
		credentials.PersistentManagerConfig{
			ClientID: runtimeConfig.BatchClientID, LeaseOwner: runtimeConfig.WorkerID,
			LeaseDuration: runtimeConfig.WorkflowLease,
		})
	if err != nil {
		return err
	}
	var recoveryManager *recovery.Manager
	if runtimeConfig.RecoveryGovernanceEnabled {
		// 启用开关只允许完整生产适配器；当前二进制尚未链接这些适配器，因此必须拒绝启动。
		recoveryProviders := appRuntime.BuildRecoveryProviders(nil, nil, nil, nil, nil, nil, nil,
			recoveryRotation, recoveryRotation,
			cryptoRuntime.Cipher)
		if err := recoveryProviders.Ready(context.Background()); err != nil {
			return errors.New("recovery governance is enabled but production providers are not configured")
		}
		recoveryManager, err = recovery.NewManager(workflowStore, recoveryProviders, recovery.ManagerConfig{
			ClientID: runtimeConfig.RecoveryClientID, LeaseOwner: runtimeConfig.WorkerID,
			LeaseDuration: runtimeConfig.WorkflowLease, ExpectedRootProviderID: runtimeConfig.RecoveryRootProviderID,
			RootTrustProfile:      runtimeConfig.RecoveryRootTrustProfile,
			PortableEvidence:      runtimeConfig.RecoveryPortableEvidence,
			RecoveryCryptoSuiteID: runtimeConfig.RecoveryCryptoSuiteID,
			ReplacementClaimTTL:   runtimeConfig.RecoveryReplacementClaimTTL,
			FinalizationBackoff:   runtimeConfig.RecoveryBackoff,
		})
		if err != nil {
			return err
		}
	}
	var verificationExporter *exporter.Manager
	if runtimeConfig.RecoveryEvidenceExport {
		// The binary intentionally has no fallback signer. A production HSM/KMS signer adapter must be
		// injected by the composition root before this feature can listen on HTTP.
		verificationExporter, err = appRuntime.BuildVerificationExporter(workflowStore, nil,
			appRuntime.VerificationExportConfig{ClientID: runtimeConfig.RecoveryEvidenceClientID,
				LeaseOwner: runtimeConfig.WorkerID, LeaseDuration: runtimeConfig.WorkflowLease})
		if err != nil {
			return errors.New("recovery evidence export is enabled but the external signer adapter is not configured")
		}
	}
	probes := []appRuntime.Probe{postgres.DBProbe{DB: db}, appRuntime.EnvelopeProbe{Cipher: cryptoRuntime.Cipher},
		appRuntime.BatchProbe{Manager: credentialBatchManager}}
	if recoveryManager != nil {
		probes = append(probes, appRuntime.RecoveryProbe{Manager: recoveryManager})
	}
	if verificationExporter != nil {
		probes = append(probes, appRuntime.VerificationExportProbe{Manager: verificationExporter})
	}
	readiness, err := appRuntime.NewReadiness(2*time.Second, probes...)
	if err != nil {
		return err
	}
	var api *httpapi.Server
	if recoveryManager == nil {
		api, err = httpapi.NewServer(coordinator, riskAggregator, credentialBatchManager,
			apiKey, settlementAPIKey, batchAPIKey)
	} else {
		api, err = httpapi.NewServerWithRecoveryEvidence(coordinator, riskAggregator, credentialBatchManager,
			recoveryManager, verificationExporter,
			apiKey, settlementAPIKey, batchAPIKey, recoveryAPIKey)
	}
	if err != nil {
		return err
	}

	address := os.Getenv("TRUSTED_POOL_HTTP_ADDR")
	if address == "" {
		address = ":8092"
	}
	server := &http.Server{
		Addr: address, Handler: appRuntime.WithReadiness(api.Handler(), readiness), ReadHeaderTimeout: 5 * time.Second,
		ReadTimeout: 15 * time.Second, WriteTimeout: 30 * time.Second, IdleTimeout: 60 * time.Second,
	}
	signalContext, stop := signal.NotifyContext(context.Background(), os.Interrupt, syscall.SIGTERM)
	defer stop()
	serviceContext, cancelService := context.WithCancel(signalContext)
	defer cancelService()
	recoveryWorker, err := application.NewPersistentRecoveryWorker(coordinator)
	if err != nil {
		return err
	}
	recoveryLoop, err := appRuntime.NewPersistentRecoveryLoop(recoveryWorker, runtimeConfig.RecoveryIdleBackoff)
	if err != nil {
		return err
	}
	runtimeWorkers := []appRuntime.Worker{recoveryLoop}
	if recoveryManager != nil {
		finalizationLoop, loopErr := appRuntime.NewRecoveryFinalizationLoop(recoveryManager,
			runtimeConfig.RecoveryIdleBackoff)
		if loopErr != nil {
			return loopErr
		}
		runtimeWorkers = append(runtimeWorkers, finalizationLoop)
	}
	workers, err := appRuntime.NewWorkerGroup(runtimeWorkers...)
	if err != nil {
		return err
	}
	if err := workers.Start(serviceContext); err != nil {
		return err
	}
	workerFailure := make(chan error, 1)
	go func() {
		select {
		case workerErr := <-workers.Errors():
			log.Printf("runtime worker failed: %v", workerErr)
			workerFailure <- workerErr
			cancelService()
		case <-serviceContext.Done():
		}
	}()
	go func() {
		<-serviceContext.Done()
		ctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
		defer cancel()
		_ = server.Shutdown(ctx)
		_ = workers.Stop(ctx)
	}()
	log.Printf("trusted pool backend listening on %s", address)
	err = server.ListenAndServe()
	cancelService()
	workerStopContext, cancelWorkerStop := context.WithTimeout(context.Background(), 10*time.Second)
	defer cancelWorkerStop()
	if stopErr := workers.Stop(workerStopContext); stopErr != nil {
		return stopErr
	}
	select {
	case workerErr := <-workerFailure:
		return workerErr
	default:
	}
	if errors.Is(err, http.ErrServerClosed) {
		return nil
	}
	return err
}

func validateIndependentBatchClient(batchID string, otherIDs ...string) error {
	batchID = strings.TrimSpace(batchID)
	if batchID == "" {
		return errors.New("credential batch client id must not be empty")
	}
	for _, otherID := range otherIDs {
		if batchID == strings.TrimSpace(otherID) {
			return errors.New("credential batch client id must use an independent idempotency namespace")
		}
	}
	return nil
}

func validateIndependentRecoveryClient(recoveryID string, otherIDs ...string) error {
	recoveryID = strings.TrimSpace(recoveryID)
	if recoveryID == "" {
		return errors.New("recovery governance client id must not be empty")
	}
	for _, otherID := range otherIDs {
		if recoveryID == strings.TrimSpace(otherID) {
			return errors.New("recovery governance client id must use an independent idempotency namespace")
		}
	}
	return nil
}

func validateIndependentEvidenceExportClient(exportID string, otherIDs ...string) error {
	exportID = strings.TrimSpace(exportID)
	if exportID == "" {
		return errors.New("recovery evidence export client id must not be empty")
	}
	for _, otherID := range otherIDs {
		if exportID == strings.TrimSpace(otherID) {
			return errors.New("recovery evidence export client id must use an independent idempotency namespace")
		}
	}
	return nil
}

func validateIndependentRecoveryRotationCredentials(rotationID, rotationSecret string,
	otherIDs, otherSecrets []string) error {
	rotationID = strings.TrimSpace(rotationID)
	if rotationID == "" || strings.TrimSpace(rotationSecret) == "" || len(otherIDs) != len(otherSecrets) {
		return errors.New("Sub2API recovery rotation credentials are invalid")
	}
	for index := range otherIDs {
		if rotationID == strings.TrimSpace(otherIDs[index]) {
			return errors.New("Sub2API recovery rotation client id must be independently scoped")
		}
		if rotationSecret == otherSecrets[index] {
			return errors.New("Sub2API recovery rotation secret must be independent")
		}
	}
	return nil
}

func decodeEd25519PublicKey(value string) (ed25519.PublicKey, error) {
	decoded, err := base64.StdEncoding.DecodeString(strings.TrimSpace(value))
	if err != nil || len(decoded) != ed25519.PublicKeySize {
		return nil, errors.New("SUB2API_RECOVERY_ROTATION_ATTESTATION_PUBLIC_KEY_BASE64 must encode an Ed25519 public key")
	}
	return ed25519.PublicKey(decoded), nil
}

func validateSub2APITransport(runtimeMode, rawURL string) error {
	parsed, err := url.Parse(strings.TrimSpace(rawURL))
	if err != nil || parsed.Scheme == "" || parsed.Host == "" {
		return errors.New("SUB2API_BASE_URL is invalid")
	}
	if runtimeMode == appRuntime.ModeProduction && !strings.EqualFold(parsed.Scheme, "https") {
		return errors.New("production mode requires an HTTPS SUB2API_BASE_URL")
	}
	return nil
}

func validateIndependentSettlementCredentials(controlID, controlSecret, readID, readSecret, resolveID, resolveSecret string) error {
	controlID, readID, resolveID = strings.TrimSpace(controlID), strings.TrimSpace(readID), strings.TrimSpace(resolveID)
	if controlID == "" || readID == "" || resolveID == "" {
		return errors.New("Sub2API client ids must not be empty")
	}
	ids := map[string]struct{}{controlID: {}}
	if _, exists := ids[readID]; exists {
		return errors.New("Sub2API settlement read client id must differ from the control client id")
	}
	ids[readID] = struct{}{}
	if _, exists := ids[resolveID]; exists {
		return errors.New("Sub2API settlement resolve client id must be independently scoped")
	}
	secrets := map[string]struct{}{controlSecret: {}}
	if _, exists := secrets[readSecret]; exists {
		return errors.New("Sub2API settlement read secret must differ from the control secret")
	}
	secrets[readSecret] = struct{}{}
	if _, exists := secrets[resolveSecret]; exists {
		return errors.New("Sub2API settlement resolve secret must be independently scoped")
	}
	return nil
}

func requiredSecret(name string, minimumLength int) (string, error) {
	value := os.Getenv(name)
	if len(value) < minimumLength {
		return "", errors.New(name + " is required and too short")
	}
	return value, nil
}
