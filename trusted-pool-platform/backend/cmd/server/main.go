package main

import (
	"context"
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
	connectContext, cancelConnect := context.WithTimeout(context.Background(), 10*time.Second)
	db, err := postgres.OpenDB(connectContext, runtimeConfig.Database)
	cancelConnect()
	if err != nil {
		return err
	}
	defer db.Close()
	migrationContext, cancelMigration := context.WithTimeout(context.Background(), runtimeConfig.MigrationLimit)
	err = postgres.Migrate(migrationContext, db, os.DirFS(runtimeConfig.MigrationsDir))
	cancelMigration()
	if err != nil {
		return err
	}
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
	readiness, err := appRuntime.NewReadiness(2*time.Second,
		postgres.DBProbe{DB: db}, appRuntime.EnvelopeProbe{Cipher: cryptoRuntime.Cipher},
		appRuntime.BatchProbe{Manager: credentialBatchManager})
	if err != nil {
		return err
	}
	api, err := httpapi.NewServer(coordinator, riskAggregator, credentialBatchManager,
		apiKey, settlementAPIKey, batchAPIKey)
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
	workers, err := appRuntime.NewWorkerGroup(recoveryLoop)
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
