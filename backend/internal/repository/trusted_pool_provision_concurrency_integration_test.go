//go:build integration

package repository

import (
	"context"
	"fmt"
	"strings"
	"testing"
	"time"

	"github.com/Wei-Shaw/sub2api/internal/service"
	"github.com/stretchr/testify/require"
)

func TestTrustedPoolProvisionReplayObservesClaimCommittedWhileWaitingForOperationLock(t *testing.T) {
	ctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
	defer cancel()

	suffix := fmt.Sprintf("%d", time.Now().UnixNano())
	clientID := "provision-race-client-" + suffix
	operationID := "provision-race-operation-" + suffix
	externalPoolID := "provision-race-pool-" + suffix
	externalSeatID := "provision-race-seat-" + suffix
	credential := "sk-provision-race-" + suffix
	fingerprint := trustedPoolCredentialFingerprint(credential)

	_, err := integrationDB.ExecContext(ctx, `
		INSERT INTO trusted_pool_integration_clients(client_id, external_pool_id, secret_hash, scopes)
		VALUES ($1,$2,$3,ARRAY['seat:provision','credential:ack'])
	`, clientID, externalPoolID, strings.Repeat("a", 64))
	require.NoError(t, err)

	group := mustCreateGroup(t, testEntClient(t), &service.Group{
		Name:             "provision-race-group-" + suffix,
		Platform:         service.PlatformAnthropic,
		RateMultiplier:   1,
		IsExclusive:      true,
		Status:           service.StatusActive,
		SubscriptionType: service.SubscriptionTypeSubscription,
	})

	input := service.ProvisionTrustedPoolSeatInput{
		ExternalPoolID:        externalPoolID,
		ExternalSeatID:        externalSeatID,
		ExistingGroupID:       group.ID,
		AssignmentEpoch:       1,
		OperationID:           operationID,
		PrincipalConcurrency:  1,
		SubscriptionExpiresAt: time.Now().Add(24 * time.Hour),
		APIKeyQuota:           10,
		ActorClientID:         clientID,
		RequestHash:           strings.Repeat("b", 64),
		Credential:            credential,
		CredentialFingerprint: fingerprint,
		PrincipalEmail:        "provision-race-" + suffix + "@principal.invalid",
	}
	repo := &trustedPoolRepository{db: integrationDB}
	created, err := repo.ProvisionSeat(ctx, input)
	require.NoError(t, err)
	require.Equal(t, credential, created.Credential)

	ackTx, err := integrationDB.BeginTx(ctx, nil)
	require.NoError(t, err)
	t.Cleanup(func() { _ = ackTx.Rollback() })
	var lockedSeatID int64
	err = ackTx.QueryRowContext(ctx, `
		SELECT seat_id
		FROM trusted_pool_provision_operations
		WHERE client_id=$1 AND operation_id=$2
		FOR UPDATE
	`, clientID, operationID).Scan(&lockedSeatID)
	require.NoError(t, err)
	require.Equal(t, created.Seat.ID, lockedSeatID)

	type replayOutcome struct {
		result *service.TrustedPoolProvisionResult
		err    error
	}
	replayDone := make(chan replayOutcome, 1)
	go func() {
		result, replayErr := repo.ProvisionSeat(ctx, input)
		replayDone <- replayOutcome{result: result, err: replayErr}
	}()

	// replay 必须在 Ack 持有 operation 锁期间等待，不能提前返回初始凭据。
	select {
	case outcome := <-replayDone:
		require.Failf(t, "provision replay returned before ack committed", "result=%v err=%v", outcome.result, outcome.err)
	case <-time.After(150 * time.Millisecond):
	}

	_, err = ackTx.ExecContext(ctx, `
		INSERT INTO trusted_pool_provision_credential_claims(
			client_id, provision_operation_id, seat_id, claim_operation_id, claimed_by, credential_fingerprint
		) VALUES ($1,$2,$3,$4,$5,$6)
	`, clientID, operationID, lockedSeatID, "claim-race-"+suffix, "integration-test", fingerprint)
	require.NoError(t, err)
	require.NoError(t, ackTx.Commit())

	select {
	case outcome := <-replayDone:
		require.Nil(t, outcome.result)
		require.ErrorIs(t, outcome.err, service.ErrTrustedPoolCredentialClaimed)
	case <-ctx.Done():
		require.Fail(t, "provision replay did not finish after ack committed", ctx.Err().Error())
	}
}
