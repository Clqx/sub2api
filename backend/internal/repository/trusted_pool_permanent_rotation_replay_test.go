//go:build unit

package repository

import (
	"context"
	"errors"
	"strings"
	"testing"

	"github.com/Wei-Shaw/sub2api/internal/service"
	"github.com/stretchr/testify/require"
)

func TestPermanentCommitReceiptRejectsSupersededGeneration(t *testing.T) {
	input := service.CommitTrustedPoolPermanentRotationInput{
		ProtocolVersion: service.TrustedPoolPermanentRotationProtocolV1,
		OperationID:     "commit-op", PrepareOperationID: "prepare-op",
		ActivationOperationID: "activate-op", ActivationRequestHash: strings.Repeat("a", 64),
		ExternalPoolID: "pool-1", PlanID: "plan-1", CeremonyType: "ROTATE",
		FromEpoch: 7, ToEpoch: 8, PreparedSetHash: strings.Repeat("b", 64),
		RequestHash: strings.Repeat("c", 64), Seats: []service.ActivateTrustedPoolPermanentRotationSeat{{ExternalSeatID: "seat-1"}},
	}
	parent := permanentRotationParent{
		Status: "superseded", CommitOperationID: input.OperationID, CommitRequestHash: input.RequestHash,
	}

	result, found, err := tryLoadPermanentCommitReceipt(context.Background(), nil, parent, input)
	require.Nil(t, result)
	require.True(t, found)
	require.True(t, errors.Is(err, service.ErrTrustedPoolPermanentCommitReceiptUnavailable))
}
