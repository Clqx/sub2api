package domain

import (
	"errors"
	"strings"
	"testing"
	"time"
)

func TestSeatRejectsIdentifierOutsidePublishedLimit(t *testing.T) {
	if _, err := NewSeat(strings.Repeat("s", 129), "pool-1", "owner-1", time.Now()); err == nil {
		t.Fatal("accepted a seat id that Phase 2 cannot persist")
	}
}

func TestSeatRequiresFreezeBeforeEveryMemberChange(t *testing.T) {
	now := time.Date(2026, 8, 16, 10, 0, 0, 0, time.UTC)
	seat, err := NewSeat("seat-1", "pool-1", "owner-1", now)
	if err != nil {
		t.Fatal(err)
	}

	for name, change := range map[string]func() error{
		"temporary": func() error { return seat.StartTemporaryAssignment("op-temp", "temp-1", now) },
		"restore":   func() error { return seat.StartRestore("op-restore", now) },
		"replace":   func() error { return seat.StartPermanentReplacement("op-replace", "owner-2", "attestation-1", now) },
	} {
		t.Run(name, func(t *testing.T) {
			if err := change(); !errors.Is(err, ErrFreezeRequired) {
				t.Fatalf("expected freeze requirement, got %v", err)
			}
		})
	}
}

func TestTemporaryAssignmentThenRestoreRequiresAnotherFreeze(t *testing.T) {
	now := time.Date(2026, 8, 16, 10, 0, 0, 0, time.UTC)
	seat, _ := NewSeat("seat-1", "pool-1", "owner-1", now)
	mustFreeze(t, seat, "freeze-1", now)
	if err := seat.StartTemporaryAssignment("assign-temp", "temp-1", now); err != nil {
		t.Fatal(err)
	}
	if err := seat.CompleteAssignment("assign-temp", true, "", now); err != nil {
		t.Fatal(err)
	}
	if seat.Current.Kind != AssignmentTemporary || seat.Current.UserID != "temp-1" {
		t.Fatalf("unexpected assignment: %+v", seat.Current)
	}
	if err := seat.StartRestore("restore", now); !errors.Is(err, ErrFreezeRequired) {
		t.Fatalf("restore bypassed freeze: %v", err)
	}

	mustFreeze(t, seat, "freeze-2", now)
	if err := seat.StartRestore("restore", now); err != nil {
		t.Fatal(err)
	}
	if err := seat.CompleteAssignment("restore", true, "", now); err != nil {
		t.Fatal(err)
	}
	if seat.Current.UserID != "owner-1" || seat.Current.Kind != AssignmentOwner {
		t.Fatalf("owner was not restored: %+v", seat.Current)
	}
}

func TestPermanentReplacementRequiresCredentialRotation(t *testing.T) {
	now := time.Date(2026, 8, 16, 10, 0, 0, 0, time.UTC)
	seat, _ := NewSeat("seat-1", "pool-1", "owner-1", now)
	mustFreeze(t, seat, "freeze-1", now)
	if err := seat.StartPermanentReplacement("replace", "owner-2", "attestation-1", now); err != nil {
		t.Fatal(err)
	}
	if err := seat.CompleteAssignment("replace", false, "attestation-1", now); err == nil {
		t.Fatal("replacement completed without access credential rotation")
	}
	if err := seat.CompleteAssignment("replace", true, "wrong-attestation", now); err == nil {
		t.Fatal("replacement completed with mismatched provider control credential evidence")
	}
	if err := seat.CompleteAssignment("replace", true, "attestation-1", now); err != nil {
		t.Fatal(err)
	}
	if seat.OwnerUserID != "owner-2" || seat.MembershipEpoch != 2 || seat.AssignmentEpoch != 2 {
		t.Fatalf("unexpected replacement result: %+v", seat)
	}
}

func TestUnknownSuspendOutcomeCannotReactivateSeat(t *testing.T) {
	now := time.Date(2026, 8, 16, 10, 0, 0, 0, time.UTC)
	seat, _ := NewSeat("seat-1", "pool-1", "owner-1", now)
	if err := seat.StartSuspend("freeze-1", now); err != nil {
		t.Fatal(err)
	}
	if seat.State != SeatSuspendPending {
		t.Fatalf("unexpected state %s", seat.State)
	}
	if err := seat.CompleteSuspend(FreezeSnapshot{
		OperationID:     "freeze-1",
		AssignmentEpoch: seat.AssignmentEpoch,
		InFlight:        1,
	}, now); err == nil {
		t.Fatal("completed freeze while a request was still in flight")
	}
	if seat.State != SeatSuspendPending {
		t.Fatalf("unknown outcome must remain pending, got %s", seat.State)
	}
}

func TestPendingSettlementCannotCompleteSuspend(t *testing.T) {
	now := time.Date(2026, 8, 16, 10, 0, 0, 0, time.UTC)
	seat, _ := NewSeat("seat-1", "pool-1", "owner-1", now)
	if err := seat.StartSuspend("freeze-1", now); err != nil {
		t.Fatal(err)
	}
	err := seat.CompleteSuspend(FreezeSnapshot{
		OperationID:        "freeze-1",
		AssignmentEpoch:    seat.AssignmentEpoch,
		Usage:              map[string]float64{"daily": 12.5},
		WindowStarts:       map[string]*time.Time{"daily": testTime(now.Add(-time.Hour))},
		PendingSettlements: 1,
		CapturedAt:         now,
	}, now)
	if err == nil {
		t.Fatal("pending settlement 未清零时完成了冻结")
	}
	if seat.State != SeatSuspendPending {
		t.Fatalf("结算屏障未清零时必须保持暂停待确认，实际状态 %s", seat.State)
	}
}

func mustFreeze(t *testing.T, seat *Seat, operationID string, now time.Time) {
	t.Helper()
	if err := seat.StartSuspend(operationID, now); err != nil {
		t.Fatal(err)
	}
	if err := seat.CompleteSuspend(FreezeSnapshot{
		OperationID:     operationID,
		AssignmentEpoch: seat.AssignmentEpoch,
		Usage:           map[string]float64{"daily": 12.5},
		WindowStarts:    map[string]*time.Time{"daily": testTime(now.Add(-time.Hour))},
		CapturedAt:      now,
	}, now); err != nil {
		t.Fatal(err)
	}
}

func testTime(value time.Time) *time.Time { return &value }
