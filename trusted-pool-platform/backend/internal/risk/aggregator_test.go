package risk

import (
	"strings"
	"testing"
	"time"
)

func TestAggregatorRejectsOversizedObservationID(t *testing.T) {
	aggregator, err := NewAggregator([]byte(strings.Repeat("k", 32)), DefaultPolicy())
	if err != nil {
		t.Fatal(err)
	}
	_, err = aggregator.Record(Observation{
		ID: strings.Repeat("o", 129), SeatID: "seat-1", AssignmentEpoch: 1,
		Fingerprint: "device", ObservedAt: time.Now().UTC(),
	})
	if err == nil {
		t.Fatal("accepted an observation id outside the API contract")
	}
}

func TestAggregatorUsesWindowsDeduplicatesAndRaisesRisk(t *testing.T) {
	key := []byte(strings.Repeat("k", 32))
	aggregator, err := NewAggregator(key, DefaultPolicy())
	if err != nil {
		t.Fatal(err)
	}
	now := time.Now().UTC()
	first, err := aggregator.Record(Observation{
		ID: "obs-1", SeatID: "seat-1", AssignmentEpoch: 3,
		Fingerprint: "raw-device-a", Concurrency: 1, Requests: 4, ObservedAt: now,
	})
	if err != nil || first.Level != LevelNormal || first.RequestCount != 4 {
		t.Fatalf("unexpected first summary: %+v err=%v", first, err)
	}
	duplicate, err := aggregator.Record(Observation{
		ID: "obs-1", SeatID: "seat-1", AssignmentEpoch: 3,
		Fingerprint: "raw-device-b", Concurrency: 9, Requests: 99, ObservedAt: now,
	})
	if err != nil || duplicate.RequestCount != 4 || duplicate.FingerprintCount != 1 {
		t.Fatalf("duplicate changed summary: %+v err=%v", duplicate, err)
	}
	second, err := aggregator.Record(Observation{
		ID: "obs-2", SeatID: "seat-1", AssignmentEpoch: 3,
		Fingerprint: "raw-device-b", Concurrency: 2, Requests: 3, ObservedAt: now,
	})
	if err != nil || second.Level != LevelWatch || second.FingerprintCount != 2 || second.RequestCount != 7 {
		t.Fatalf("risk was not raised: %+v err=%v", second, err)
	}
}

func TestAggregatorSeparatesAssignmentEpochs(t *testing.T) {
	aggregator, _ := NewAggregator([]byte(strings.Repeat("k", 32)), DefaultPolicy())
	now := time.Now().UTC()
	for epoch := uint64(1); epoch <= 2; epoch++ {
		_, err := aggregator.Record(Observation{
			ID: "obs-" + string(rune('0'+epoch)), SeatID: "seat-1", AssignmentEpoch: epoch,
			Fingerprint: "device", Requests: 1, ObservedAt: now,
		})
		if err != nil {
			t.Fatal(err)
		}
	}
	if got := len(aggregator.Summaries("seat-1", 1)); got != 1 {
		t.Fatalf("expected one epoch-1 window, got %d", got)
	}
	if got := len(aggregator.Summaries("seat-1", 2)); got != 1 {
		t.Fatalf("expected one epoch-2 window, got %d", got)
	}
}

func TestAggregatorRejectsWeakHMACKey(t *testing.T) {
	if _, err := NewAggregator([]byte("weak"), DefaultPolicy()); err == nil {
		t.Fatal("accepted weak HMAC key")
	}
}

func TestAggregatorRejectsOutOfRangeObservationTimeAndCleansExpiredState(t *testing.T) {
	policy := DefaultPolicy()
	policy.Retention = 10 * time.Minute
	aggregator, err := NewAggregator([]byte(strings.Repeat("k", 32)), policy)
	if err != nil {
		t.Fatal(err)
	}
	now := time.Now().UTC()
	base := Observation{ID: "obs-current", SeatID: "seat-1", AssignmentEpoch: 1, Fingerprint: "device", Requests: 1}
	base.ObservedAt = now.Add(-policy.Retention - time.Second)
	if _, err := aggregator.Record(base); err == nil {
		t.Fatal("accepted observation older than retention")
	}
	base.ID = "obs-future"
	base.ObservedAt = now.Add(policy.FutureSkew + time.Second)
	if _, err := aggregator.Record(base); err == nil {
		t.Fatal("accepted observation too far in the future")
	}
	base.ID = "obs-current"
	base.ObservedAt = now
	if _, err := aggregator.Record(base); err != nil {
		t.Fatal(err)
	}
	aggregator.mu.Lock()
	aggregator.cleanupLocked(now.Add(policy.Retention + policy.Window + time.Second))
	seen, windows := len(aggregator.seen), len(aggregator.windows)
	aggregator.mu.Unlock()
	if seen != 0 || windows != 0 {
		t.Fatalf("expired risk state was not cleaned: seen=%d windows=%d", seen, windows)
	}
}
