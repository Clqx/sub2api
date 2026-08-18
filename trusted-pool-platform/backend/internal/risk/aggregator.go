package risk

import (
	"crypto/hmac"
	"crypto/sha256"
	"encoding/hex"
	"errors"
	"sort"
	"strings"
	"sync"
	"time"
)

type Level string

const (
	LevelNormal  Level = "NORMAL"
	LevelWatch   Level = "WATCH"
	LevelLimited Level = "LIMITED"
	LevelSuspend Level = "SUSPEND"
)

type Policy struct {
	Window              time.Duration
	Retention           time.Duration
	FutureSkew          time.Duration
	WatchFingerprints   int
	LimitedFingerprints int
	SuspendFingerprints int
	WatchConcurrency    int
	LimitedConcurrency  int
	SuspendConcurrency  int
}

func DefaultPolicy() Policy {
	return Policy{
		Window:              5 * time.Minute,
		Retention:           24 * time.Hour,
		FutureSkew:          2 * time.Minute,
		WatchFingerprints:   2,
		LimitedFingerprints: 4,
		SuspendFingerprints: 8,
		WatchConcurrency:    2,
		LimitedConcurrency:  4,
		SuspendConcurrency:  8,
	}
}

type Observation struct {
	ID              string
	SeatID          string
	AssignmentEpoch uint64
	Fingerprint     string
	Concurrency     int
	Requests        int
	ObservedAt      time.Time
}

type Summary struct {
	SeatID           string    `json:"seat_id"`
	AssignmentEpoch  uint64    `json:"assignment_epoch"`
	WindowStart      time.Time `json:"window_start"`
	WindowEnd        time.Time `json:"window_end"`
	RequestCount     int       `json:"request_count"`
	PeakConcurrency  int       `json:"peak_concurrency"`
	FingerprintCount int       `json:"fingerprint_count"`
	Level            Level     `json:"level"`
}

type windowKey struct {
	seatID string
	epoch  uint64
	start  int64
}

type window struct {
	Summary
	fingerprints map[string]struct{}
}

type Aggregator struct {
	mu      sync.Mutex
	policy  Policy
	key     []byte
	seen    map[string]time.Time
	windows map[windowKey]*window
}

func NewAggregator(hmacKey []byte, policy Policy) (*Aggregator, error) {
	if len(hmacKey) < 32 {
		return nil, errors.New("fingerprint HMAC key must contain at least 32 bytes")
	}
	if policy.Window <= 0 {
		return nil, errors.New("risk window must be positive")
	}
	if policy.Retention < policy.Window || policy.FutureSkew < 0 {
		return nil, errors.New("risk retention must cover one window and future skew cannot be negative")
	}
	return &Aggregator{
		policy:  policy,
		key:     append([]byte(nil), hmacKey...),
		seen:    make(map[string]time.Time),
		windows: make(map[windowKey]*window),
	}, nil
}

func (a *Aggregator) Record(observation Observation) (Summary, error) {
	observation.ID = strings.TrimSpace(observation.ID)
	observation.SeatID = strings.TrimSpace(observation.SeatID)
	if len(observation.ID) == 0 || len(observation.ID) > 128 || len(observation.SeatID) == 0 || len(observation.SeatID) > 128 || observation.AssignmentEpoch == 0 || observation.Fingerprint == "" {
		return Summary{}, errors.New("observation id, seat id, assignment epoch and fingerprint are required")
	}
	if observation.Concurrency < 0 || observation.Requests < 0 {
		return Summary{}, errors.New("concurrency and request count cannot be negative")
	}
	now := time.Now().UTC()
	observedAt := observation.ObservedAt.UTC()
	if observedAt.IsZero() || observedAt.Before(now.Add(-a.policy.Retention)) || observedAt.After(now.Add(a.policy.FutureSkew)) {
		return Summary{}, errors.New("observation time is outside the accepted risk retention window")
	}
	start := observedAt.Truncate(a.policy.Window)
	key := windowKey{seatID: observation.SeatID, epoch: observation.AssignmentEpoch, start: start.UnixNano()}

	a.mu.Lock()
	defer a.mu.Unlock()
	a.cleanupLocked(now)
	if _, duplicated := a.seen[observation.ID]; duplicated {
		return a.summaryLocked(key), nil
	}
	a.seen[observation.ID] = observedAt
	current := a.windows[key]
	if current == nil {
		current = &window{
			Summary: Summary{
				SeatID: observation.SeatID, AssignmentEpoch: observation.AssignmentEpoch,
				WindowStart: start, WindowEnd: start.Add(a.policy.Window), Level: LevelNormal,
			},
			fingerprints: make(map[string]struct{}),
		}
		a.windows[key] = current
	}
	current.RequestCount += observation.Requests
	if observation.Concurrency > current.PeakConcurrency {
		current.PeakConcurrency = observation.Concurrency
	}
	// 原始设备指纹不得写入内存聚合结构或持久层，只保留带密钥的不可逆摘要。
	current.fingerprints[a.digest(observation.Fingerprint)] = struct{}{}
	current.FingerprintCount = len(current.fingerprints)
	current.Level = a.level(*current)
	return current.Summary, nil
}

func (a *Aggregator) Summaries(seatID string, assignmentEpoch uint64) []Summary {
	a.mu.Lock()
	defer a.mu.Unlock()
	a.cleanupLocked(time.Now().UTC())
	result := make([]Summary, 0)
	for key, value := range a.windows {
		if key.seatID == seatID && key.epoch == assignmentEpoch {
			result = append(result, value.Summary)
		}
	}
	sort.Slice(result, func(i, j int) bool { return result[i].WindowStart.Before(result[j].WindowStart) })
	return result
}

func (a *Aggregator) cleanupLocked(now time.Time) {
	cutoff := now.Add(-a.policy.Retention)
	for id, observedAt := range a.seen {
		if observedAt.Before(cutoff) {
			delete(a.seen, id)
		}
	}
	for key, value := range a.windows {
		if value.WindowEnd.Before(cutoff) {
			delete(a.windows, key)
		}
	}
}

func (a *Aggregator) summaryLocked(key windowKey) Summary {
	if current := a.windows[key]; current != nil {
		return current.Summary
	}
	return Summary{}
}

func (a *Aggregator) digest(raw string) string {
	mac := hmac.New(sha256.New, a.key)
	_, _ = mac.Write([]byte(raw))
	return hex.EncodeToString(mac.Sum(nil))
}

func (a *Aggregator) level(current window) Level {
	fingerprints := len(current.fingerprints)
	concurrency := current.PeakConcurrency
	switch {
	case fingerprints >= a.policy.SuspendFingerprints || concurrency >= a.policy.SuspendConcurrency:
		return LevelSuspend
	case fingerprints >= a.policy.LimitedFingerprints || concurrency >= a.policy.LimitedConcurrency:
		return LevelLimited
	case fingerprints >= a.policy.WatchFingerprints || concurrency >= a.policy.WatchConcurrency:
		return LevelWatch
	default:
		return LevelNormal
	}
}
