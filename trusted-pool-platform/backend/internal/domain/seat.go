package domain

import (
	"errors"
	"fmt"
	"math"
	"strings"
	"time"
)

var (
	ErrInvalidTransition = errors.New("invalid seat state transition")
	ErrFreezeRequired    = errors.New("seat must be frozen before changing members")
	ErrStaleSnapshot     = errors.New("freeze snapshot does not match the current assignment epoch")
	ErrInvalidSnapshot   = errors.New("freeze snapshot does not contain valid quota evidence")
)

type SeatState string

const (
	SeatActive             SeatState = "ACTIVE"
	SeatSuspendPending     SeatState = "SUSPEND_PENDING"
	SeatDraining           SeatState = "DRAINING"
	SeatFrozen             SeatState = "FROZEN"
	SeatAssignmentPending  SeatState = "ASSIGNMENT_PENDING"
	SeatReplacementPending SeatState = "REPLACEMENT_PENDING"
)

type AssignmentKind string

const (
	AssignmentOwner     AssignmentKind = "OWNER"
	AssignmentTemporary AssignmentKind = "TEMPORARY"
)

type Assignment struct {
	UserID          string         `json:"user_id"`
	Kind            AssignmentKind `json:"kind"`
	AssignmentEpoch uint64         `json:"assignment_epoch"`
	AssignedAt      time.Time      `json:"assigned_at"`
}

type FreezeSnapshot struct {
	OperationID        string                `json:"operation_id"`
	AssignmentEpoch    uint64                `json:"assignment_epoch"`
	Usage              map[string]float64    `json:"usage"`
	WindowStarts       map[string]*time.Time `json:"window_starts"`
	InFlight           int                   `json:"in_flight"`
	PendingSettlements int                   `json:"pending_settlements"`
	CapturedAt         time.Time             `json:"captured_at"`
}

type PendingChange struct {
	OperationID                string         `json:"operation_id"`
	TargetUser                 string         `json:"target_user_id"`
	Kind                       AssignmentKind `json:"kind"`
	Permanent                  bool           `json:"permanent"`
	ControlRotationEvidenceRef string         `json:"control_rotation_evidence_ref,omitempty"`
	StartedAt                  time.Time      `json:"started_at"`
}

type Seat struct {
	ID              string          `json:"id"`
	PoolID          string          `json:"pool_id"`
	State           SeatState       `json:"state"`
	OwnerUserID     string          `json:"owner_user_id"`
	Current         Assignment      `json:"current_assignment"`
	AssignmentEpoch uint64          `json:"assignment_epoch"`
	MembershipEpoch uint64          `json:"membership_epoch"`
	Freeze          *FreezeSnapshot `json:"freeze_snapshot,omitempty"`
	Pending         *PendingChange  `json:"pending_change,omitempty"`
	UpdatedAt       time.Time       `json:"updated_at"`
}

func NewSeat(id, poolID, ownerUserID string, now time.Time) (*Seat, error) {
	id, poolID, ownerUserID = strings.TrimSpace(id), strings.TrimSpace(poolID), strings.TrimSpace(ownerUserID)
	if !validIdentifier(id) || !validIdentifier(poolID) || !validIdentifier(ownerUserID) {
		return nil, errors.New("seat id, pool id and owner user id are required")
	}
	return &Seat{
		ID:              id,
		PoolID:          poolID,
		State:           SeatActive,
		OwnerUserID:     ownerUserID,
		AssignmentEpoch: 1,
		MembershipEpoch: 1,
		Current: Assignment{
			UserID:          ownerUserID,
			Kind:            AssignmentOwner,
			AssignmentEpoch: 1,
			AssignedAt:      now.UTC(),
		},
		UpdatedAt: now.UTC(),
	}, nil
}

func (s *Seat) StartSuspend(operationID string, now time.Time) error {
	operationID = strings.TrimSpace(operationID)
	if !validIdentifier(operationID) {
		return errors.New("operation id is required")
	}
	if s.State != SeatActive {
		return transitionError(s.State, SeatSuspendPending)
	}
	s.State = SeatSuspendPending
	s.Pending = &PendingChange{OperationID: operationID, StartedAt: now.UTC()}
	s.UpdatedAt = now.UTC()
	return nil
}

func (s *Seat) CompleteSuspend(snapshot FreezeSnapshot, now time.Time) error {
	if (s.State != SeatSuspendPending && s.State != SeatDraining) || s.Pending == nil {
		return transitionError(s.State, SeatFrozen)
	}
	if snapshot.OperationID != s.Pending.OperationID || snapshot.AssignmentEpoch != s.AssignmentEpoch {
		return ErrStaleSnapshot
	}
	if snapshot.InFlight != 0 || snapshot.PendingSettlements != 0 {
		return fmt.Errorf("%w: freeze snapshot retained in-flight=%d pending-settlements=%d",
			ErrInvalidTransition, snapshot.InFlight, snapshot.PendingSettlements)
	}
	if err := validateFreezeSnapshot(snapshot); err != nil {
		return err
	}
	snapshot.CapturedAt = snapshot.CapturedAt.UTC()
	s.State = SeatFrozen
	s.Freeze = &snapshot
	s.Pending = nil
	s.UpdatedAt = now.UTC()
	return nil
}

func (s *Seat) MarkDraining(operationID string, now time.Time) error {
	if s.State != SeatSuspendPending || s.Pending == nil || s.Pending.OperationID != operationID {
		return transitionError(s.State, SeatDraining)
	}
	s.State = SeatDraining
	s.UpdatedAt = now.UTC()
	return nil
}

// MarkSuspendRejected 只用于上游明确确认“冻结未执行”的情况。
// 网络超时等结果未知场景必须保留 SUSPEND_PENDING，交给对账流程确认。
func (s *Seat) MarkSuspendRejected(operationID string, now time.Time) error {
	if s.State != SeatSuspendPending || s.Pending == nil || s.Pending.OperationID != operationID {
		return transitionError(s.State, SeatActive)
	}
	s.State = SeatActive
	s.Pending = nil
	s.UpdatedAt = now.UTC()
	return nil
}

func (s *Seat) StartTemporaryAssignment(operationID, userID string, now time.Time) error {
	return s.startAssignment(operationID, userID, AssignmentTemporary, false, "", now)
}

func (s *Seat) StartRestore(operationID string, now time.Time) error {
	return s.startAssignment(operationID, s.OwnerUserID, AssignmentOwner, false, "", now)
}

func (s *Seat) StartPermanentReplacement(operationID, userID, controlRotationEvidenceRef string, now time.Time) error {
	if userID == s.OwnerUserID {
		return errors.New("replacement user must differ from the current owner")
	}
	if strings.TrimSpace(controlRotationEvidenceRef) == "" {
		return errors.New("permanent replacement requires provider control credential rotation evidence")
	}
	return s.startAssignment(operationID, userID, AssignmentOwner, true, controlRotationEvidenceRef, now)
}

func (s *Seat) startAssignment(operationID, userID string, kind AssignmentKind, permanent bool, controlRotationEvidenceRef string, now time.Time) error {
	if s.State != SeatFrozen || s.Freeze == nil {
		return ErrFreezeRequired
	}
	if s.Freeze.AssignmentEpoch != s.AssignmentEpoch {
		return ErrStaleSnapshot
	}
	operationID, userID = strings.TrimSpace(operationID), strings.TrimSpace(userID)
	if !validIdentifier(operationID) || !validIdentifier(userID) {
		return errors.New("operation id and target user are required")
	}
	if userID == s.Current.UserID && !permanent {
		return errors.New("target user is already assigned")
	}
	if permanent {
		s.State = SeatReplacementPending
	} else {
		s.State = SeatAssignmentPending
	}
	s.Pending = &PendingChange{
		OperationID:                operationID,
		TargetUser:                 userID,
		Kind:                       kind,
		Permanent:                  permanent,
		ControlRotationEvidenceRef: strings.TrimSpace(controlRotationEvidenceRef),
		StartedAt:                  now.UTC(),
	}
	s.UpdatedAt = now.UTC()
	return nil
}

func (s *Seat) CompleteAssignment(operationID string, accessCredentialRotationComplete bool, controlRotationEvidenceRef string, now time.Time) error {
	if (s.State != SeatAssignmentPending && s.State != SeatReplacementPending) || s.Pending == nil {
		return transitionError(s.State, SeatActive)
	}
	if s.Pending.OperationID != operationID {
		return errors.New("operation id does not match pending assignment")
	}
	if !accessCredentialRotationComplete {
		return errors.New("member assignment requires access credential rotation")
	}
	if s.Pending.Permanent && (strings.TrimSpace(controlRotationEvidenceRef) == "" || strings.TrimSpace(controlRotationEvidenceRef) != s.Pending.ControlRotationEvidenceRef) {
		return errors.New("permanent replacement requires matching provider control credential rotation evidence")
	}
	s.AssignmentEpoch++
	if s.Pending.Permanent {
		s.MembershipEpoch++
		s.OwnerUserID = s.Pending.TargetUser
	}
	s.Current = Assignment{
		UserID:          s.Pending.TargetUser,
		Kind:            s.Pending.Kind,
		AssignmentEpoch: s.AssignmentEpoch,
		AssignedAt:      now.UTC(),
	}
	s.State = SeatActive
	s.Freeze = nil
	s.Pending = nil
	s.UpdatedAt = now.UTC()
	return nil
}

func validateFreezeSnapshot(snapshot FreezeSnapshot) error {
	if snapshot.CapturedAt.IsZero() || len(snapshot.Usage) == 0 || len(snapshot.WindowStarts) == 0 || len(snapshot.Usage) != len(snapshot.WindowStarts) {
		return ErrInvalidSnapshot
	}
	for name, usage := range snapshot.Usage {
		if strings.TrimSpace(name) == "" || math.IsNaN(usage) || math.IsInf(usage, 0) || usage < 0 {
			return ErrInvalidSnapshot
		}
	}
	for name := range snapshot.WindowStarts {
		// 零时间明确表示该原生额度窗口尚未启动；键缺失才表示快照不完整。
		if _, ok := snapshot.Usage[name]; strings.TrimSpace(name) == "" || !ok {
			return ErrInvalidSnapshot
		}
	}
	return nil
}

// MarkAssignmentRejected 仅在上游明确拒绝且确认未产生任何变更时回退到冻结态。
// 结果未知时保留 pending 状态，避免成员在对账完成前重新获得使用权限。
func (s *Seat) MarkAssignmentRejected(operationID string, now time.Time) error {
	if (s.State != SeatAssignmentPending && s.State != SeatReplacementPending) || s.Pending == nil || s.Pending.OperationID != operationID {
		return transitionError(s.State, SeatFrozen)
	}
	s.State = SeatFrozen
	s.Pending = nil
	s.UpdatedAt = now.UTC()
	return nil
}

func transitionError(from, to SeatState) error {
	return fmt.Errorf("%w: %s -> %s", ErrInvalidTransition, from, to)
}

func validIdentifier(value string) bool {
	return len(value) > 0 && len(value) <= 128
}
