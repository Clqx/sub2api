package offline

import (
	"bytes"
	"encoding/hex"
	"encoding/json"
	"errors"
	"io"
	"strings"
	"unicode/utf8"

	"github.com/gowebpki/jcs"
)

type validationError struct {
	code ReasonCode
}

func (e *validationError) Error() string { return string(e.code) }

func fail(code ReasonCode) error { return &validationError{code: code} }

func reasonOf(err error, fallback ReasonCode) ReasonCode {
	var target *validationError
	if errors.As(err, &target) {
		return target.code
	}
	return fallback
}

func ParseBundle(data []byte, limits Limits) (*Bundle, error) {
	limits = normalizedLimits(limits)
	var bundle Bundle
	if err := decodeStrictCanonical(data, limits.MaxBundleBytes, &bundle); err != nil {
		return nil, err
	}
	return &bundle, nil
}

func ParseTrustPolicy(data []byte, limits Limits) (*TrustPolicy, error) {
	limits = normalizedLimits(limits)
	var policy TrustPolicy
	if err := decodeStrictCanonical(data, limits.MaxPolicyBytes, &policy); err != nil {
		return nil, err
	}
	return &policy, nil
}

func ParseRevealIntent(data []byte, limits Limits) (*RevealIntent, error) {
	limits = normalizedLimits(limits)
	var intent RevealIntent
	if err := decodeStrictCanonical(data, limits.MaxIntentBytes, &intent); err != nil {
		return nil, err
	}
	return &intent, nil
}

func ParseRevealApprovals(data []byte, limits Limits) (*RevealApprovalsDocument, error) {
	limits = normalizedLimits(limits)
	var approvals RevealApprovalsDocument
	if err := decodeStrictCanonical(data, limits.MaxApprovalsBytes, &approvals); err != nil {
		return nil, err
	}
	return &approvals, nil
}

func MarshalCanonicalBundle(bundle Bundle) ([]byte, error) {
	return marshalCanonical(bundle)
}

func MarshalCanonicalTrustPolicy(policy TrustPolicy) ([]byte, error) {
	return marshalCanonical(policy)
}

func MarshalCanonicalRevealIntent(intent RevealIntent) ([]byte, error) {
	return marshalCanonical(intent)
}

func MarshalCanonicalRevealApprovals(approvals RevealApprovalsDocument) ([]byte, error) {
	return marshalCanonical(approvals)
}

func MarshalCanonicalReport(report Report) ([]byte, error) {
	return marshalCanonical(report)
}

func MarshalCanonicalRevealReport(report RevealReport) ([]byte, error) {
	return marshalCanonical(report)
}

func marshalCanonical(value any) ([]byte, error) {
	raw, err := json.Marshal(value)
	if err != nil {
		return nil, fail(ReasonSchemaInvalid)
	}
	canonical, err := jcs.Transform(raw)
	if err != nil || len(canonical) == 0 {
		return nil, fail(ReasonInvalidJSON)
	}
	return canonical, nil
}

// decodeStrictCanonical 先由成熟 JCS 实现完成完整语法、重复键和尾随值检查，
// 再用 DisallowUnknownFields 固定协议表面；任何宽松解析都不能进入验签路径。
func decodeStrictCanonical(data []byte, maximum int64, target any) error {
	if maximum <= 0 || int64(len(data)) > maximum {
		return fail(ReasonInputTooLarge)
	}
	if len(data) == 0 {
		return fail(ReasonInvalidJSON)
	}
	if !utf8.Valid(data) {
		return fail(ReasonInvalidUTF8)
	}
	canonical, err := jcs.Transform(data)
	if err != nil {
		return fail(ReasonInvalidJSON)
	}
	if !bytes.Equal(data, canonical) {
		return fail(ReasonNonCanonicalJSON)
	}
	if data[0] != '{' {
		return fail(ReasonSchemaInvalid)
	}
	decoder := json.NewDecoder(bytes.NewReader(data))
	decoder.DisallowUnknownFields()
	if err := decoder.Decode(target); err != nil {
		return fail(ReasonSchemaInvalid)
	}
	var trailing any
	if err := decoder.Decode(&trailing); !errors.Is(err, io.EOF) {
		return fail(ReasonInvalidJSON)
	}
	return nil
}

func normalizedLimits(value Limits) Limits {
	defaults := DefaultLimits()
	if value.MaxBundleBytes <= 0 {
		value.MaxBundleBytes = defaults.MaxBundleBytes
	}
	if value.MaxPolicyBytes <= 0 {
		value.MaxPolicyBytes = defaults.MaxPolicyBytes
	}
	if value.MaxIntentBytes <= 0 {
		value.MaxIntentBytes = defaults.MaxIntentBytes
	}
	if value.MaxApprovalsBytes <= 0 {
		value.MaxApprovalsBytes = defaults.MaxApprovalsBytes
	}
	if value.MaxManifestBytes <= 0 {
		value.MaxManifestBytes = defaults.MaxManifestBytes
	}
	if value.MaxManifests <= 0 {
		value.MaxManifests = defaults.MaxManifests
	}
	if value.MaxMembers <= 0 {
		value.MaxMembers = defaults.MaxMembers
	}
	if value.MaxEvidenceBytes <= 0 {
		value.MaxEvidenceBytes = defaults.MaxEvidenceBytes
	}
	return value
}

func validID(value string) bool {
	return value != "" && value == strings.TrimSpace(value) && len(value) <= 512
}

func validProfileID(value string) bool {
	if value == "" || len(value) > 128 {
		return false
	}
	for index := range len(value) {
		character := value[index]
		if (character >= 'a' && character <= 'z') || (character >= 'A' && character <= 'Z') ||
			(character >= '0' && character <= '9') || (index > 0 && strings.ContainsRune("._:/-", rune(character))) {
			continue
		}
		return false
	}
	return true
}

func validHash(value string) bool {
	if len(value) != 64 || value != strings.ToLower(value) {
		return false
	}
	decoded, err := hex.DecodeString(value)
	if err != nil {
		return false
	}
	var combined byte
	for _, item := range decoded {
		combined |= item
	}
	return combined != 0
}
