package offline

import (
	"crypto/sha256"

	"trusted-pool-platform/backend/internal/recovery"
)

func BuildPlatformManifestSignatureMessage(canonicalManifest []byte) ([]byte, error) {
	if len(canonicalManifest) == 0 {
		return nil, fail(ReasonManifestInvalid)
	}
	message, err := recovery.BuildPlatformManifestSignatureMessageV2(canonicalManifest)
	if err != nil {
		return nil, fail(ReasonManifestInvalid)
	}
	return message, nil
}

func BuildProviderProofMessage(statement ProviderStatement) ([]byte, error) {
	if err := validateProviderStatementShape(statement); err != nil {
		return nil, err
	}
	canonical, err := marshalCanonical(statement)
	if err != nil {
		return nil, err
	}
	return domainMessage(ProviderSignatureDomainV1, canonical), nil
}

func BuildRevealApprovalMessage(intent RevealIntent) ([]byte, error) {
	if err := validateRevealIntentShape(intent); err != nil {
		return nil, err
	}
	canonical, err := MarshalCanonicalRevealIntent(intent)
	if err != nil {
		return nil, err
	}
	return domainMessage(RevealApprovalDomainV1, canonical), nil
}

func BuildVerificationExportSignatureMessage(statement VerificationExportStatement) ([]byte, error) {
	if statement.ProtocolVersion != BundleProtocolVersion || !validID(statement.ExportID) ||
		statement.FormatVersion != BundleProtocolVersion || !validHash(statement.InventoryDigest) ||
		!validHash(statement.BundleDigest) {
		return nil, fail(ReasonSchemaInvalid)
	}
	if _, err := parseCanonicalTime(statement.GeneratedAt); err != nil {
		return nil, err
	}
	canonical, err := marshalCanonical(statement)
	if err != nil {
		return nil, err
	}
	return domainMessage(VerificationExportDomainV1, canonical), nil
}

func domainMessage(domain string, payload []byte) []byte {
	message := make([]byte, 0, len(domain)+1+len(payload))
	message = append(message, domain...)
	message = append(message, 0)
	message = append(message, payload...)
	return message
}

func hashText(value []byte) string {
	digest := sha256.Sum256(value)
	return encodeHash(digest)
}
