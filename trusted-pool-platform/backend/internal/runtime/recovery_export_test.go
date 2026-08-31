package runtime

import (
	"testing"
	"time"
)

func TestBuildVerificationExporterFailsClosedWithoutExternalSigner(t *testing.T) {
	manager, err := BuildVerificationExporter(nil, nil, VerificationExportConfig{
		ClientID: "recovery-evidence-export", LeaseOwner: "worker-1", LeaseDuration: time.Minute,
	})
	if err == nil || manager != nil {
		t.Fatalf("missing export signer was accepted: manager=%v err=%v", manager, err)
	}
}
