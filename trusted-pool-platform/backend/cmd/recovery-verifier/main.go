package main

import (
	"flag"
	"fmt"
	"io"
	"os"
	"strings"
	"time"

	"trusted-pool-platform/backend/internal/recovery/offline"
)

const (
	exitVerified   = 0
	exitIO         = 1
	exitIncomplete = 2
	exitRejected   = 3
)

func main() {
	os.Exit(run(os.Args[1:], os.Stdin, os.Stdout))
}

func run(args []string, stdin io.Reader, stdout io.Writer) int {
	if len(args) == 0 {
		return writeVerificationFailure(stdout, offline.ReasonCLIUsageInvalid, exitIO)
	}
	switch args[0] {
	case "verify":
		return runVerify(args[1:], stdin, stdout)
	case "reveal-authorize":
		return runRevealAuthorize(args[1:], stdin, stdout)
	default:
		return writeVerificationFailure(stdout, offline.ReasonCLIUsageInvalid, exitIO)
	}
}

func runVerify(args []string, stdin io.Reader, stdout io.Writer) int {
	flags := flag.NewFlagSet("verify", flag.ContinueOnError)
	flags.SetOutput(io.Discard)
	bundlePath := flags.String("bundle", "", "")
	policyPath := flags.String("policy", "", "")
	if flags.Parse(args) != nil || flags.NArg() != 0 || *bundlePath == "" || *policyPath == "" ||
		(*bundlePath == "-" && *policyPath == "-") {
		return writeVerificationFailure(stdout, offline.ReasonCLIUsageInvalid, exitIO)
	}
	limits := offline.DefaultLimits()
	bundle, err := readLocalInput(*bundlePath, stdin, limits.MaxBundleBytes)
	if err != nil {
		return writeVerificationFailure(stdout, offline.ReasonIOFailure, exitIO)
	}
	policy, err := readLocalInput(*policyPath, stdin, limits.MaxPolicyBytes)
	if err != nil {
		return writeVerificationFailure(stdout, offline.ReasonIOFailure, exitIO)
	}
	report := offline.Verify(bundle, policy, limits)
	encoded, err := offline.MarshalCanonicalReport(report)
	if err != nil || writeLine(stdout, encoded) != nil {
		return exitIO
	}
	switch report.Verdict {
	case offline.VerdictVerified:
		return exitVerified
	case offline.VerdictIncomplete:
		return exitIncomplete
	default:
		return exitRejected
	}
}

func runRevealAuthorize(args []string, stdin io.Reader, stdout io.Writer) int {
	flags := flag.NewFlagSet("reveal-authorize", flag.ContinueOnError)
	flags.SetOutput(io.Discard)
	bundlePath := flags.String("bundle", "", "")
	policyPath := flags.String("policy", "", "")
	intentPath := flags.String("intent", "", "")
	approvalsPath := flags.String("approvals", "", "")
	atText := flags.String("at", "", "")
	if flags.Parse(args) != nil || flags.NArg() != 0 || *bundlePath == "" || *policyPath == "" ||
		*intentPath == "" || *approvalsPath == "" || *atText == "" ||
		countStdin(*bundlePath, *policyPath, *intentPath, *approvalsPath) > 1 {
		return writeRevealFailure(stdout, offline.ReasonCLIUsageInvalid, exitIO, "")
	}
	verificationTime, err := time.Parse(time.RFC3339Nano, *atText)
	if err != nil || verificationTime.UTC().Format(time.RFC3339Nano) != *atText {
		return writeRevealFailure(stdout, offline.ReasonCLIUsageInvalid, exitIO, "")
	}
	limits := offline.DefaultLimits()
	bundle, err := readLocalInput(*bundlePath, stdin, limits.MaxBundleBytes)
	if err != nil {
		return writeRevealFailure(stdout, offline.ReasonIOFailure, exitIO, *atText)
	}
	policy, err := readLocalInput(*policyPath, stdin, limits.MaxPolicyBytes)
	if err != nil {
		return writeRevealFailure(stdout, offline.ReasonIOFailure, exitIO, *atText)
	}
	intent, err := readLocalInput(*intentPath, stdin, limits.MaxIntentBytes)
	if err != nil {
		return writeRevealFailure(stdout, offline.ReasonIOFailure, exitIO, *atText)
	}
	approvals, err := readLocalInput(*approvalsPath, stdin, limits.MaxApprovalsBytes)
	if err != nil {
		return writeRevealFailure(stdout, offline.ReasonIOFailure, exitIO, *atText)
	}
	report := offline.EvaluateRevealAuthorization(bundle, policy, intent, approvals, verificationTime.UTC(), limits)
	encoded, err := offline.MarshalCanonicalRevealReport(report)
	if err != nil || writeLine(stdout, encoded) != nil {
		return exitIO
	}
	if report.Verdict == offline.RevealVerdictRejected {
		return exitRejected
	}
	return exitIncomplete
}

func readLocalInput(path string, stdin io.Reader, maximum int64) ([]byte, error) {
	var reader io.Reader
	var file *os.File
	if path == "-" {
		reader = stdin
	} else {
		info, err := os.Lstat(path)
		if err != nil || info.Mode()&os.ModeSymlink != 0 || !info.Mode().IsRegular() {
			return nil, fmt.Errorf("input is not a regular file")
		}
		file, err = os.Open(path)
		if err != nil {
			return nil, err
		}
		defer file.Close()
		openedInfo, err := file.Stat()
		if err != nil || !openedInfo.Mode().IsRegular() || !os.SameFile(info, openedInfo) {
			return nil, fmt.Errorf("input changed while opening")
		}
		reader = file
	}
	data, err := io.ReadAll(io.LimitReader(reader, maximum+1))
	if err != nil || int64(len(data)) > maximum {
		return nil, fmt.Errorf("input exceeds limit")
	}
	return data, nil
}

func countStdin(paths ...string) int {
	count := 0
	for _, path := range paths {
		if strings.TrimSpace(path) == "-" {
			count++
		}
	}
	return count
}

func writeVerificationFailure(stdout io.Writer, reason offline.ReasonCode, exitCode int) int {
	report := offline.Report{ProtocolVersion: offline.ReportProtocolVersion, Verdict: offline.VerdictRejected,
		ReasonCode: reason}
	encoded, err := offline.MarshalCanonicalReport(report)
	if err != nil || writeLine(stdout, encoded) != nil {
		return exitIO
	}
	return exitCode
}

func writeRevealFailure(stdout io.Writer, reason offline.ReasonCode, exitCode int, evaluationTime string) int {
	report := offline.RevealReport{ProtocolVersion: offline.RevealReportVersion,
		Verdict: offline.RevealVerdictRejected, ReasonCode: reason, EvaluationTime: evaluationTime}
	encoded, err := offline.MarshalCanonicalRevealReport(report)
	if err != nil || writeLine(stdout, encoded) != nil {
		return exitIO
	}
	return exitCode
}

func writeLine(output io.Writer, value []byte) error {
	_, err := fmt.Fprintf(output, "%s\n", value)
	return err
}
