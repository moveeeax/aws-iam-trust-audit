// Command aws-iam-trust-audit reads IAM role trust policies and reports who
// may actually assume each role.
package main

import (
	"flag"
	"fmt"
	"io"
	"os"
	"strings"

	"github.com/moveeeax/aws-iam-trust-audit/internal/audit"
	"github.com/moveeeax/aws-iam-trust-audit/internal/iampolicy"
	"github.com/moveeeax/aws-iam-trust-audit/internal/report"
)

// version is the build stamp; -ldflags can override it.
var version = "0.1.0"

// Exit codes: 0 clean, 1 findings at or above --fail-on, 2 a parse or usage error.
const (
	exitClean    = 0
	exitFindings = 1
	exitError    = 2
)

type stringList []string

func (s *stringList) String() string { return strings.Join(*s, ",") }
func (s *stringList) Set(v string) error {
	for _, piece := range strings.Split(v, ",") {
		if p := strings.TrimSpace(piece); p != "" {
			*s = append(*s, p)
		}
	}
	return nil
}

func main() {
	os.Exit(run(os.Args[1:], os.Stdout, os.Stderr))
}

func run(args []string, stdout, stderr io.Writer) int {
	fs := flag.NewFlagSet("aws-iam-trust-audit", flag.ContinueOnError)
	fs.SetOutput(stderr)
	var (
		dir         = fs.String("dir", ".", "directory (or single file) of trust policy JSON to audit")
		format      = fs.String("format", "table", "output format: table, json or markdown")
		trusted     stringList
		ignore      stringList
		minSeverity = fs.String("min-severity", "warning", "report findings at this severity and above: warning or error")
		failOn      = fs.String("fail-on", "error", "exit 1 when a finding reaches this severity: warning, error or never")
		account     = fs.String("account", "", "the account that owns these roles; defaults to the account in each role ARN")
		listRules   = fs.Bool("rules", false, "list the rules and exit")
		showVersion = fs.Bool("version", false, "print the version and exit")
	)
	fs.Var(&trusted, "trusted-accounts", "account ids that are expected to appear (repeatable or comma-separated)")
	fs.Var(&ignore, "ignore", "rule name to suppress (repeatable or comma-separated)")
	fs.Usage = func() {
		fmt.Fprintf(stderr, "aws-iam-trust-audit — who may actually assume your IAM roles\n\nUsage:\n  aws-iam-trust-audit --dir ./iam/roles [flags]\n\nFlags:\n")
		fs.PrintDefaults()
	}
	if err := fs.Parse(args); err != nil {
		return exitError
	}
	if *showVersion {
		fmt.Fprintln(stdout, version)
		return exitClean
	}
	if *listRules {
		for _, r := range audit.Rules {
			fmt.Fprintf(stdout, "%-28s %-7s %s\n", r.Name, r.Severity, r.Desc)
		}
		return exitClean
	}

	minSev, err := audit.ParseSeverity(*minSeverity)
	if err != nil {
		fmt.Fprintf(stderr, "aws-iam-trust-audit: --min-severity: %v\n", err)
		return exitError
	}
	var failSev audit.Severity
	if !strings.EqualFold(*failOn, "never") {
		failSev, err = audit.ParseSeverity(*failOn)
		if err != nil {
			fmt.Fprintf(stderr, "aws-iam-trust-audit: --fail-on: %v\n", err)
			return exitError
		}
	}
	known := map[string]bool{}
	for _, r := range audit.Rules {
		known[r.Name] = true
	}
	ignoreSet := map[string]bool{}
	for _, name := range ignore {
		if !known[name] {
			fmt.Fprintf(stderr, "aws-iam-trust-audit: --ignore: unknown rule %q (see --rules)\n", name)
			return exitError
		}
		ignoreSet[name] = true
	}

	roles, err := iampolicy.LoadDir(*dir)
	if err != nil {
		fmt.Fprintf(stderr, "aws-iam-trust-audit: %v\n", err)
		return exitError
	}

	res := audit.Run(roles, audit.Options{
		TrustedAccounts: trusted,
		SelfAccount:     *account,
		Ignore:          ignoreSet,
		MinSeverity:     minSev,
	})
	if err := report.Write(stdout, res, *format); err != nil {
		fmt.Fprintf(stderr, "aws-iam-trust-audit: %v\n", err)
		return exitError
	}
	if failSev != 0 && res.Max() >= failSev {
		return exitFindings
	}
	return exitClean
}
