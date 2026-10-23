// Package report renders an audit result as a table, as JSON, or as Markdown
// fit for a pull-request comment.
package report

import (
	"encoding/json"
	"fmt"
	"io"
	"strings"

	"github.com/moveeeax/aws-iam-trust-audit/internal/audit"
)

// Write renders res in the named format.
func Write(w io.Writer, res audit.Result, format string) error {
	switch strings.ToLower(format) {
	case "table", "":
		return writeTable(w, res)
	case "json":
		return writeJSON(w, res)
	case "markdown", "md":
		return writeMarkdown(w, res)
	}
	return fmt.Errorf("unknown format %q (want table, json or markdown)", format)
}

func writeTable(w io.Writer, res audit.Result) error {
	fmt.Fprintln(w, "WHO MAY ASSUME")
	for _, r := range res.Roles {
		fmt.Fprintf(w, "\n  %s  (%s)\n", r.Role, r.File)
		for _, a := range r.Assumers {
			fmt.Fprintf(w, "    %-16s %s%s\n", "["+a.Who.Kind+"]", a.Who.Value, dim(a.Effect))
			fmt.Fprintf(w, "        actions:    %s\n", joinOr(a.Actions, "(none)"))
			fmt.Fprintf(w, "        conditions: %s\n", strings.Join(a.ConditionStrings(), "; "))
		}
	}
	errs, warns := res.Counts()
	fmt.Fprintf(w, "\nFINDINGS (%d error, %d warning)\n", errs, warns)
	if len(res.Findings) == 0 {
		fmt.Fprintln(w, "\n  none")
		return nil
	}
	for _, f := range res.Findings {
		fmt.Fprintf(w, "\n  %-7s %s\n", strings.ToUpper(f.Severity), f.Rule)
		fmt.Fprintf(w, "          role %s, statement %d (%s)\n", f.Role, f.Statement, f.File)
		if f.Principal != "" {
			fmt.Fprintf(w, "          principal %s\n", f.Principal)
		}
		fmt.Fprintf(w, "          %s\n", f.Message)
	}
	return nil
}

func writeJSON(w io.Writer, res audit.Result) error {
	errs, warns := res.Counts()
	out := struct {
		Summary struct {
			Roles    int `json:"roles"`
			Errors   int `json:"errors"`
			Warnings int `json:"warnings"`
		} `json:"summary"`
		Roles    []audit.RoleReport `json:"roles"`
		Findings []audit.Finding    `json:"findings"`
	}{Roles: res.Roles, Findings: res.Findings}
	out.Summary.Roles = len(res.Roles)
	out.Summary.Errors = errs
	out.Summary.Warnings = warns
	if out.Findings == nil {
		out.Findings = []audit.Finding{}
	}
	enc := json.NewEncoder(w)
	enc.SetIndent("", "  ")
	return enc.Encode(out)
}

func writeMarkdown(w io.Writer, res audit.Result) error {
	errs, warns := res.Counts()
	fmt.Fprintf(w, "## IAM trust audit\n\n%d role(s), **%d error**, **%d warning**.\n\n",
		len(res.Roles), errs, warns)
	if len(res.Findings) == 0 {
		fmt.Fprintln(w, "No findings.")
	} else {
		fmt.Fprintln(w, "| Severity | Rule | Role | Stmt | Principal | Detail |")
		fmt.Fprintln(w, "| --- | --- | --- | --- | --- | --- |")
		for _, f := range res.Findings {
			fmt.Fprintf(w, "| %s | `%s` | `%s` | %d | %s | %s |\n",
				f.Severity, f.Rule, f.Role, f.Statement, code(f.Principal), escape(f.Message))
		}
	}
	fmt.Fprint(w, "\n<details><summary>Who may assume each role</summary>\n")
	for _, r := range res.Roles {
		fmt.Fprintf(w, "\n**%s** — `%s`\n\n", r.Role, r.File)
		for _, a := range r.Assumers {
			fmt.Fprintf(w, "- `%s` %s — %s — conditions: %s\n",
				a.Who.Kind, code(a.Who.Value), joinOr(a.Actions, "(none)"),
				strings.Join(a.ConditionStrings(), "; "))
		}
	}
	fmt.Fprintln(w, "\n</details>")
	return nil
}

func joinOr(v []string, fallback string) string {
	if len(v) == 0 {
		return fallback
	}
	return strings.Join(v, ", ")
}

func code(s string) string {
	if s == "" {
		return ""
	}
	return "`" + s + "`"
}

func escape(s string) string { return strings.ReplaceAll(s, "|", "\\|") }

// dim annotates a non-Allow statement; an Allow is the default and stays bare.
func dim(effect string) string {
	if effect == "Allow" {
		return ""
	}
	return " (" + effect + ")"
}
