package report

import (
	"fmt"
	"io"
	"strings"

	"github.com/cawalch/go-yara-supplychain/pkg/analyzer"
	"github.com/cawalch/go-yara-supplychain/pkg/ml"
)

// ANSI color escape codes
const (
	ansiReset  = "\033[0m"
	ansiBold   = "\033[1m"
	ansiRed    = "\033[31m"
	ansiGreen  = "\033[32m"
	ansiYellow = "\033[33m"
	ansiCyan   = "\033[36m"
	ansiGray   = "\033[90m"
)

type terminalColors struct {
	red    string
	green  string
	yellow string
	bold   string
	gray   string
	reset  string
}

func getColors(noColor bool) *terminalColors {
	if noColor {
		return &terminalColors{}
	}
	return &terminalColors{
		red:    ansiRed,
		green:  ansiGreen,
		yellow: ansiYellow,
		bold:   ansiBold,
		gray:   ansiGray,
		reset:  ansiReset,
	}
}

// WriteTerminal prints a human-readable security assessment table to the writer.
func WriteTerminal(w io.Writer, verdicts []*analyzer.Verdict, noColor bool) error {
	c := getColors(noColor)

	if _, err := fmt.Fprintf(w, "\n%s=== go-yara-supplychain Security Scan Results ===%s\n\n", c.bold, c.reset); err != nil {
		return err
	}

	criticalCount := 0
	highCount := 0
	mediumCount := 0
	passCount := 0

	for _, v := range verdicts {
		badge := ""
		switch v.RiskLevel {
		case analyzer.RiskCritical:
			badge = fmt.Sprintf("%s%s[CRITICAL - BLOCK]%s", c.bold, c.red, c.reset)
			criticalCount++
		case analyzer.RiskHigh:
			badge = fmt.Sprintf("%s%s[HIGH - WARN]%s", c.bold, c.red, c.reset)
			highCount++
		case analyzer.RiskMedium:
			badge = fmt.Sprintf("%s%s[MEDIUM - WARN]%s", c.bold, c.yellow, c.reset)
			mediumCount++
		default:
			badge = fmt.Sprintf("%s%s[BENIGN - PASS]%s", c.bold, c.green, c.reset)
			passCount++
		}

		if _, err := fmt.Fprintf(w, "%s %s@%s (score: %.2f)%s\n", badge, c.bold, v.PackageName, v.ConfidenceScore, c.reset); err != nil {
			return err
		}
		if v.PackagePath != "" {
			if _, err := fmt.Fprintf(w, "  %sPath:%s %s\n", c.gray, c.reset, v.PackagePath); err != nil {
				return err
			}
		}

		if v.HadObfuscation {
			if _, err := fmt.Fprintf(w, "  %s[!] Unicode/String-concat obfuscation detected and de-obfuscated%s\n", c.yellow, c.reset); err != nil {
				return err
			}
		}

		if len(v.Evidence) > 0 {
			if err := printEvidenceList(w, v.Evidence, c); err != nil {
				return err
			}
		}

		if v.MLScore >= 0.50 && len(v.MLAttributions) > 0 {
			if err := printMLAttributions(w, v.MLScore, v.MLAttributions, c); err != nil {
				return err
			}
		}

		if _, err := fmt.Fprintln(w); err != nil {
			return err
		}
	}

	_, err := fmt.Fprintf(w, "%sSummary:%s %d packages scanned | %s%d passed%s | %s%d critical%s | %s%d high%s | %s%d medium%s\n\n",
		c.bold, c.reset,
		len(verdicts),
		c.green, passCount, c.reset,
		c.red, criticalCount, c.reset,
		c.yellow, highCount, c.reset,
		c.yellow, mediumCount, c.reset,
	)
	return err
}

func printEvidenceList(w io.Writer, evidence []analyzer.EvidenceItem, c *terminalColors) error {
	if _, err := fmt.Fprintf(w, "  %sFindings (%d):%s\n", c.bold, len(evidence), c.reset); err != nil {
		return err
	}

	for _, ev := range evidence {
		sevColor := c.gray
		switch ev.Severity {
		case analyzer.RiskCritical, analyzer.RiskHigh:
			sevColor = c.red
		case analyzer.RiskMedium:
			sevColor = c.yellow
		}

		if _, err := fmt.Fprintf(w, "    - %s[%s]%s %s (%s%s%s)\n",
			sevColor, ev.Severity, c.reset,
			ev.Description,
			c.gray, ev.FilePath, c.reset); err != nil {
			return err
		}

		if ev.Snippet != "" {
			snip := strings.TrimSpace(ev.Snippet)
			if len(snip) > 80 {
				snip = snip[:77] + "..."
			}
			if _, err := fmt.Fprintf(w, "      %sCode: %s%s\n", c.gray, snip, c.reset); err != nil {
				return err
			}
		}
	}

	return nil
}

func printMLAttributions(w io.Writer, mlScore float64, attributions []ml.FeatureInfluence, c *terminalColors) error {
	if _, err := fmt.Fprintf(w, "  %sNeural Anomaly Risk:%s %.1f%%\n", c.bold, c.reset, mlScore*100.0); err != nil {
		return err
	}
	if _, err := fmt.Fprintf(w, "  %sTop Contributing Signals (Explainable AI):%s\n", c.gray, c.reset); err != nil {
		return err
	}

	for _, attr := range attributions {
		sign := "+"
		col := c.red
		if attr.Impact < 0 {
			sign = ""
			col = c.green
		}
		if _, err := fmt.Fprintf(w, "    - %s%s%s: impact %s%s%.2f%s\n",
			c.bold, attr.Name, c.reset,
			col, sign, attr.Impact, c.reset); err != nil {
			return err
		}
	}
	return nil
}
