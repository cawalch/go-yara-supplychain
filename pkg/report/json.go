package report

import (
	"encoding/json"
	"fmt"
	"io"

	"github.com/cawalch/go-yara-supplychain/pkg/analyzer"
)

// WriteJSON formats the verdicts as a pretty-printed JSON array.
func WriteJSON(w io.Writer, verdicts []*analyzer.Verdict) error {
	enc := json.NewEncoder(w)
	enc.SetIndent("", "  ")
	if err := enc.Encode(verdicts); err != nil {
		return fmt.Errorf("encoding JSON verdicts: %w", err)
	}
	return nil
}

// WriteNDJSON formats each verdict as a single line JSON object (Newline Delimited JSON).
func WriteNDJSON(w io.Writer, verdicts []*analyzer.Verdict) error {
	enc := json.NewEncoder(w)
	for _, v := range verdicts {
		if err := enc.Encode(v); err != nil {
			return fmt.Errorf("encoding NDJSON verdict: %w", err)
		}
	}
	return nil
}
