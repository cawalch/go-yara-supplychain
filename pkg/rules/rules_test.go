package rules

import (
	"testing"
)

func TestGetCompiledRules(t *testing.T) {
	prog, err := GetCompiledRules()
	if err != nil {
		t.Fatalf("failed to compile embedded supply chain rules: %v", err)
	}
	if len(prog.Rules) == 0 {
		t.Fatal("expected compiled rules to be non-empty")
	}

	// Verify cached instance returns identical pointer
	second, err := GetCompiledRules()
	if err != nil {
		t.Fatalf("second call failed: %v", err)
	}
	if prog != second {
		t.Fatal("expected cached CompiledProgram singleton")
	}
}
