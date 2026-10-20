package ml

import (
	"testing"
)

func TestCleanPackageBaseline(t *testing.T) {
	model := DefaultModel()

	fv := &FeatureVector{
		HasLifecycleHook: 0.0,
		ScriptSizeRatio:  0.0,
	}

	pred := model.Predict(fv)
	if pred.Probability > 0.01 {
		t.Fatalf("expected clean package probability < 0.01, got %.4f", pred.Probability)
	}
}

func TestBenignBinaryFetcherDisambiguation(t *testing.T) {
	model := DefaultModel()

	// esbuild/sharp style: has postinstall, downloads binary, BUT validates checksum and uses trusted domain
	fv := &FeatureVector{
		HasLifecycleHook:    1.0,
		HookNetworkDownload: 1.0,
		ChecksumValidation:  1.0, // protective
		TrustedCDNSource:    1.0, // protective
		ScriptSizeRatio:     0.2,
	}

	pred := model.Predict(fv)
	if pred.Probability > 0.05 {
		t.Fatalf("expected benign binary fetcher probability < 0.05, got %.4f", pred.Probability)
	}
}

func TestMaliciousShellDropper(t *testing.T) {
	model := DefaultModel()

	// Attack style: curl | bash in postinstall
	fv := &FeatureVector{
		HasLifecycleHook:    1.0,
		HookPipesToShell:    1.0,
		HookNetworkDownload: 1.0,
		YARAMatchWeight:     1.0,
	}

	pred := model.Predict(fv)
	if pred.Probability < 0.50 {
		t.Fatalf("expected malicious dropper probability >= 0.50, got %.4f", pred.Probability)
	}

	// Verify explainability
	hasShellAttribution := false
	for _, attr := range pred.Attributions {
		if attr.Name == "HookPipesToShell" && attr.Impact > 0 {
			hasShellAttribution = true
			break
		}
	}
	if !hasShellAttribution {
		t.Errorf("expected HookPipesToShell in explainability attributions, got %+v", pred.Attributions)
	}
}

func TestObfuscatedBackdoor(t *testing.T) {
	model := DefaultModel()

	fv := &FeatureVector{
		UnicodeObfuscation:  1.0,
		StringConcatDensity: 2.0,
		Base64PayloadCount:  3.0,
		DynamicEval:         1.0,
		NetworkRawIP:        1.0,
		YARAMatchWeight:     1.5,
	}

	pred := model.Predict(fv)
	if pred.Probability < 0.95 {
		t.Fatalf("expected obfuscated backdoor probability >= 0.95, got %.4f", pred.Probability)
	}
}

func BenchmarkModelPredict(b *testing.B) {
	model := DefaultModel()
	fv := &FeatureVector{
		HasLifecycleHook:    1.0,
		HookNetworkDownload: 1.0,
		ChecksumValidation:  1.0,
		TrustedCDNSource:    1.0,
		DynamicEval:         0.5,
		YARAMatchWeight:     0.5,
	}

	b.ResetTimer()
	b.ReportAllocs()
	for i := 0; i < b.N; i++ {
		_ = model.Predict(fv)
	}
}
