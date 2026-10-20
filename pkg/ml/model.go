// Package ml provides a pure-Go, zero-CGO neural network inference engine
// optimized for high-confidence supply chain malware risk classification.
package ml

import (
	"math"
)

// FeatureVector defines the 16 extracted structural and behavioral signals.
type FeatureVector struct {
	HasLifecycleHook    float64 // 0: Has preinstall/postinstall hooks
	HookPipesToShell    float64 // 1: Hook command pipes directly to shell (| sh, | bash)
	HookNetworkDownload float64 // 2: Hook command downloads remote script (curl, wget)
	ChecksumValidation  float64 // 3: Verified checksum/integrity present (protective)
	TrustedCDNSource    float64 // 4: Download from trusted domain (protective)
	UnicodeObfuscation  float64 // 5: Normalized invisible/homoglyph runes
	StringConcatDensity float64 // 6: Folded string concatenation count
	Base64PayloadCount  float64 // 7: Decoded hidden base64 blocks
	DynamicEval         float64 // 8: eval(), Function(), vm.runInContext
	ChildProcessExec    float64 // 9: child_process.exec/spawn in scripts
	NetworkRawIP        float64 // 10: Outbound socket to raw IP address
	WebhookExfiltration float64 // 11: Discord, Telegram, or webhook.site exfiltration
	SensitivePathAccess float64 // 12: Access to .ssh, .aws, .env, /etc/passwd
	ProcessTampering    float64 // 13: Attempt to kill processes or modify bashrc
	ScriptSizeRatio     float64 // 14: Log-ratio of hook size to total package size
	YARAMatchWeight     float64 // 15: Weighted sum of activated YARA signatures
}

// FeatureNames maps vector indices to human-readable names.
var FeatureNames = [16]string{
	"HasLifecycleHook",
	"HookPipesToShell",
	"HookNetworkDownload",
	"ChecksumValidation",
	"TrustedCDNSource",
	"UnicodeObfuscation",
	"StringConcatDensity",
	"Base64PayloadCount",
	"DynamicEval",
	"ChildProcessExec",
	"NetworkRawIP",
	"WebhookExfiltration",
	"SensitivePathAccess",
	"ProcessTampering",
	"ScriptSizeRatio",
	"YARAMatchWeight",
}

// Prediction contains the neural network risk probability and explainable feature attributions.
type Prediction struct {
	Probability  float64            // Malicious probability [0.0, 1.0]
	Attributions []FeatureInfluence // Top contributing signals (Explainable AI)
}

// FeatureInfluence describes how much a specific feature pushed the prediction towards malicious or benign.
type FeatureInfluence struct {
	Name   string
	Value  float64
	Impact float64 // Positive = pushed towards malicious; Negative = pushed towards benign
}

// ToSlice converts FeatureVector to a flat 16-element float64 slice.
func (f *FeatureVector) ToSlice() [16]float64 {
	return [16]float64{
		f.HasLifecycleHook,
		f.HookPipesToShell,
		f.HookNetworkDownload,
		f.ChecksumValidation,
		f.TrustedCDNSource,
		f.UnicodeObfuscation,
		f.StringConcatDensity,
		f.Base64PayloadCount,
		f.DynamicEval,
		f.ChildProcessExec,
		f.NetworkRawIP,
		f.WebhookExfiltration,
		f.SensitivePathAccess,
		f.ProcessTampering,
		f.ScriptSizeRatio,
		f.YARAMatchWeight,
	}
}

// NeuralClassifier is a 16 -> 16 -> 8 -> 1 Multi-Layer Perceptron (MLP)
// trained on benign package distributions and supply chain attack corpora.
type NeuralClassifier struct {
	w1 [16][16]float64 // Input (16) -> Hidden 1 (16)
	b1 [16]float64     // Bias 1
	w2 [16][8]float64  // Hidden 1 (16) -> Hidden 2 (8)
	b2 [8]float64      // Bias 2
	w3 [8]float64      // Hidden 2 (8) -> Output (1)
	b3 float64         // Bias 3
}

// DefaultModel returns the pre-trained, calibrated neural network model.
func DefaultModel() *NeuralClassifier {
	return pretrainedModel
}

// Predict performs a high-speed forward pass (< 2 microseconds) and computes feature attributions.
func (m *NeuralClassifier) Predict(fv *FeatureVector) Prediction {
	x := fv.ToSlice()

	// Hidden Layer 1: h1 = ReLU(x * W1 + b1)
	var h1 [16]float64
	for j := 0; j < 16; j++ {
		sum := m.b1[j]
		for i := 0; i < 16; i++ {
			sum += x[i] * m.w1[i][j]
		}
		if sum > 0 {
			h1[j] = sum
		}
	}

	// Hidden Layer 2: h2 = ReLU(h1 * W2 + b2)
	var h2 [8]float64
	for j := 0; j < 8; j++ {
		sum := m.b2[j]
		for i := 0; i < 16; i++ {
			sum += h1[i] * m.w2[i][j]
		}
		if sum > 0 {
			h2[j] = sum
		}
	}

	// Output Layer: z = h2 * W3 + b3, p = Sigmoid(z)
	z := m.b3
	for i := 0; i < 8; i++ {
		z += h2[i] * m.w3[i]
	}

	prob := sigmoid(z)

	// Compute linear approximation of feature attributions for explainability
	attributions := make([]FeatureInfluence, 0, 5)
	for i := 0; i < 16; i++ {
		if x[i] == 0 {
			continue
		}
		// Effective path weight: approximate gradient w.r.t input feature
		effectiveWeight := 0.0
		for j := 0; j < 16; j++ {
			if h1[j] <= 0 {
				continue
			}
			w1Val := m.w1[i][j]
			for k := 0; k < 8; k++ {
				if h2[k] <= 0 {
					continue
				}
				effectiveWeight += w1Val * m.w2[j][k] * m.w3[k]
			}
		}

		impact := x[i] * effectiveWeight
		if math.Abs(impact) > 0.05 {
			attributions = append(attributions, FeatureInfluence{
				Name:   FeatureNames[i],
				Value:  x[i],
				Impact: impact,
			})
		}
	}

	return Prediction{
		Probability:  prob,
		Attributions: attributions,
	}
}

func sigmoid(z float64) float64 {
	switch {
	case z > 15.0:
		return 1.0
	case z < -15.0:
		return 0.0
	default:
		return 1.0 / (1.0 + math.Exp(-z))
	}
}
