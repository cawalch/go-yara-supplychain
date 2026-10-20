# Machine Learning Model Training & Empirical Validation Report

**Date**: October 2026 | **Total Verified Samples**: 25 | **Optimizer**: Gradient Descent with $L_2$ Regularization

## 1. 5-Fold Stratified Cross-Validation Results

| Fold | Train Loss | Val Loss | Accuracy | Precision | Recall | F1 Score | False Positive Rate |
| :---: | :---: | :---: | :---: | :---: | :---: | :---: | :---: |
| 1 | 0.2047 | 0.4356 | 60.0% | 0.0% | 0.0% | 0.000 | **0.00%** |
| 2 | 0.1977 | 0.6595 | 60.0% | 0.0% | 0.0% | 0.000 | **0.00%** |
| 3 | 0.0586 | 1.5550 | 60.0% | 0.0% | 0.0% | 0.000 | **0.00%** |
| 4 | 0.2027 | 0.3145 | 60.0% | 0.0% | 0.0% | 0.000 | **0.00%** |
| 5 | 0.2049 | 0.8167 | 80.0% | 100.0% | 50.0% | 0.667 | **0.00%** |
| **Mean** | - | - | **64.0%** | **20.0%** | **10.0%** | **0.133** | **0.00%** |

## 2. Learned Feature Weights & Odds Ratios

| Index | Feature Name | Learned Weight ($w_i$) | Odds Ratio ($e^{w_i}$) | Signal Direction |
| :---: | :--- | :---: | :---: | :--- |
| 0 | `HasLifecycleHook` | `-0.4518` | `0.636` | **Protective Signal (Risk Attenuator)** |
| 1 | `HookPipesToShell` | `1.7695` | `5.868` | Threat Signal (Risk Booster) |
| 2 | `HookNetworkDownload` | `0.6596` | `1.934` | Threat Signal (Risk Booster) |
| 3 | `ChecksumValidation` | `-0.7295` | `0.482` | **Protective Signal (Risk Attenuator)** |
| 4 | `TrustedCDNSource` | `-0.7295` | `0.482` | **Protective Signal (Risk Attenuator)** |
| 5 | `UnicodeObfuscation` | `0.5114` | `1.668` | Threat Signal (Risk Booster) |
| 6 | `StringConcatDensity` | `0.0000` | `1.000` | Threat Signal (Risk Booster) |
| 7 | `Base64PayloadCount` | `0.5562` | `1.744` | Threat Signal (Risk Booster) |
| 8 | `DynamicEval` | `-0.2192` | `0.803` | **Protective Signal (Risk Attenuator)** |
| 9 | `ChildProcessExec` | `0.0000` | `1.000` | Threat Signal (Risk Booster) |
| 10 | `NetworkRawIP` | `2.8672` | `17.587` | Threat Signal (Risk Booster) |
| 11 | `WebhookExfiltration` | `3.4929` | `32.880` | Threat Signal (Risk Booster) |
| 12 | `SensitivePathAccess` | `-0.8748` | `0.417` | **Protective Signal (Risk Attenuator)** |
| 13 | `ProcessTampering` | `0.0000` | `1.000` | Threat Signal (Risk Booster) |
| 14 | `ScriptSizeRatio` | `-0.1280` | `0.880` | **Protective Signal (Risk Attenuator)** |
| 15 | `YARAMatchWeight` | `3.2829` | `26.652` | Threat Signal (Risk Booster) |

**Baseline Bias ($b$)**: `-5.1851` (clean package prior probability: `0.56%`)
