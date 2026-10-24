# Machine Learning Model Training & Empirical Validation Report

**Date**: October 2026 | **Total Verified Samples**: 25 | **Optimizer**: Gradient Descent with $L_2$ Regularization

## 1. 5-Fold Stratified Cross-Validation Results

| Fold | Train Loss | Val Loss | Accuracy | Precision | Recall | F1 Score | False Positive Rate |
| :---: | :---: | :---: | :---: | :---: | :---: | :---: | :---: |
| 1 | 0.1977 | 0.3963 | 60.0% | 0.0% | 0.0% | 0.000 | **0.00%** |
| 2 | 0.1929 | 0.5211 | 80.0% | 100.0% | 50.0% | 0.667 | **0.00%** |
| 3 | 0.0464 | 1.6465 | 60.0% | 0.0% | 0.0% | 0.000 | **0.00%** |
| 4 | 0.1958 | 0.2548 | 80.0% | 100.0% | 50.0% | 0.667 | **0.00%** |
| 5 | 0.1989 | 0.6977 | 80.0% | 100.0% | 50.0% | 0.667 | **0.00%** |
| **Mean** | - | - | **72.0%** | **60.0%** | **30.0%** | **0.400** | **0.00%** |

## 2. Learned Feature Weights & Odds Ratios

| Index | Feature Name | Learned Weight ($w_i$) | Odds Ratio ($e^{w_i}$) | Signal Direction |
| :---: | :--- | :---: | :---: | :--- |
| 0 | `HasLifecycleHook` | `-0.4478` | `0.639` | **Protective Signal (Risk Attenuator)** |
| 1 | `HookPipesToShell` | `1.6859` | `5.397` | Threat Signal (Risk Booster) |
| 2 | `HookNetworkDownload` | `0.7020` | `2.018` | Threat Signal (Risk Booster) |
| 3 | `ChecksumValidation` | `-0.7064` | `0.493` | **Protective Signal (Risk Attenuator)** |
| 4 | `TrustedCDNSource` | `-0.7064` | `0.493` | **Protective Signal (Risk Attenuator)** |
| 5 | `UnicodeObfuscation` | `0.3251` | `1.384` | Threat Signal (Risk Booster) |
| 6 | `StringConcatDensity` | `0.0000` | `1.000` | Threat Signal (Risk Booster) |
| 7 | `Base64PayloadCount` | `0.4609` | `1.586` | Threat Signal (Risk Booster) |
| 8 | `DynamicEval` | `-0.2638` | `0.768` | **Protective Signal (Risk Attenuator)** |
| 9 | `ChildProcessExec` | `0.0000` | `1.000` | Threat Signal (Risk Booster) |
| 10 | `NetworkRawIP` | `2.6971` | `14.837` | Threat Signal (Risk Booster) |
| 11 | `WebhookExfiltration` | `2.7783` | `16.091` | Threat Signal (Risk Booster) |
| 12 | `SensitivePathAccess` | `-1.0769` | `0.341` | **Protective Signal (Risk Attenuator)** |
| 13 | `ProcessTampering` | `0.0000` | `1.000` | Threat Signal (Risk Booster) |
| 14 | `ScriptSizeRatio` | `-0.1083` | `0.897` | **Protective Signal (Risk Attenuator)** |
| 15 | `YARAMatchWeight` | `3.6486` | `38.419` | Threat Signal (Risk Booster) |

**Baseline Bias ($b$)**: `-5.2622` (clean package prior probability: `0.52%`)
