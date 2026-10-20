# Machine Learning Model Training & Empirical Validation Report

**Date**: October 2026 | **Total Verified Samples**: 25 | **Optimizer**: Gradient Descent with $L_2$ Regularization

## 1. 5-Fold Stratified Cross-Validation Results

| Fold | Train Loss | Val Loss | Accuracy | Precision | Recall | F1 Score | False Positive Rate |
| :---: | :---: | :---: | :---: | :---: | :---: | :---: | :---: |
| 1 | 0.2012 | 0.5383 | 60.0% | 0.0% | 0.0% | 0.000 | **0.00%** |
| 2 | 0.1977 | 0.6067 | 60.0% | 0.0% | 0.0% | 0.000 | **0.00%** |
| 3 | 0.0574 | 1.5439 | 60.0% | 0.0% | 0.0% | 0.000 | **0.00%** |
| 4 | 0.1974 | 0.3206 | 60.0% | 0.0% | 0.0% | 0.000 | **0.00%** |
| 5 | 0.2002 | 0.8050 | 80.0% | 100.0% | 50.0% | 0.667 | **0.00%** |
| **Mean** | - | - | **64.0%** | **20.0%** | **10.0%** | **0.133** | **0.00%** |

## 2. Learned Feature Weights & Odds Ratios

| Index | Feature Name | Learned Weight ($w_i$) | Odds Ratio ($e^{w_i}$) | Signal Direction |
| :---: | :--- | :---: | :---: | :--- |
| 0 | `HasLifecycleHook` | `-0.5252` | `0.591` | **Protective Signal (Risk Attenuator)** |
| 1 | `HookPipesToShell` | `1.7311` | `5.647` | Threat Signal (Risk Booster) |
| 2 | `HookNetworkDownload` | `0.6611` | `1.937` | Threat Signal (Risk Booster) |
| 3 | `ChecksumValidation` | `-0.7321` | `0.481` | **Protective Signal (Risk Attenuator)** |
| 4 | `TrustedCDNSource` | `-0.7321` | `0.481` | **Protective Signal (Risk Attenuator)** |
| 5 | `UnicodeObfuscation` | `0.5066` | `1.660` | Threat Signal (Risk Booster) |
| 6 | `StringConcatDensity` | `0.0000` | `1.000` | Threat Signal (Risk Booster) |
| 7 | `Base64PayloadCount` | `0.6530` | `1.921` | Threat Signal (Risk Booster) |
| 8 | `DynamicEval` | `-0.7577` | `0.469` | **Protective Signal (Risk Attenuator)** |
| 9 | `ChildProcessExec` | `0.0000` | `1.000` | Threat Signal (Risk Booster) |
| 10 | `NetworkRawIP` | `2.8374` | `17.072` | Threat Signal (Risk Booster) |
| 11 | `WebhookExfiltration` | `3.4464` | `31.388` | Threat Signal (Risk Booster) |
| 12 | `SensitivePathAccess` | `-0.9485` | `0.387` | **Protective Signal (Risk Attenuator)** |
| 13 | `ProcessTampering` | `0.0000` | `1.000` | Threat Signal (Risk Booster) |
| 14 | `ScriptSizeRatio` | `-0.1663` | `0.847` | **Protective Signal (Risk Attenuator)** |
| 15 | `YARAMatchWeight` | `3.3270` | `27.856` | Threat Signal (Risk Booster) |

**Baseline Bias ($b$)**: `-5.1157` (clean package prior probability: `0.60%`)
