package main

import (
	"fmt"
	"log"
	"path/filepath"
)

func main() {
	fmt.Println("=== go-yara-supplychain ML Training & Validation Pipeline ===")

	rawSamples := GetCorpusSamples()
	fmt.Printf("Loaded %d audited training samples from corpus\n", len(rawSamples))

	// 1. Save corpus metadata to disk
	corpusPath := filepath.Join("tools", "train", "data", "corpus.json")
	if err := SaveCorpusToFile(corpusPath); err != nil {
		log.Fatalf("Failed saving corpus file: %v", err)
	}
	fmt.Printf("Saved corpus metadata to %s\n", corpusPath)

	// 2. Feature Extraction
	dataset, err := ExtractCorpusDataset(rawSamples)
	if err != nil {
		log.Fatalf("Feature extraction failed: %v", err)
	}
	fmt.Printf("Extracted 16-D feature vectors for %d packages\n", len(dataset))

	// 3. 5-Fold Stratified Cross Validation
	fmt.Println("\nRunning 5-Fold Stratified Cross-Validation...")
	folds, err := RunStratifiedKFold(dataset, 5)
	if err != nil {
		log.Fatalf("Cross validation failed: %v", err)
	}

	for _, f := range folds {
		fmt.Printf("  Fold %d: Acc=%.1f%%, Prec=%.1f%%, Rec=%.1f%%, F1=%.3f, FP-Rate=%.2f%% (ValLoss=%.4f)\n",
			f.FoldNumber, f.Accuracy*100, f.Precision*100, f.Recall*100, f.F1, f.FPRate*100, f.ValLoss)
	}

	// 4. Train Final Model on Complete Dataset
	fmt.Println("\nTraining final production model on complete dataset (epochs=2000, lr=0.1, l2=0.001)...")
	finalModel, finalLoss := TrainLogisticRegression(dataset, 2000, 0.1, 0.001)
	fmt.Printf("Training complete. Final Loss: %.4f, Baseline Bias: %.4f\n", finalLoss, finalModel.Bias)

	// 5. Generate Go Weights File
	weightsPath := filepath.Join("pkg", "ml", "weights_generated.go")
	if err := GenerateGoWeightsCode(finalModel, weightsPath); err != nil {
		log.Fatalf("Failed writing generated weights: %v", err)
	}
	fmt.Printf("Successfully generated Go weights: %s\n", weightsPath)

	// 6. Generate Markdown Audit Report
	reportPath := filepath.Join("pkg", "ml", "TRAINING_REPORT.md")
	if err := GenerateMarkdownReport(finalModel, folds, len(dataset), reportPath); err != nil {
		log.Fatalf("Failed writing training report: %v", err)
	}
	fmt.Printf("Successfully generated validation report: %s\n", reportPath)
}
