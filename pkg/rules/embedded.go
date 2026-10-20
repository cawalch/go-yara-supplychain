// Package rules embeds and compiles curated supply chain YARA rules.
package rules

import (
	"context"
	_ "embed"
	"fmt"
	"sync"

	"github.com/cawalch/go-yara/compiler"
)

//go:embed supplychain.yar
var SupplyChainRulesSource string

var (
	compiledProg *compiler.CompiledProgram
	compileOnce  sync.Once
	compileErr   error
)

// GetCompiledRules returns a cached, compiled program of the builtin supply chain rules.
// CompiledProgram is immutable and thread-safe for concurrent scanner instances.
func GetCompiledRules() (*compiler.CompiledProgram, error) {
	compileOnce.Do(func() {
		comp := compiler.NewCompiler()
		compiledProg, compileErr = comp.CompileSourceWithContext(context.Background(), SupplyChainRulesSource)
		if compileErr != nil {
			compileErr = fmt.Errorf("compiling supply chain YARA rules: %w", compileErr)
		}
	})
	return compiledProg, compileErr
}
