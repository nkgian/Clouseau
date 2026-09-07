package analyzer

import "fmt"

type HTMLAnalyzer struct{}

func (w *HTMLAnalyzer) Run(url string, params map[string]interface{}) error {
	fmt.Printf("Running html lookup for %s with %v", url, params)
	return nil
}
