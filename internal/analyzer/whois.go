package analyzer

import "fmt"

type WhoisAnalyzer struct{}

func (w *WhoisAnalyzer) Run(url string, params map[string]interface{}) error {
	fmt.Printf("Running Whois lookup for %s with params: %v\n", url, params)
	return nil
}
