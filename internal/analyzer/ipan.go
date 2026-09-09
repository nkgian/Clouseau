package analyzer

import "fmt"

type IpLookup

func (w *IpLookup) Run(url string, params map[string]interface{}) error {
	fmt.Printf("Running ip lookup for %s with %v", url, params)
	return nil
}
