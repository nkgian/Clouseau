package analyzer

type Analyzer interface {
	Run(url string, params map[string]interface{}) error
}

var Registry = map[string]Analyzer{
	"whois_lookup": &WhoisAnalyzer{},
	"html_scan":    &HTMLAnalyzer{},
}
