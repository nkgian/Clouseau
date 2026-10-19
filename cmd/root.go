package cmd

import (
	"bytes"
	"encoding/json"
	"fmt"
	"os"
	"time"

	"clouseau/internal/analyzer"
	"clouseau/internal/config"

	"github.com/spf13/cobra"
)

var configFile string
var outputFile string

// Define variables to hold the state of our flags
var skipWhois bool
var skipHTML bool
var skipRobots bool
var skipHeaders bool
var skipDomain bool
var skipThreat bool
var skipInfra bool

type taskResult struct {
	Task   string      `json:"task"`
	Result interface{} `json:"result,omitempty"`
	Error  string      `json:"error,omitempty"`
}

type outputReport struct {
	Target      string       `json:"target"`
	GeneratedAt time.Time    `json:"generated_at"`
	Results     []taskResult `json:"results"`
}

var rootCmd = &cobra.Command{
	Use:   "clouseau [url]",
	Short: "A CLI tool to analyze websites",
	Args:  cobra.ExactArgs(1),
	Run: func(cmd *cobra.Command, args []string) {
		url := args[0]
		fmt.Printf("Starting analysis for: %s\n", url)
		fmt.Println("---------------------------------------------------")

		cfg, err := config.LoadConfig(configFile)
		if err != nil {
			fmt.Printf("Error loading config: %v\n", err)
			os.Exit(1)
		}

		// Map YAML task names to their respective skip flags for easy checking
		skipMap := map[string]bool{
			"whois_lookup":  skipWhois,
			"html_scan":     skipHTML,
			"robots_scan":   skipRobots,
			"headers_scan":  skipHeaders,
			"domain_scan":   skipDomain,
			"threat_lookup": skipThreat,
			"infra_scan":    skipInfra,
		}

		report := outputReport{
			Target:      url,
			GeneratedAt: time.Now(),
			Results:     []taskResult{},
		}

		for _, task := range cfg.Tasks {
			// Check if the user passed a flag to skip this specific task
			if skipMap[task.Name] {
				fmt.Printf("[-] Skipping %s...\n", task.Name)
				continue
			}

			analyzerInstance, exists := analyzer.Registry[task.Name]
			if !exists {
				fmt.Printf("[-] Warning: Unknown analyzer '%s' in config\n", task.Name)
				continue
			}

			result, err := analyzerInstance.Run(url, task.Params)
			if err != nil {
				fmt.Printf("[-] Error running %s: %v\n", task.Name, err)
				report.Results = append(report.Results, taskResult{Task: task.Name, Error: err.Error()})
				continue
			}

			fmt.Println(result)
			report.Results = append(report.Results, taskResult{Task: task.Name, Result: result})
		}

		fmt.Println("---------------------------------------------------")

		if outputFile != "" {
			if err := writeReport(outputFile, report); err != nil {
				fmt.Printf("[-] Error writing report: %v\n", err)
				os.Exit(1)
			}
			fmt.Printf("[+] Report written to %s\n", outputFile)
		}
	},
}

func writeReport(filename string, report outputReport) error {
	var buffer bytes.Buffer
	encoder := json.NewEncoder(&buffer)
	encoder.SetEscapeHTML(false)
	encoder.SetIndent("", "  ")
	if err := encoder.Encode(report); err != nil {
		return err
	}
	return os.WriteFile(filename, buffer.Bytes(), 0o644)
}

func Execute() {
	err := rootCmd.Execute()
	if err != nil {
		os.Exit(1)
	}
}

func init() {
	rootCmd.PersistentFlags().StringVarP(&configFile, "config", "c", "config.yaml", "path to config file")

	// Write the collected module results as a JSON report to this file.
	rootCmd.Flags().StringVarP(&outputFile, "output", "o", "", "write the analysis report as JSON to this file")

	// Add the boolean flags for skipping specific modules.
	// Format: variable pointer, "flag-name", shorthand (empty here), default value, "description"
	rootCmd.Flags().BoolVar(&skipWhois, "skip-whois", false, "Skip the WHOIS lookup module")
	rootCmd.Flags().BoolVar(&skipHTML, "skip-html", false, "Skip the HTML scanning module")
	rootCmd.Flags().BoolVar(&skipRobots, "skip-robots", false, "Skip the robots.txt scanning module")
	rootCmd.Flags().BoolVar(&skipHeaders, "skip-headers", false, "Skip the security headers scanning module")
	rootCmd.Flags().BoolVar(&skipDomain, "skip-domain", false, "Skip the domain name scanning module")
	rootCmd.Flags().BoolVar(&skipThreat, "skip-threat", false, "Skip the threat intelligence module")
	rootCmd.Flags().BoolVar(&skipInfra, "skip-infra", false, "Skip the infrastructure clustering module")
}
