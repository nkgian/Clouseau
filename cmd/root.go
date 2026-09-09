package cmd

import (
	"fmt"
	"os"

	"clouseau/internal/analyzer"
	"clouseau/internal/config"

	"github.com/spf13/cobra"
)

var configFile string

// Define variables to hold the state of our flags
var skipWhois bool
var skipHTML bool

var rootCmd = &cobra.Command{
	Use:   "webanalyzer [url]",
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
			"whois_lookup": skipWhois,
			"html_scan":    skipHTML,
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

			err := analyzerInstance.Run(url, task.Params)
			if err != nil {
				fmt.Printf("[-] Error running %s: %v\n", task.Name, err)
			}
		}
		
		fmt.Println("---------------------------------------------------")
		fmt.Println("Analysis complete.")
	},
}

func Execute() {
	err := rootCmd.Execute()
	if err != nil {
		os.Exit(1)
	}
}

func init() {
	rootCmd.PersistentFlags().StringVarP(&configFile, "config", "c", "config.yaml", "path to config file")
	
	// Add the boolean flags for skipping specific modules.
	// Format: variable pointer, "flag-name", shorthand (empty here), default value, "description"
	rootCmd.Flags().BoolVar(&skipWhois, "skip-whois", false, "Skip the WHOIS lookup module")
	rootCmd.Flags().BoolVar(&skipHTML, "skip-html", false, "Skip the HTML scanning module")
}