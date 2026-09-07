package cmd

import (
	"fmt"
	"os"

	"github.com/spf13/cobra"
)

var rootCmd = &cobra.Command{
	Use:   "clouseau [url]",
	Short: "A CLI tool to analyze websites. Poorly.",
	Args:  cobra.ExactArgs(1), // Ensures exactly one argument (the URL) is provided
	Run: func(cmd *cobra.Command, args []string) {
		url := args[0]

		// TODO: In the future load the YAML here and pass it to the analyzer engine

		fmt.Printf("site to analyze is : %s\n", url)
	},
}

func Execute() {
	err := rootCmd.Execute()
	if err != nil {
		os.Exit(1)
	}
}

func init() {
	// define global	 flags, like --config config.yaml
}
