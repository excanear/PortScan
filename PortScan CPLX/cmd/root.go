package cmd

import (
	"os"

	"github.com/spf13/cobra"
)

var rootCmd = &cobra.Command{
	Use:   "webscan",
	Short: "HTTP-focused port scanner",
	Long:  "webscan is a high-performance HTTP/HTTPS focused port scanner (skeleton).",
}

// Execute runs the root cobra command.
func Execute() {
	if err := rootCmd.Execute(); err != nil {
		os.Exit(1)
	}
}
