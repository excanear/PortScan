package cmd

import (
	"context"
	"fmt"
	"os"
	"os/signal"
	"strconv"
	"strings"
	"syscall"
	"time"

	"portscan/internal/scanner"
	"portscan/pkg/output"

	"github.com/spf13/cobra"
)

var (
	flagTarget  string
	flagPorts   string
	flagThreads int
	flagTimeout int
	flagJSON    bool
	flagVerbose bool
	flagRetries int
	flagRate    int
)

var scanCmd = &cobra.Command{
	Use:   "scan",
	Short: "Scan target for web services",
	RunE: func(cmd *cobra.Command, args []string) error {
		if flagTarget == "" {
			return fmt.Errorf("target is required")
		}
		ports, err := parsePorts(flagPorts)
		if err != nil {
			return err
		}
		cfg := scanner.Config{
			Target:    flagTarget,
			Ports:     ports,
			Threads:   flagThreads,
			Timeout:   time.Duration(flagTimeout) * time.Second,
			Verbose:   flagVerbose,
			JSON:      flagJSON,
			Retries:   flagRetries,
			RateLimit: flagRate,
		}
		sc := scanner.NewScanner(cfg)
		ctx, stop := signal.NotifyContext(context.Background(), os.Interrupt, syscall.SIGTERM)
		defer stop()
		start := time.Now()
		results, err := sc.Start(ctx)
		duration := time.Since(start)
		if err != nil {
			return err
		}
		if flagJSON {
			b, err := output.FormatJSON(results, flagTarget, duration)
			if err != nil {
				return err
			}
			fmt.Println(string(b))
			return nil
		}
		fmt.Print(output.FormatText(results, flagVerbose, flagTarget, duration))
		return nil
	},
}

func init() {
	rootCmd.AddCommand(scanCmd)
	scanCmd.Flags().StringVarP(&flagTarget, "target", "t", "", "Target domain or IP (required)")
	scanCmd.Flags().StringVarP(&flagPorts, "ports", "p", "80,443", "Comma-separated ports or ranges (e.g., 1-1024,80,443)")
	scanCmd.Flags().IntVar(&flagThreads, "threads", 100, "Number of concurrent workers")
	scanCmd.Flags().IntVar(&flagTimeout, "timeout", 2, "Timeout in seconds for network ops")
	scanCmd.Flags().IntVar(&flagRetries, "retries", 2, "Number of retries for TCP connect (default 2)")
	scanCmd.Flags().IntVar(&flagRate, "rate", 0, "Rate limit (connections per second). 0 = unlimited")
	scanCmd.Flags().BoolVar(&flagJSON, "json", false, "Output in JSON format")
	scanCmd.Flags().BoolVarP(&flagVerbose, "verbose", "v", false, "Verbose output")
}

// parsePorts parses comma separated ports and ranges into a slice of ints.
func parsePorts(spec string) ([]int, error) {
	var ports []int
	if spec == "" {
		return ports, nil
	}
	tokens := strings.Split(spec, ",")
	for _, t := range tokens {
		t = strings.TrimSpace(t)
		if t == "" {
			continue
		}
		if strings.Contains(t, "-") {
			parts := strings.SplitN(t, "-", 2)
			start, err := strconv.Atoi(parts[0])
			if err != nil {
				return nil, err
			}
			end, err := strconv.Atoi(parts[1])
			if err != nil {
				return nil, err
			}
			for i := start; i <= end; i++ {
				ports = append(ports, i)
			}
			continue
		}
		p, err := strconv.Atoi(t)
		if err != nil {
			return nil, err
		}
		ports = append(ports, p)
	}
	return ports, nil
}
