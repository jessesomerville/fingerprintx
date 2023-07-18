package runner

import (
	"bufio"
	"fmt"
	"os"
	"os/user"
	"runtime"
	"time"

	"github.com/praetorian-inc/fingerprintx/pkg/plugins"
	"github.com/praetorian-inc/fingerprintx/pkg/scan"
	"github.com/spf13/cobra"
)

type cli struct {
	*cobra.Command

	inputFile  string
	targets    []string
	timeout    int
	outputFile string
	outputJSON bool
	outputCSV  bool
	scancfg    scan.Config
}

func (c *cli) initScanConfig(_ *cobra.Command, _ []string) error {
	c.scancfg.DefaultTimeout = time.Duration(c.timeout) * time.Millisecond

	if c.outputFile != "" {
		if err := checkOutputFile(c.outputFile); err != nil {
			return err
		}
	}

	if (c.scancfg.UDP && c.scancfg.Verbose) && (runtime.GOOS == "linux" || runtime.GOOS == "darwin") {
		user, err := user.Current()
		if err != nil {
			return fmt.Errorf("Failed to retrieve current user (error: %w)", err)
		}
		if user.Uid != "0" {
			fmt.Fprintln(os.Stderr, "Note: UDP Scan may require root privileges")
		}
	}
	return nil
}

func (c *cli) scanTargets(_ *cobra.Command, _ []string) error {
	targetsList, err := c.parseTargets()
	if err != nil {
		return err
	}
	results, err := scan.ScanTargets(targetsList, c.scancfg)
	if err != nil {
		return fmt.Errorf("Failed running ScanTargets (%w)", err)
	}
	if err := report(results); err != nil {
		return fmt.Errorf("Failed reporting results (%w)", err)
	}
	return nil
}

func (c *cli) parseTargets() ([]plugins.Target, error) {
	if len(c.targets) == 0 {
		var f *os.File
		if c.inputFile != "" {
			var err error
			f, err = os.Open(c.inputFile)
			if err != nil {
				return nil, err
			}
			defer f.Close()
		} else {
			fmt.Fprintln(os.Stderr, "Reading targets from stdin")
			f = os.Stdin
		}

		scanner := bufio.NewScanner(f)
		for scanner.Scan() {
			c.targets = append(c.targets, scanner.Text())
		}
		if err := scanner.Err(); err != nil {
			return nil, err
		}
	}

	var scanTargets []plugins.Target
	for _, t := range c.targets {
		target, err := parseTarget(t)
		if err != nil {
			if rootCmd.scancfg.Verbose {
				fmt.Fprintln(os.Stderr, err)
			}
			continue
		}
		scanTargets = append(scanTargets, target)
	}
	return scanTargets, nil
}
