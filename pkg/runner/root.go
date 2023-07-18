// Copyright 2022 Praetorian Security, Inc.
//
// Licensed under the Apache License, Version 2.0 (the "License");
// you may not use this file except in compliance with the License.
// You may obtain a copy of the License at
//
//      http://www.apache.org/licenses/LICENSE-2.0
//
// Unless required by applicable law or agreed to in writing, software
// distributed under the License is distributed on an "AS IS" BASIS,
// WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
// See the License for the specific language governing permissions and
// limitations under the License.

package runner

import (
	"os"

	"github.com/spf13/cobra"
)

var rootCmd = new(cli)

func init() {
	rootCmd.Command = &cobra.Command{
		Use:               "fingerprintx",
		CompletionOptions: cobra.CompletionOptions{DisableDefaultCmd: true},
		PreRunE:           rootCmd.initScanConfig,
		RunE:              rootCmd.scanTargets,
		Long: `
TARGET SPECIFICATION:
	Requires a host and port number or ip and port number. The port is assumed to be open.
	HOST:PORT or IP:PORT`,
		Example: `
  fingerprintx -t praetorian.com:80
  fingerprintx -l input-file.txt
  fingerprintx --json -t praetorian.com:80,127.0.0.1:8000`,
	}

	rootCmd.Flags().StringVarP(&rootCmd.inputFile, "list", "l", "", "input file containing targets")
	rootCmd.Flags().StringSliceVarP(&rootCmd.targets, "targets", "t", nil, "target or comma separated target list")

	rootCmd.Flags().BoolVarP(&rootCmd.scancfg.FastMode, "fast", "f", false, "fast mode")
	rootCmd.Flags().BoolVarP(&rootCmd.scancfg.UDP, "udp", "U", false, "run UDP plugins")
	rootCmd.Flags().BoolVarP(&rootCmd.scancfg.Verbose, "verbose", "v", false, "verbose mode")
	rootCmd.Flags().IntVarP(&rootCmd.timeout, "timeout", "w", 2000, "timeout (milliseconds)")

	rootCmd.Flags().StringVarP(&rootCmd.outputFile, "output", "o", "", "output file")
	rootCmd.Flags().BoolVarP(&rootCmd.outputJSON, "json", "", false, "output format in json")
	rootCmd.Flags().BoolVarP(&rootCmd.outputCSV, "csv", "", false, "output format in csv")

	rootCmd.MarkFlagsMutuallyExclusive("json", "csv")
	rootCmd.MarkFlagsMutuallyExclusive("targets", "list")
}

func Execute() {
	if err := rootCmd.Execute(); err != nil {
		os.Exit(1)
	}
}
