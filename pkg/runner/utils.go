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
	"errors"
	"fmt"
	"io/fs"
	"os"
	"strconv"
	"strings"

	"github.com/praetorian-inc/fingerprintx/pkg/plugins"
	"golang.org/x/term"
)

func checkOutputFile(path string) error {
	if _, err := os.Stat(path); err != nil {
		if errors.Is(err, fs.ErrNotExist) {
			return nil
		}
		return fmt.Errorf("failed to check output file %q: %v", path, err)
	}

	// Refrain from prompting for input in case stdin is connected to
	// a pipe / non-tty file.
	if term.IsTerminal(int(os.Stdin.Fd())) {
		fmt.Fprintf(os.Stderr, "File: %q already exists. Overwrite? (Y/n): ", path)
		var input string
		fmt.Scanln(&input)
		input = strings.ToLower(strings.TrimSpace(input))
		if input == "" || input == "y" || input == "yes" {
			return nil
		}
	}
	return fmt.Errorf("output file %q already exists", path)
}

func isPriorityPort(port int) bool {
	protocols := []plugins.Protocol{plugins.UDP, plugins.TCP, plugins.TCPTLS}
	for _, protocol := range protocols {
		if pluginList, exists := plugins.Plugins[protocol]; exists {
			for _, plugin := range pluginList {
				if plugin.PortPriority(uint16(port)) {
					return true
				}
			}
		}
	}
	return false
}

func DefaultPortRange() string {
	priorityPorts := make([]string, 0)
	var port int
	for port = 1; port <= 65535; port++ {
		if isPriorityPort(port) {
			priorityPorts = append(priorityPorts, strconv.Itoa(port))
		}
	}
	return strings.Join(priorityPorts, ",")
}
