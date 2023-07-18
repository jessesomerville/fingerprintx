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
	"encoding/csv"
	"encoding/json"
	"fmt"
	"io"
	"os"
	"strconv"

	"github.com/praetorian-inc/fingerprintx/pkg/plugins"
)

type formatter interface {
	WriteService(plugins.Service) error
}

type jsonFormatter struct {
	*json.Encoder
}

func (j *jsonFormatter) WriteService(svc plugins.Service) error {
	return j.Encode(svc)
}

type csvFormatter struct {
	*csv.Writer
}

func (c *csvFormatter) WriteService(svc plugins.Service) error {
	row := []string{
		svc.Host,
		svc.IP,
		strconv.Itoa(svc.Port),
		svc.Protocol,
		strconv.FormatBool(svc.TLS),
		string(svc.Raw),
	}
	return c.Write(row)
}

type textFormatter struct {
	w io.Writer
}

func (t *textFormatter) WriteService(svc plugins.Service) error {
	fmt.Fprintln(t.w, svc)
	return nil
}

func report(services []plugins.Service) error {
	var out *os.File
	if rootCmd.outputFile != "" {
		f, err := os.Create(rootCmd.outputFile)
		if err != nil {
			return err
		}
		out = f
		defer f.Close()
	} else {
		out = os.Stdout
	}

	var w formatter
	switch {
	case rootCmd.outputJSON:
		w = &jsonFormatter{json.NewEncoder(out)}
	case rootCmd.outputCSV:
		cw := &csvFormatter{csv.NewWriter(out)}
		if err := cw.Write([]string{"Host", "IP", "Port", "Protocol", "TLS", "Data"}); err != nil {
			return err
		}
		defer cw.Flush()
		w = cw
	default:
		w = &textFormatter{w: out}
	}

	for _, service := range services {
		if err := w.WriteService(service); err != nil {
			return err
		}
	}
	return nil
}
