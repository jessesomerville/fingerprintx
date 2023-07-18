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
	"fmt"
	"net"
	"net/netip"
	"strconv"

	"github.com/praetorian-inc/fingerprintx/pkg/plugins"
)

func parseTarget(inputTarget string) (plugins.Target, error) {
	var t plugins.Target

	ap, err := netip.ParseAddrPort(inputTarget)
	if err == nil {
		t.Address = ap
		return t, nil
	}

	host, port, err := net.SplitHostPort(inputTarget)
	if err != nil {
		return t, fmt.Errorf("invalid target %q: %v", inputTarget, err)
	}
	port16, err := strconv.ParseUint(port, 10, 16)
	if err != nil {
		return t, fmt.Errorf("invalid port number %q: %v", port, err)
	}
	addrs, err := net.LookupIP(host)
	if err != nil {
		return t, fmt.Errorf("failed to resolve IP target %q: %v", host, err)
	}
	ip, ok := netip.AddrFromSlice(addrs[0])
	if !ok {
		return t, fmt.Errorf("invalid target %q", inputTarget)
	}
	t.Address = netip.AddrPortFrom(ip, uint16(port16))
	t.Host = host
	return t, nil
}
