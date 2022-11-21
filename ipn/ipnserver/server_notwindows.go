// Copyright (c) 2022 Tailscale Inc & AUTHORS All rights reserved.
// Use of this source code is governed by a BSD-style
// license that can be found in the LICENSE file.

//go:build !windows

package ipnserver

import (
	"net"

	"inet.af/peercred"
)

// getConnIdentity extracts the identity information from the connection
// based on the user who owns the other end of the connection.
// and couldn't. The returned connIdentity has NotWindows set to true.
func (s *Server) getConnIdentity(c net.Conn) (ci connIdentity, err error) {
	ci = connIdentity{Conn: c, NotWindows: true}
	ci.NotWindows = true
	_, ci.IsUnixSock = c.(*net.UnixConn)
	ci.Creds, _ = peercred.Get(c)
	return ci, nil
}
