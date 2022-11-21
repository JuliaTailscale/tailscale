// Copyright (c) 2022 Tailscale Inc & AUTHORS All rights reserved.
// Use of this source code is governed by a BSD-style
// license that can be found in the LICENSE file.

package ipnserver

import (
	"fmt"
	"net"
	"syscall"
	"unsafe"

	"golang.org/x/sys/windows"
	"tailscale.com/util/pidowner"
)

var (
	kernel32                        = syscall.NewLazyDLL("kernel32.dll")
	procGetNamedPipeClientProcessId = kernel32.NewProc("GetNamedPipeClientProcessId")
)

func getNamedPipeClientProcessId(h windows.Handle) (pid uint32, err error) {
	r1, _, err := procGetNamedPipeClientProcessId.Call(uintptr(h), uintptr(unsafe.Pointer(&pid)))
	if r1 > 0 {
		return pid, nil
	}
	return 0, err
}

// getConnIdentity extracts the identity information from the connection
// based on the user who owns the other end of the connection.
// If c is not backed by a named pipe, an error is returned.
func (s *Server) getConnIdentity(c net.Conn) (ci connIdentity, err error) {
	ci = connIdentity{Conn: c}
	h, ok := c.(interface {
		Handle() windows.Handle
	})
	if !ok {
		return ci, fmt.Errorf("not a windows handle: %T", c)
	}
	pid, err := getNamedPipeClientProcessId(h.Handle())
	if err != nil {
		return ci, fmt.Errorf("getNamedPipeClientProcessId: %v", err)
	}
	ci.Pid = int(pid)
	uid, err := pidowner.OwnerOfPID(ci.Pid)
	if err != nil {
		return ci, fmt.Errorf("failed to map connection's pid to a user (WSL?): %w", err)
	}
	ci.UserID = uid
	u, err := lookupUserFromID(s.logf, uid)
	if err != nil {
		return ci, fmt.Errorf("failed to look up user from userid: %w", err)
	}
	ci.User = u
	return ci, nil
}
