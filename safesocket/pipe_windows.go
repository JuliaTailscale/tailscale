// Copyright (c) 2020 Tailscale Inc & AUTHORS All rights reserved.
// Use of this source code is governed by a BSD-style
// license that can be found in the LICENSE file.

package safesocket

import (
	"fmt"
	"net"
	"syscall"
	"time"
	"unsafe"

	"golang.org/x/sys/windows"
	"golang.zx2c4.com/wireguard/ipc/namedpipe"
)

func connect(s *ConnectionStrategy) (net.Conn, error) {
	return namedpipe.DialTimeout(s.path, time.Second)
}

func setFlags(network, address string, c syscall.RawConn) error {
	return c.Control(func(fd uintptr) {
		syscall.SetsockoptInt(syscall.Handle(fd), syscall.SOL_SOCKET,
			syscall.SO_REUSEADDR, 1)
	})
}

func listen(path string, port uint16) (_ net.Listener, gotPort uint16, _ error) {
	// Construct the default named pipe security descriptor.
	var acl *windows.ACL
	if err := windows.RtlDefaultNpAcl(&acl); err != nil {
		return nil, 0, err
	}
	defer windows.LocalFree(windows.Handle(unsafe.Pointer(acl)))
	sd, err := windows.NewSecurityDescriptor()
	if err != nil {
		return nil, 0, err
	}

	allUsers, err := windows.CreateWellKnownSid(windows.WinBuiltinUsersSid)
	if err != nil {
		return nil, 0, err
	}
	ea := windows.EXPLICIT_ACCESS{
		AccessPermissions: windows.GENERIC_READ | windows.GENERIC_WRITE,
		AccessMode:        windows.SET_ACCESS,
		Trustee: windows.TRUSTEE{
			TrusteeType:  windows.TRUSTEE_IS_WELL_KNOWN_GROUP,
			TrusteeValue: windows.TrusteeValueFromSID(allUsers),
		},
	}
	acl, err = windows.ACLFromEntries([]windows.EXPLICIT_ACCESS{ea}, acl)
	if err != nil {
		return nil, 0, err
	}

	if err = sd.SetDACL(acl, true, false); err != nil {
		return nil, 0, err
	}
	cfg := namedpipe.ListenConfig{
		SecurityDescriptor: sd,
		InputBufferSize:    256 * 1024,
		OutputBufferSize:   256 * 1024,
	}
	lc, err := cfg.Listen(path)
	if err != nil {
		return nil, 0, fmt.Errorf("namedpipe.Listen: %w", err)
	}
	return lc, 0, nil
}
