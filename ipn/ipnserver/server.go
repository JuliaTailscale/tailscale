// Copyright (c) 2020 Tailscale Inc & AUTHORS All rights reserved.
// Use of this source code is governed by a BSD-style
// license that can be found in the LICENSE file.

package ipnserver

import (
	"context"
	"errors"
	"fmt"
	"io"
	"net"
	"net/http"
	"os/user"
	"strings"
	"sync"
	"sync/atomic"
	"time"
	"unicode"

	"tailscale.com/envknob"
	"tailscale.com/ipn"
	"tailscale.com/ipn/ipnauth"
	"tailscale.com/ipn/ipnlocal"
	"tailscale.com/ipn/localapi"
	"tailscale.com/types/logger"
	"tailscale.com/util/mak"
	"tailscale.com/util/systemd"
)

// Server is an IPN backend and its set of 0 or more active localhost
// TCP or unix socket connections talking to that backend.
type Server struct {
	lb           atomic.Pointer[ipnlocal.LocalBackend]
	logf         logger.Logf
	backendLogID string
	// resetOnZero is whether to call bs.Reset on transition from
	// 1->0 active HTTP requests. That is, this is whether the backend is
	// being run in "client mode" that requires an active GUI
	// connection (such as on Windows by default). Even if this
	// is true, the ForceDaemon pref can override this.
	resetOnZero bool

	startBackendOnce sync.Once
	runCalled        atomic.Bool

	// mu guards the fields that follow.
	// lock order: mu, then LocalBackend.mu
	mu         sync.Mutex
	lastUserID ipn.WindowsUserID // tracks last userid; on change, Reset state for paranoia
	activeReqs map[*http.Request]*ipnauth.ConnIdentity
}

func (s *Server) mustBackend() *ipnlocal.LocalBackend {
	lb := s.lb.Load()
	if lb == nil {
		panic("unexpected: call to mustBackend in path where SetLocalBackend should've been called")
	}
	return lb
}

func (s *Server) serveHTTP(w http.ResponseWriter, r *http.Request) {
	if r.Method == "CONNECT" {
		if envknob.GOOS() == "windows" {
			// For the GUI client when using an exit node. See docs on handleProxyConnectConn.
			s.handleProxyConnectConn(w, r)
		} else {
			http.Error(w, "bad method for platform", http.StatusMethodNotAllowed)
		}
		return
	}

	// TODO(bradfitz): add a status HTTP handler that returns whether there's a
	// LocalBackend yet, optionally blocking until there is one. See
	// https://github.com/tailscale/tailscale/issues/6522
	lb := s.lb.Load()
	if lb == nil {
		http.Error(w, "no backend", http.StatusServiceUnavailable)
		return
	}

	var ci *ipnauth.ConnIdentity
	switch v := r.Context().Value(connIdentityContextKey{}).(type) {
	case *ipnauth.ConnIdentity:
		ci = v
	case error:
		http.Error(w, v.Error(), http.StatusUnauthorized)
		return
	case nil:
		http.Error(w, "internal error: no connIdentityContextKey", http.StatusInternalServerError)
		return
	}

	onDone, err := s.addActiveHTTPRequest(r, ci)
	if err != nil {
		http.Error(w, err.Error(), http.StatusUnauthorized)
		return
	}
	defer onDone()

	if strings.HasPrefix(r.URL.Path, "/localapi/") {
		lah := localapi.NewHandler(lb, s.logf, s.backendLogID)
		lah.PermitRead, lah.PermitWrite = s.localAPIPermissions(ci)
		lah.PermitCert = s.connCanFetchCerts(ci)
		lah.ServeHTTP(w, r)
		return
	}

	if r.URL.Path != "/" {
		http.NotFound(w, r)
		return
	}

	if envknob.GOOS() == "windows" {
		// TODO(bradfitz): remove this once we moved to named pipes for LocalAPI
		// on Windows. This could then move to all platforms instead at
		// 100.100.100.100 or something (quad100 handler in LocalAPI)
		s.ServeHTMLStatus(w, r)
		return
	}

	io.WriteString(w, "<html><title>Tailscale</title><body><h1>Tailscale</h1>This is the local Tailscale daemon.\n")
}

// inUseOtherUserError is the error type for when the server is in use
// by a different local user.
type inUseOtherUserError struct{ error }

func (e inUseOtherUserError) Unwrap() error { return e.error }

// checkConnIdentityLocked checks whether the provided identity is
// allowed to connect to the server.
//
// The returned error, when non-nil, will be of type inUseOtherUserError.
//
// s.mu must be held.
func (s *Server) checkConnIdentityLocked(ci *ipnauth.ConnIdentity) error {
	// If clients are already connected, verify they're the same user.
	// This mostly matters on Windows at the moment.
	if len(s.activeReqs) > 0 {
		var active *ipnauth.ConnIdentity
		for _, active = range s.activeReqs {
			break
		}
		if active != nil && ci.WindowsUserID() != active.WindowsUserID() {
			return inUseOtherUserError{fmt.Errorf("Tailscale already in use by %s, pid %d", active.User().Username, active.Pid())}
		}
	}
	if err := s.mustBackend().CheckIPNConnectionAllowed(ci); err != nil {
		return inUseOtherUserError{err}
	}
	return nil
}

// localAPIPermissions returns the permissions for the given identity accessing
// the Tailscale local daemon API.
//
// s.mu must not be held.
func (s *Server) localAPIPermissions(ci *ipnauth.ConnIdentity) (read, write bool) {
	switch envknob.GOOS() {
	case "windows":
		s.mu.Lock()
		defer s.mu.Unlock()
		if s.checkConnIdentityLocked(ci) == nil {
			return true, true
		}
		return false, false
	case "js":
		return true, true
	}
	if ci.IsUnixSock() {
		return true, !ci.IsReadonlyConn(s.mustBackend().OperatorUserID(), logger.Discard)
	}
	return false, false
}

// userIDFromString maps from either a numeric user id in string form
// ("998") or username ("caddy") to its string userid ("998").
// It returns the empty string on error.
func userIDFromString(v string) string {
	if v == "" || isAllDigit(v) {
		return v
	}
	u, err := user.Lookup(v)
	if err != nil {
		return ""
	}
	return u.Uid
}

func isAllDigit(s string) bool {
	for i := 0; i < len(s); i++ {
		if b := s[i]; b < '0' || b > '9' {
			return false
		}
	}
	return true
}

// connCanFetchCerts reports whether ci is allowed to fetch HTTPS
// certs from this server when it wouldn't otherwise be able to.
//
// That is, this reports whether ci should grant additional
// capabilities over what the conn would otherwise be able to do.
//
// For now this only returns true on Unix machines when
// TS_PERMIT_CERT_UID is set the to the userid of the peer
// connection. It's intended to give your non-root webserver access
// (www-data, caddy, nginx, etc) to certs.
func (s *Server) connCanFetchCerts(ci *ipnauth.ConnIdentity) bool {
	if ci.IsUnixSock() && ci.Creds() != nil {
		connUID, ok := ci.Creds().UserID()
		if ok && connUID == userIDFromString(envknob.String("TS_PERMIT_CERT_UID")) {
			return true
		}
	}
	return false
}

// addActiveHTTPRequest adds c to the server's list of active HTTP requests.
//
// If the returned error may be of type inUseOtherUserError.
//
// onDone must be called when the HTTP request is done.
func (s *Server) addActiveHTTPRequest(req *http.Request, ci *ipnauth.ConnIdentity) (onDone func(), err error) {
	if ci == nil {
		return nil, errors.New("internal error: nil connIdentity")
	}

	lb := s.mustBackend()

	// If the connected user changes, reset the backend server state to make
	// sure node keys don't leak between users.
	var doReset bool
	defer func() {
		if doReset {
			s.logf("identity changed; resetting server")
			lb.ResetForClientDisconnect()
		}
	}()

	s.mu.Lock()
	defer s.mu.Unlock()

	if err := s.checkConnIdentityLocked(ci); err != nil {
		return nil, err
	}

	mak.Set(&s.activeReqs, req, ci)

	if uid := ci.WindowsUserID(); uid != "" && len(s.activeReqs) == 1 {
		// Tell the LocalBackend about the identity we're now running as.
		lb.SetCurrentUserID(uid)
		if s.lastUserID != uid {
			if s.lastUserID != "" {
				doReset = true
			}
			s.lastUserID = uid
		}
	}

	onDone = func() {
		s.mu.Lock()
		delete(s.activeReqs, req)
		remain := len(s.activeReqs)
		s.mu.Unlock()

		if remain == 0 && s.resetOnZero {
			if lb.InServerMode() {
				s.logf("client disconnected; staying alive in server mode")
			} else {
				s.logf("client disconnected; stopping server")
				lb.ResetForClientDisconnect()
			}
		}
	}

	return onDone, nil
}

// New returns a new Server.
//
// To start it, use the Server.Run method.
//
// At some point, either before or after Run, the Server's SetLocalBackend
// method must also be called before Server can do anything useful.
func New(logf logger.Logf, logid string) *Server {
	return &Server{
		backendLogID: logid,
		logf:         logf,
		resetOnZero:  envknob.GOOS() == "windows",
	}
}

// SetLocalBackend sets the server's LocalBackend.
//
// If b.Run has already been called, then lb.Start will be called.
// Otherwise Start will be called once Run is called.
func (s *Server) SetLocalBackend(lb *ipnlocal.LocalBackend) {
	if lb == nil {
		panic("nil LocalBackend")
	}
	if !s.lb.CompareAndSwap(nil, lb) {
		panic("already set")
	}
	s.startBackendIfNeeded()
	// TODO(bradfitz): send status update to GUI long poller waiter. See
	// https://github.com/tailscale/tailscale/issues/6522
}

func (b *Server) startBackendIfNeeded() {
	if !b.runCalled.Load() {
		return
	}
	lb := b.lb.Load()
	if lb == nil {
		return
	}
	if lb.Prefs().Valid() {
		b.startBackendOnce.Do(func() {
			lb.Start(ipn.Options{})
		})
	}
}

// connIdentityContextKey is the http.Request.Context's context.Value key for either an
// *ipnauth.ConnIdentity or an error.
type connIdentityContextKey struct{}

// Run runs the server, accepting connections from ln forever.
//
// If the context is done, the listener is closed. It is also the base context
// of all HTTP requests.
//
// If the Server's LocalBackend has already been set, Run starts it.
// Otherwise, the next call to SetLocalBackend will start it.
func (s *Server) Run(ctx context.Context, ln net.Listener) error {
	s.runCalled.Store(true)
	defer func() {
		if lb := s.lb.Load(); lb != nil {
			lb.Shutdown()
		}
	}()

	runDone := make(chan struct{})
	defer close(runDone)

	// When the context is closed or when we return, whichever is first, close our listener
	// and all open connections.
	go func() {
		select {
		case <-ctx.Done():
		case <-runDone:
		}
		ln.Close()
	}()

	s.startBackendIfNeeded()
	systemd.Ready()

	hs := &http.Server{
		Handler:     http.HandlerFunc(s.serveHTTP),
		BaseContext: func(_ net.Listener) context.Context { return ctx },
		ConnContext: func(ctx context.Context, c net.Conn) context.Context {
			ci, err := ipnauth.GetConnIdentity(s.logf, c)
			if err != nil {
				return context.WithValue(ctx, connIdentityContextKey{}, err)
			}
			return context.WithValue(ctx, connIdentityContextKey{}, ci)
		},
		// Localhost connections are cheap; so only do
		// keep-alives for a short period of time, as these
		// active connections lock the server into only serving
		// that user. If the user has this page open, we don't
		// want another switching user to be locked out for
		// minutes. 5 seconds is enough to let browser hit
		// favicon.ico and such.
		IdleTimeout: 5 * time.Second,
		ErrorLog:    logger.StdLogger(logger.WithPrefix(s.logf, "ipnserver: ")),
	}
	if err := hs.Serve(ln); err != nil {
		if err := ctx.Err(); err != nil {
			return err
		}
	}
	return nil
}

// ServeHTMLStatus serves an HTML status page at http://localhost:41112/ for
// Windows and via $DEBUG_LISTENER/debug/ipn when tailscaled's --debug flag
// is used to run a debug server.
func (s *Server) ServeHTMLStatus(w http.ResponseWriter, r *http.Request) {
	lb := s.lb.Load()
	if lb == nil {
		http.Error(w, "no LocalBackend", http.StatusServiceUnavailable)
		return
	}

	// As this is only meant for debug, verify there's no DNS name being used to
	// access this.
	if !strings.HasPrefix(r.Host, "localhost:") && strings.IndexFunc(r.Host, unicode.IsLetter) != -1 {
		http.Error(w, "invalid host", http.StatusForbidden)
		return
	}

	w.Header().Set("Content-Security-Policy", `default-src 'none'; frame-ancestors 'none'; script-src 'none'; script-src-elem 'none'; script-src-attr 'none'`)
	w.Header().Set("X-Frame-Options", "DENY")
	w.Header().Set("X-Content-Type-Options", "nosniff")
	w.Header().Set("Content-Type", "text/html; charset=utf-8")
	st := lb.Status()
	// TODO(bradfitz): add LogID and opts to st?
	st.WriteHTML(w)
}
