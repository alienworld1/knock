package lease

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net"
	"net/http"
	"strconv"
	"sync"
	"time"
)

func startHTTP(ctx context.Context, grant Grant, assigned slot) error {
	remaining := time.Until(grant.Deadline).Microseconds()
	if remaining <= 0 {
		return errors.New("the session deadline passed during provisioning")
	}
	if err := run(ctx, systemdRunPath, "--quiet", "--unit="+unit(grant.ID), "--collect", "--service-type=exec",
		fmt.Sprintf("--property=RuntimeMaxSec=%dus", remaining),
		"--property=KillMode=control-group", "--property=KillSignal=SIGKILL", "--property=TimeoutStopSec=1s",
		"--property=DynamicUser=yes", "--property=NoNewPrivileges=yes", "--property=ProtectSystem=strict",
		"--property=ProtectHome=yes", "--property=PrivateTmp=yes", "--property=TasksMax=32", "--property=LimitCORE=0",
		daemonPath, "private-http", strconv.Itoa(int(assigned))); err != nil {
		return err
	}
	return waitListener(ctx, assigned)
}

func (s slot) httpAddress() string { return net.JoinHostPort(ServerIP, strconv.Itoa(s.port())) }

func connectHTTP(ctx context.Context, assigned slot, streams Streams) error {
	dialer := net.Dialer{LocalAddr: &net.TCPAddr{IP: net.ParseIP(assigned.clientIP())}}
	transport := &http.Transport{DialContext: dialer.DialContext, DisableKeepAlives: true}
	defer transport.CloseIdleConnections()
	client := http.Client{Transport: transport, Timeout: 2 * time.Second, CheckRedirect: func(*http.Request, []*http.Request) error {
		return http.ErrUseLastResponse
	}}
	url := "http://" + assigned.httpAddress() + "/status"
	ticker := time.NewTicker(2 * time.Second)
	defer ticker.Stop()
	var connected bool
	disconnected := func() error {
		if !connected {
			return errors.New("couldn't verify a request to the private service")
		}
		fmt.Fprintln(streams.Err, "Disconnected.")
		return nil
	}
	failures := 0
	for {
		request, err := http.NewRequestWithContext(ctx, http.MethodGet, url, nil)
		if err != nil {
			return err
		}
		response, err := client.Do(request)
		if err == nil {
			var status struct{ Status string }
			err = json.NewDecoder(io.LimitReader(response.Body, 1024)).Decode(&status)
			response.Body.Close()
			if err == nil && response.StatusCode == http.StatusOK && status.Status == "ok" {
				failures = 0
				if !connected {
					fmt.Fprintln(streams.Err, "Connected. Press Ctrl+C to disconnect.")
					fmt.Fprintln(streams.Out, url)
					connected = true
					if streams.OnConnected != nil {
						streams.OnConnected()
					}
				}
			} else {
				failures++
			}
		} else {
			failures++
		}
		if ctx.Err() != nil {
			return disconnected()
		}
		if failures == 3 {
			if !connected {
				return errors.New("couldn't verify a request to the private service")
			}
			return errors.New("private service connection ended")
		}
		select {
		case <-ctx.Done():
			return disconnected()
		case <-ticker.C:
		}
	}
}

// ServeHTTP runs a fixed, read-only status resource for a single protected slot.
func ServeHTTP(value string, evidence io.Writer) error {
	number, err := strconv.ParseUint(value, 10, 8)
	assigned := slot(number)
	if err != nil || !assigned.valid() {
		return errors.New("invalid private HTTP slot")
	}
	var first sync.Once
	server := http.Server{
		Addr: assigned.httpAddress(), ReadHeaderTimeout: 2 * time.Second, ReadTimeout: 3 * time.Second,
		WriteTimeout: 3 * time.Second, MaxHeaderBytes: 4096,
		Handler: http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			source, _, err := net.SplitHostPort(r.RemoteAddr)
			if err != nil || source != assigned.clientIP() || r.Host != assigned.httpAddress() ||
				r.Method != http.MethodGet || r.RequestURI != "/status" {
				http.NotFound(w, r)
				return
			}
			w.Header().Set("Content-Type", "application/json")
			w.Header().Set("Cache-Control", "no-store")
			if err := json.NewEncoder(w).Encode(struct {
				Status string    `json:"status"`
				Time   time.Time `json:"time"`
			}{"ok", time.Now().UTC()}); err == nil {
				first.Do(func() { fmt.Fprintln(evidence, "Served private HTTP request from "+source) })
			}
		}),
	}
	server.SetKeepAlivesEnabled(false)
	return server.ListenAndServe()
}
