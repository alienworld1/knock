package main

import (
	"context"
	"crypto/rand"
	"crypto/subtle"
	"embed"
	"encoding/base64"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"io/fs"
	"net"
	"net/http"
	"strings"
	"sync"
	"time"

	"knock/internal/command"

	"github.com/spf13/cobra"
)

//go:embed all:consoleassets
var consoleAssets embed.FS

func (s *settings) consoleCommand() *cobra.Command {
	return &cobra.Command{
		Use: "console", Short: "Open a local operator console", Args: cobra.NoArgs,
		RunE: func(cmd *cobra.Command, _ []string) error {
			assets, err := fs.Sub(consoleAssets, "consoleassets/dist")
			if err != nil {
				return command.Exit(8, err)
			}
			if _, err := fs.Stat(assets, "index.html"); err != nil {
				return command.Exit(2, errors.New("build the console with make build"))
			}
			if _, err := s.registry(); err != nil {
				return command.Exit(2, err)
			}
			keys, err := command.Unlock(command.Profile(s.home, s.profile), "Operator passphrase")
			if err != nil {
				return command.Exit(8, err)
			}
			defer keys.Clear()
			listener, err := net.Listen("tcp4", "127.0.0.1:0")
			if err != nil {
				return command.Exit(8, err)
			}
			defer listener.Close()

			server := newConsoleServer(listener.Addr().String(), assets, (&operatorConsole{settings: s, keys: keys}).routes())
			ctx, cancel := context.WithCancel(cmd.Context())
			defer cancel()
			httpServer := &http.Server{
				Handler: server, ReadHeaderTimeout: 3 * time.Second, ReadTimeout: 8 * time.Second,
				WriteTimeout: 125 * time.Second, IdleTimeout: 30 * time.Second, MaxHeaderBytes: 16 << 10,
				BaseContext: func(net.Listener) context.Context { return ctx },
			}
			launchURL := server.origin + "/#" + server.bootstrap
			result := make(chan error, 1)
			go func() { result <- httpServer.Serve(listener) }()
			fmt.Fprintln(cmd.ErrOrStderr(), "Open this one-time link in your browser. Press Ctrl+C here to close the console.")
			fmt.Fprintln(cmd.OutOrStdout(), launchURL)
			select {
			case err := <-result:
				cancel()
				_ = httpServer.Shutdown(context.Background())
				return command.Exit(8, err)
			case <-ctx.Done():
				// BaseContext cancels in-flight operations before keys are discarded.
				if err := httpServer.Shutdown(context.Background()); err != nil {
					return command.Exit(8, err)
				}
				return nil
			}
		},
	}
}

type consoleServer struct {
	host, origin          string
	bootstrap, cookieName string
	session, csrf         string
	mu                    sync.Mutex
	api                   http.Handler
	files                 http.Handler
}

func newConsoleServer(host string, assets fs.FS, api http.Handler) *consoleServer {
	_, port, _ := net.SplitHostPort(host)
	return &consoleServer{
		host: host, origin: "http://" + host, bootstrap: consoleToken(), cookieName: "knock_" + port,
		session: consoleToken(), csrf: consoleToken(), api: api, files: http.FileServerFS(assets),
	}
}

func consoleToken() string {
	key := make([]byte, 32)
	rand.Read(key)
	return base64.RawURLEncoding.EncodeToString(key)
}

func tokenMatches(a, b string) bool {
	return b != "" && subtle.ConstantTimeCompare([]byte(a), []byte(b)) == 1
}

func (s *consoleServer) ServeHTTP(w http.ResponseWriter, r *http.Request) {
	w.Header().Set("Cache-Control", "no-store")
	w.Header().Set("Content-Security-Policy", "default-src 'none'; script-src 'self'; style-src 'self'; img-src 'self'; font-src 'self'; connect-src 'self'; base-uri 'none'; frame-ancestors 'none'; form-action 'none'; object-src 'none'")
	w.Header().Set("Referrer-Policy", "no-referrer")
	w.Header().Set("X-Content-Type-Options", "nosniff")
	w.Header().Set("X-Frame-Options", "DENY")
	if r.Host != s.host {
		consoleError(w, http.StatusForbidden, "Unrecognized console address.")
		return
	}
	if !strings.HasPrefix(r.URL.Path, "/api/") {
		if r.Method != http.MethodGet {
			http.NotFound(w, r)
			return
		}
		switch r.URL.Path {
		case "/", "/sessions", "/history":
			page := r.Clone(r.Context())
			page.URL.Path = "/"
			s.files.ServeHTTP(w, page)
		default:
			if strings.HasPrefix(r.URL.Path, "/assets/") {
				s.files.ServeHTTP(w, r)
			} else {
				http.NotFound(w, r)
			}
		}
		return
	}
	origin := r.Header.Values("Origin")
	site := r.Header.Get("Sec-Fetch-Site")
	if len(origin) > 1 || (len(origin) == 1 && origin[0] != s.origin) ||
		(site != "" && site != "same-origin") ||
		(r.Method != http.MethodGet && len(origin) != 1) || r.Header.Get("X-Knock-Console") != "1" {
		consoleError(w, http.StatusForbidden, "Request blocked by console security.")
		return
	}
	if r.URL.Path == "/api/bootstrap" && r.Method == http.MethodPost {
		s.exchange(w, r)
		return
	}
	cookies := r.CookiesNamed(s.cookieName)
	if len(cookies) != 1 || !tokenMatches(cookies[0].Value, s.session) {
		consoleError(w, http.StatusUnauthorized, "Console session unavailable. Start knock console again.")
		return
	}
	if r.Method != http.MethodGet && !tokenMatches(r.Header.Get("X-Knock-CSRF"), s.csrf) {
		consoleError(w, http.StatusForbidden, "Request blocked by console security.")
		return
	}
	if r.URL.Path == "/api/session" && r.Method == http.MethodGet {
		consoleJSON(w, http.StatusOK, map[string]string{"csrf": s.csrf})
		return
	}
	s.api.ServeHTTP(w, r)
}

func (s *consoleServer) exchange(w http.ResponseWriter, r *http.Request) {
	var body struct {
		Token string `json:"token"`
	}
	if !consoleBody(w, r, &body) {
		return
	}
	s.mu.Lock()
	defer s.mu.Unlock()
	if !tokenMatches(body.Token, s.bootstrap) {
		consoleError(w, http.StatusUnauthorized, "This link has expired. Start knock console again.")
		return
	}
	s.bootstrap = ""
	http.SetCookie(w, &http.Cookie{
		Name: s.cookieName, Value: s.session, Path: "/api/", HttpOnly: true, Secure: true, SameSite: http.SameSiteStrictMode,
	})
	consoleJSON(w, http.StatusOK, map[string]string{"csrf": s.csrf})
}

func consoleBody(w http.ResponseWriter, r *http.Request, dst any) bool {
	if r.Header.Get("Content-Type") != "application/json" {
		consoleError(w, http.StatusUnsupportedMediaType, "Expected JSON.")
		return false
	}
	r.Body = http.MaxBytesReader(w, r.Body, 8192)
	decoder := json.NewDecoder(r.Body)
	decoder.DisallowUnknownFields()
	if decoder.Decode(dst) != nil || decoder.Decode(new(any)) != io.EOF {
		consoleError(w, http.StatusBadRequest, "Invalid request.")
		return false
	}
	return true
}

func consoleJSON(w http.ResponseWriter, status int, value any) {
	w.Header().Set("Content-Type", "application/json")
	w.WriteHeader(status)
	_ = json.NewEncoder(w).Encode(value)
}

func consoleError(w http.ResponseWriter, status int, message string) {
	consoleJSON(w, status, map[string]string{"error": message})
}
