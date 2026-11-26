package main

import (
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"strings"
	"sync"
	"testing"
	"testing/fstest"
)

func testConsole() *consoleServer {
	files := fstest.MapFS{
		"index.html":  {Data: []byte("<main>Knock</main>")},
		"favicon.svg": {Data: []byte("<svg xmlns=\"http://www.w3.org/2000/svg\"></svg>")},
	}
	return newConsoleServer("127.0.0.1:12345", files, http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		w.WriteHeader(http.StatusNoContent)
	}))
}

func consoleRequest(s *consoleServer, method, path, body string) *http.Request {
	r := httptest.NewRequest(method, s.origin+path, strings.NewReader(body))
	r.Header.Set("X-Knock-Console", "1")
	if method == http.MethodPost {
		r.Header.Set("Origin", s.origin)
		r.Header.Set("Content-Type", "application/json")
	}
	return r
}

func TestConsoleBootstrapExchangesOnce(t *testing.T) {
	server := testConsole()
	token := server.bootstrap
	var group sync.WaitGroup
	responses := make(chan *httptest.ResponseRecorder, 4)
	for range cap(responses) {
		group.Go(func() {
			w := httptest.NewRecorder()
			server.ServeHTTP(w, consoleRequest(server, "POST", "/api/bootstrap", `{"token":"`+token+`"}`))
			responses <- w
		})
	}
	group.Wait()
	close(responses)
	success := 0
	for w := range responses {
		if w.Code == http.StatusUnauthorized {
			continue
		}
		if w.Code != http.StatusOK {
			t.Fatalf("bootstrap status %d", w.Code)
		}
		success++
		cookies := w.Result().Cookies()
		if len(cookies) != 1 || !cookies[0].HttpOnly || !cookies[0].Secure ||
			cookies[0].SameSite != http.SameSiteStrictMode || cookies[0].Path != "/api/" || cookies[0].Domain != "" {
			t.Fatal("bootstrap did not set a host-only secure session cookie")
		}
		var data map[string]string
		if json.Unmarshal(w.Body.Bytes(), &data) != nil || len(data) != 1 || data["csrf"] != server.csrf {
			t.Fatal("unexpected bootstrap response")
		}
	}
	if success != 1 {
		t.Fatalf("%d clients redeemed one link", success)
	}
}

func TestConsoleRejectsUnsafeRequests(t *testing.T) {
	server := testConsole()
	for _, tc := range []struct {
		name, method, path string
		edit               func(*http.Request)
		status             int
	}{
		{"rebound Host", "GET", "/api/doors", func(r *http.Request) { r.Host = "evil.test:12345" }, 403},
		{"wrong Origin", "POST", "/api/bootstrap", func(r *http.Request) { r.Header.Set("Origin", "http://127.0.0.1:1") }, 403},
		{"same-site other port", "GET", "/api/doors", func(r *http.Request) { r.Header.Set("Sec-Fetch-Site", "same-site") }, 403},
		{"cross-origin preflight", "OPTIONS", "/api/rotation", func(r *http.Request) { r.Header.Set("Origin", "https://evil.test") }, 403},
		{"missing header", "GET", "/api/session", func(r *http.Request) { r.Header.Del("X-Knock-Console") }, 403},
		{"missing Origin", "POST", "/api/decision", func(r *http.Request) { r.Header.Del("Origin") }, 403},
		{"multiple Origins", "POST", "/api/decision", func(r *http.Request) { r.Header.Add("Origin", server.origin) }, 403},
		{"missing CSRF", "POST", "/api/decision", func(r *http.Request) { r.Header.Del("X-Knock-CSRF") }, 403},
		{"wrong CSRF", "POST", "/api/decision", func(r *http.Request) { r.Header.Set("X-Knock-CSRF", "invalid") }, 403},
		{"missing cookie", "GET", "/api/doors", func(r *http.Request) { r.Header.Del("Cookie") }, 401},
		{"duplicate cookie", "GET", "/api/doors", func(r *http.Request) { r.AddCookie(&http.Cookie{Name: server.cookieName, Value: server.session}) }, 401},
		{"valid session", "POST", "/api/decision", func(*http.Request) {}, 204},
		{"direct History route", "GET", "/history", func(*http.Request) {}, 200},
		{"favicon asset", "GET", "/favicon.svg", func(*http.Request) {}, 200},
	} {
		t.Run(tc.name, func(t *testing.T) {
			r := consoleRequest(server, tc.method, tc.path, "{}")
			r.AddCookie(&http.Cookie{Name: server.cookieName, Value: server.session})
			r.Header.Set("X-Knock-CSRF", server.csrf)
			tc.edit(r)
			w := httptest.NewRecorder()
			server.ServeHTTP(w, r)
			headers := w.Result().Header
			if w.Code != tc.status || headers.Get("Access-Control-Allow-Origin") != "" || headers.Get("Cache-Control") != "no-store" ||
				!strings.Contains(headers.Get("Content-Security-Policy"), "frame-ancestors 'none'") {
				t.Fatalf("status %d, headers %v", w.Code, headers)
			}
		})
	}
}
