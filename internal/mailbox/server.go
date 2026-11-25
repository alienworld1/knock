package mailbox

import (
	"context"
	"crypto/rand"
	"crypto/sha256"
	"encoding/base64"
	"encoding/json"
	"errors"
	"net"
	"net/http"
	"strings"
	"sync"
	"time"

	"knock/internal/door"
	"knock/internal/protocol"

	"github.com/ethereum/go-ethereum/common"
	qoreseal "github.com/qorechain/qoreseal/go"
	bolt "go.etcd.io/bbolt"
)

type Registry interface {
	Head(context.Context) (uint64, error)
	SigningKey(context.Context, string) ([]byte, error)
	Recipient(context.Context, qoreseal.RecipientCard, string) (qoreseal.SealRecipient, error)
}

type authSession struct {
	account string
	expires int64
}

type quota struct {
	minute int64
	count  int
}

type Server struct {
	db       *bolt.DB
	registry Registry
	origin   string
	mux      *http.ServeMux

	mu         sync.Mutex
	challenges map[common.Hash]Challenge
	sessions   map[common.Hash]authSession
	quotas     map[string]quota
}

func NewServer(db *bolt.DB, registry Registry, origin string) (*Server, error) {
	origin, err := protocol.Origin(origin)
	if err != nil {
		return nil, err
	}
	s := &Server{
		db: db, registry: registry, origin: origin, mux: http.NewServeMux(),
		challenges: make(map[common.Hash]Challenge), sessions: make(map[common.Hash]authSession),
		quotas: make(map[string]quota),
	}
	if err := db.Update(func(tx *bolt.Tx) error {
		for _, name := range [][]byte{queueBucket, cardBucket} {
			if _, err := tx.CreateBucketIfNotExists(name); err != nil {
				return err
			}
		}
		return nil
	}); err != nil {
		return nil, err
	}
	if err := s.prune(time.Now().Unix()); err != nil {
		return nil, err
	}
	s.mux.HandleFunc("GET /healthz", func(w http.ResponseWriter, _ *http.Request) {
		w.WriteHeader(http.StatusNoContent)
	})
	s.mux.HandleFunc("POST /v1/auth/challenge", s.challenge)
	s.mux.HandleFunc("POST /v1/auth/session", s.login)
	s.mux.HandleFunc("POST /v1/messages", s.authenticated(s.postMessage))
	s.mux.HandleFunc("GET /v1/inbox", s.authenticated(s.getInbox))
	s.mux.HandleFunc("POST /v1/messages/{id}/ack", s.authenticated(s.postAck))
	s.mux.HandleFunc("GET /v1/cards/{account}", s.getCard)
	s.mux.HandleFunc("PUT /v1/cards/{account}", s.authenticated(s.putCard))
	return s, nil
}

func (s *Server) Maintain(ctx context.Context) error {
	ticker := time.NewTicker(20 * time.Second)
	defer ticker.Stop()
	for {
		select {
		case <-ctx.Done():
			return nil
		case now := <-ticker.C:
			if err := s.prune(now.Unix()); err != nil {
				return err
			}
			s.mu.Lock()
			for nonce, c := range s.challenges {
				if c.Expires <= now.Unix() {
					delete(s.challenges, nonce)
				}
			}
			for token, session := range s.sessions {
				if session.expires <= now.Unix() {
					delete(s.sessions, token)
				}
			}
			for key, quota := range s.quotas {
				if quota.minute < now.Unix()/60 {
					delete(s.quotas, key)
				}
			}
			s.mu.Unlock()
		}
	}
}

func (s *Server) ServeHTTP(w http.ResponseWriter, r *http.Request) {
	w.Header().Set("Cache-Control", "no-store")
	w.Header().Set("X-Content-Type-Options", "nosniff")
	ip, _, _ := net.SplitHostPort(r.RemoteAddr)
	if !s.withinQuota("ip/"+ip, 600) {
		http.Error(w, "Mailbox rate limit", http.StatusTooManyRequests)
		return
	}
	s.mux.ServeHTTP(w, r)
}

func (s *Server) withinQuota(key string, maximum int) bool {
	minute := time.Now().Unix() / 60
	s.mu.Lock()
	defer s.mu.Unlock()
	q, exists := s.quotas[key]
	if !exists && len(s.quotas) >= 2048 {
		return false
	}
	if q.minute != minute {
		q = quota{minute: minute}
	}
	if q.count >= maximum {
		return false
	}
	q.count++
	s.quotas[key] = q
	return true
}

func read(w http.ResponseWriter, r *http.Request, limit int64, output any) bool {
	if err := decode(http.MaxBytesReader(w, r.Body, limit), output); err != nil {
		http.Error(w, "Invalid Mailbox input", http.StatusBadRequest)
		return false
	}
	return true
}

func respond(w http.ResponseWriter, value any) {
	w.Header().Set("Content-Type", "application/json")
	_ = json.NewEncoder(w).Encode(value)
}

func result(w http.ResponseWriter, code int, err error) {
	if err != nil {
		http.Error(w, "Mailbox storage unavailable", http.StatusServiceUnavailable)
		return
	}
	w.WriteHeader(code)
}

func (s *Server) challenge(w http.ResponseWriter, r *http.Request) {
	var input struct {
		Account string `json:"account"`
	}
	if !read(w, r, 1024, &input) {
		return
	}
	if _, err := door.ParseAccount(input.Account); err != nil {
		w.WriteHeader(http.StatusBadRequest)
		return
	}
	peer, _, _ := net.SplitHostPort(r.RemoteAddr)
	if !s.withinQuota("challenge/"+peer, 60) {
		w.WriteHeader(http.StatusTooManyRequests)
		return
	}
	c := Challenge{Version: 1, Origin: s.origin, Account: input.Account, Expires: time.Now().Unix() + 60}
	rand.Read(c.Nonce[:])
	s.mu.Lock()
	if len(s.challenges) >= 1024 {
		s.mu.Unlock()
		w.WriteHeader(http.StatusTooManyRequests)
		return
	}
	s.challenges[c.Nonce] = c
	s.mu.Unlock()
	respond(w, c)
}

func (s *Server) login(w http.ResponseWriter, r *http.Request) {
	var input proof
	if !read(w, r, 16<<10, &input) {
		return
	}
	c := input.Challenge
	now := time.Now().Unix()
	s.mu.Lock()
	expected, found := s.challenges[c.Nonce]
	if found && expected == c {
		delete(s.challenges, c.Nonce)
	}
	s.mu.Unlock()
	if !found || expected != c || c.Expires <= now {
		w.WriteHeader(http.StatusUnauthorized)
		return
	}
	ctx, cancel := context.WithTimeout(r.Context(), 8*time.Second)
	defer cancel()
	if _, err := s.registry.Head(ctx); err != nil {
		w.WriteHeader(http.StatusServiceUnavailable)
		return
	}
	key, err := s.registry.SigningKey(ctx, c.Account)
	if err != nil || protocol.Verify(c.Account, key, authPurpose, c, input.Signature) != nil {
		w.WriteHeader(http.StatusUnauthorized)
		return
	}
	var entropy [32]byte
	rand.Read(entropy[:])
	token := base64.RawURLEncoding.EncodeToString(entropy[:])
	expires := time.Now().Unix() + 300
	s.mu.Lock()
	if len(s.sessions) >= 1024 {
		s.mu.Unlock()
		w.WriteHeader(http.StatusTooManyRequests)
		return
	}
	s.sessions[sha256.Sum256([]byte(token))] = authSession{c.Account, expires}
	s.mu.Unlock()
	respond(w, session{token, expires})
}

func (s *Server) authenticated(next func(http.ResponseWriter, *http.Request, string)) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		token, ok := strings.CutPrefix(r.Header.Get("Authorization"), "Bearer ")
		if !ok || len(token) != 43 {
			w.WriteHeader(http.StatusUnauthorized)
			return
		}
		s.mu.Lock()
		session, found := s.sessions[sha256.Sum256([]byte(token))]
		s.mu.Unlock()
		if !found || session.expires <= time.Now().Unix() {
			w.WriteHeader(http.StatusUnauthorized)
			return
		}
		if !s.withinQuota("account/"+session.account, 300) {
			w.WriteHeader(http.StatusTooManyRequests)
			return
		}
		next(w, r, session.account)
	}
}

func (s *Server) postMessage(w http.ResponseWriter, r *http.Request, account string) {
	var message Message
	if !read(w, r, protocol.MaxEnvelope*4/3+2048, &message) {
		return
	}
	now := time.Now().Unix()
	if _, err := door.ParseAccount(message.Route); err != nil || message.ID == (common.Hash{}) ||
		message.Expires <= now || message.Expires > now+int64(Retention/time.Second) ||
		len(message.Body) == 0 || len(message.Body) > protocol.MaxEnvelope {
		w.WriteHeader(http.StatusBadRequest)
		return
	}
	envelope, err := qoreseal.ParseEnvelope(message.Body)
	if err != nil || envelope.Mode != qoreseal.ModeHybrid || !envelope.Anonymous || len(envelope.Entries) > 8 {
		w.WriteHeader(http.StatusBadRequest)
		return
	}
	// Eight SSH sessions can send three status deliveries every ten seconds.
	// Leave room for connection replies and immediate lifecycle changes.
	if !s.withinQuota("send/"+account, 192) {
		w.WriteHeader(http.StatusTooManyRequests)
		return
	}
	code, err := s.send(account, message, now)
	result(w, code, err)
}

func (s *Server) getInbox(w http.ResponseWriter, r *http.Request, account string) {
	var after common.Hash
	if raw := r.URL.Query().Get("after"); raw != "" && after.UnmarshalText([]byte(raw)) != nil {
		w.WriteHeader(http.StatusBadRequest)
		return
	}
	inbox, err := s.inbox(account, after, time.Now().Unix())
	if err != nil {
		result(w, 0, err)
		return
	}
	respond(w, inbox)
}

func (s *Server) postAck(w http.ResponseWriter, r *http.Request, account string) {
	var id common.Hash
	if id.UnmarshalText([]byte(r.PathValue("id"))) != nil || id == (common.Hash{}) {
		w.WriteHeader(http.StatusBadRequest)
		return
	}
	result(w, http.StatusNoContent, s.ack(account, id))
}

func (s *Server) getCard(w http.ResponseWriter, r *http.Request) {
	account := r.PathValue("account")
	if _, err := door.ParseAccount(account); err != nil {
		w.WriteHeader(http.StatusBadRequest)
		return
	}
	var card qoreseal.RecipientCard
	err := s.db.View(func(tx *bolt.Tx) error {
		raw := tx.Bucket(cardBucket).Get([]byte(account))
		if raw == nil {
			return errNoCard
		}
		return json.Unmarshal(raw, &card)
	})
	if errors.Is(err, errNoCard) {
		w.WriteHeader(http.StatusNotFound)
		return
	}
	if err != nil {
		result(w, 0, err)
		return
	}
	respond(w, card)
}

var errNoCard = errors.New("recipient card not found")

func (s *Server) putCard(w http.ResponseWriter, r *http.Request, account string) {
	if account != r.PathValue("account") {
		w.WriteHeader(http.StatusForbidden)
		return
	}
	var card qoreseal.RecipientCard
	if !read(w, r, 16<<10, &card) {
		return
	}
	ctx, cancel := context.WithTimeout(r.Context(), 8*time.Second)
	defer cancel()
	if _, err := s.registry.Recipient(ctx, card, account); err != nil {
		w.WriteHeader(http.StatusUnprocessableEntity)
		return
	}
	code, err := s.saveCard(account, card)
	result(w, code, err)
}
