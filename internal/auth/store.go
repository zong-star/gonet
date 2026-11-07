package auth

import (
	"crypto/rand"
	"crypto/sha256"
	"encoding/base64"
	"errors"
	"sync"
	"time"
)

const CookieName = "gonet_session"
const maxSessions = 1024

type Session struct {
	Username  string
	CreatedAt time.Time
	ExpiresAt time.Time
	CSRFToken string
}

type Store struct {
	mu       sync.Mutex
	sessions map[[32]byte]Session
	ttl      time.Duration
	now      func() time.Time
	stop     chan struct{}
	done     chan struct{}
	once     sync.Once
}

func NewStore(ttl time.Duration) *Store {
	s := &Store{sessions: make(map[[32]byte]Session), ttl: ttl, now: time.Now, stop: make(chan struct{}), done: make(chan struct{})}
	go func() {
		defer close(s.done)
		ticker := time.NewTicker(time.Minute)
		defer ticker.Stop()
		for {
			select {
			case <-ticker.C:
				s.Cleanup()
			case <-s.stop:
				return
			}
		}
	}()
	return s
}

func randomID() (string, error) {
	var raw [32]byte
	if _, err := rand.Read(raw[:]); err != nil {
		return "", err
	}
	return base64.RawURLEncoding.EncodeToString(raw[:]), nil
}

func (s *Store) Create(username, oldID string) (string, Session, error) {
	id, err := randomID()
	if err != nil {
		return "", Session{}, err
	}
	csrf, err := randomID()
	if err != nil {
		return "", Session{}, err
	}
	s.mu.Lock()
	defer s.mu.Unlock()
	now := s.now()
	s.cleanup(now)
	oldKey := sha256.Sum256([]byte(oldID))
	_, rotating := s.sessions[oldKey]
	if len(s.sessions) >= maxSessions && !rotating {
		return "", Session{}, errors.New("session capacity reached")
	}
	session := Session{Username: username, CreatedAt: now, ExpiresAt: now.Add(s.ttl), CSRFToken: csrf}
	delete(s.sessions, oldKey)
	s.sessions[sha256.Sum256([]byte(id))] = session
	return id, session, nil
}

func (s *Store) Get(id string) (Session, bool) {
	if len(id) != 43 {
		return Session{}, false
	}
	s.mu.Lock()
	defer s.mu.Unlock()
	key := sha256.Sum256([]byte(id))
	session, ok := s.sessions[key]
	if ok && !s.now().Before(session.ExpiresAt) {
		delete(s.sessions, key)
		return Session{}, false
	}
	return session, ok
}
func (s *Store) Delete(id string) {
	s.mu.Lock()
	defer s.mu.Unlock()
	delete(s.sessions, sha256.Sum256([]byte(id)))
}
func (s *Store) cleanup(now time.Time) {
	for key, session := range s.sessions {
		if !now.Before(session.ExpiresAt) {
			delete(s.sessions, key)
		}
	}
}
func (s *Store) Cleanup() { s.mu.Lock(); defer s.mu.Unlock(); s.cleanup(s.now()) }
func (s *Store) Close() {
	s.once.Do(func() { close(s.stop) })
	<-s.done
	s.mu.Lock()
	clear(s.sessions)
	s.mu.Unlock()
}
