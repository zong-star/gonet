package auth

import (
	"sync"
	"time"
)

type attempts struct {
	started            time.Time
	failures, inFlight int
}

// LoginLimiter uses the actual socket peer, never untrusted forwarding headers.
// Entries expire; when capacity is exhausted new sources fail closed.
type LoginLimiter struct {
	mu      sync.Mutex
	entries map[string]*attempts
	now     func() time.Time
}

func NewLoginLimiter() *LoginLimiter {
	return &LoginLimiter{entries: make(map[string]*attempts), now: time.Now}
}
func (l *LoginLimiter) Begin(source string) (func(bool), time.Duration) {
	l.mu.Lock()
	defer l.mu.Unlock()
	now := l.now()
	for key, e := range l.entries {
		if now.Sub(e.started) >= time.Minute && e.inFlight == 0 {
			delete(l.entries, key)
		}
	}
	e := l.entries[source]
	if e == nil {
		if len(l.entries) >= 4096 {
			return nil, time.Minute
		}
		e = &attempts{started: now}
		l.entries[source] = e
	}
	if e.failures+e.inFlight >= 5 {
		return nil, max(time.Second, time.Minute-now.Sub(e.started))
	}
	e.inFlight++
	var once sync.Once
	return func(failed bool) {
		once.Do(func() {
			l.mu.Lock()
			defer l.mu.Unlock()
			e.inFlight--
			if failed {
				e.failures++
			}
		})
	}, 0
}
