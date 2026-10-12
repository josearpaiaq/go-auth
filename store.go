package main

import (
	"errors"
	"sync"
	"time"
)

// In-memory storage so the example runs with no database.
// In a real app these would be tables.

type User struct {
	ID           string
	Email        string
	PasswordHash []byte // never store the plain password
	Role         string // "user" or "admin"
}

type Order struct {
	ID      string `json:"id"`
	OwnerID string `json:"owner_id"`
	Item    string `json:"item"`
}

// A refresh token lives on the server so we can revoke it.
// All tokens created from the same login share a FamilyID.
type refreshRecord struct {
	UserID    string
	FamilyID  string
	ExpiresAt time.Time
	Used      bool
}

var (
	ErrInvalidRefresh = errors.New("invalid refresh token")
	ErrRefreshReuse   = errors.New("refresh token reuse detected")
)

type Store struct {
	mu        sync.Mutex
	usersByID map[string]*User
	usersByEm map[string]*User
	orders    map[string]*Order
	refresh   map[string]*refreshRecord // key = SHA-256 of the token, never the token itself
}

func NewStore() *Store {
	return &Store{
		usersByID: map[string]*User{},
		usersByEm: map[string]*User{},
		orders:    map[string]*Order{},
		refresh:   map[string]*refreshRecord{},
	}
}

func (s *Store) AddUser(u *User) {
	s.mu.Lock()
	defer s.mu.Unlock()
	s.usersByID[u.ID] = u
	s.usersByEm[u.Email] = u
}

func (s *Store) UserByEmail(email string) (*User, bool) {
	s.mu.Lock()
	defer s.mu.Unlock()
	u, ok := s.usersByEm[email]
	return u, ok
}

func (s *Store) UserByID(id string) (*User, bool) {
	s.mu.Lock()
	defer s.mu.Unlock()
	u, ok := s.usersByID[id]
	return u, ok
}

func (s *Store) AddOrder(o *Order) {
	s.mu.Lock()
	defer s.mu.Unlock()
	s.orders[o.ID] = o
}

func (s *Store) Order(id string) (*Order, bool) {
	s.mu.Lock()
	defer s.mu.Unlock()
	o, ok := s.orders[id]
	return o, ok
}

func (s *Store) AllOrders() []*Order {
	s.mu.Lock()
	defer s.mu.Unlock()
	out := make([]*Order, 0, len(s.orders))
	for _, o := range s.orders {
		out = append(out, o)
	}
	return out
}

func (s *Store) SaveRefresh(token, userID, familyID string) {
	s.mu.Lock()
	defer s.mu.Unlock()
	s.refresh[hashToken(token)] = &refreshRecord{
		UserID:    userID,
		FamilyID:  familyID,
		ExpiresAt: time.Now().Add(refreshTokenTTL),
	}
}

// UseRefresh consumes a refresh token (each one works exactly once).
// If a token that was already used shows up again, someone copied it,
// so we kill the whole family: both the attacker and the real user get logged out.
func (s *Store) UseRefresh(token string) (*refreshRecord, error) {
	s.mu.Lock()
	defer s.mu.Unlock()

	rec, ok := s.refresh[hashToken(token)]
	if !ok || time.Now().After(rec.ExpiresAt) {
		return nil, ErrInvalidRefresh
	}
	if rec.Used {
		s.revokeFamilyLocked(rec.FamilyID)
		return nil, ErrRefreshReuse
	}
	rec.Used = true
	return rec, nil
}

// RevokeByToken is used by logout: it ends the whole login session.
func (s *Store) RevokeByToken(token string) {
	s.mu.Lock()
	defer s.mu.Unlock()
	if rec, ok := s.refresh[hashToken(token)]; ok {
		s.revokeFamilyLocked(rec.FamilyID)
	}
}

func (s *Store) revokeFamilyLocked(familyID string) {
	for k, r := range s.refresh {
		if r.FamilyID == familyID {
			delete(s.refresh, k)
		}
	}
}
