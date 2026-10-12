package main

import (
	"encoding/json"
	"net/http"
)

type App struct {
	store     *Store
	tokens    *TokenService
	dummyHash []byte
}

type tokenResponse struct {
	AccessToken  string `json:"access_token"`
	RefreshToken string `json:"refresh_token"`
	TokenType    string `json:"token_type"`
	ExpiresIn    int    `json:"expires_in"`
}

// POST /login  {"email": "...", "password": "..."}
func (a *App) Login(w http.ResponseWriter, r *http.Request) {
	var req struct {
		Email    string `json:"email"`
		Password string `json:"password"`
	}
	if !decodeJSON(w, r, &req) {
		return
	}

	u, found := a.store.UserByEmail(req.Email)

	// Always run bcrypt, even if the email doesn't exist. Otherwise the
	// response is faster for unknown emails and attackers can list your users.
	hash := a.dummyHash
	if found {
		hash = u.PasswordHash
	}
	if !CheckPassword(hash, req.Password) || !found {
		// Same message for "no such user" and "wrong password".
		httpError(w, http.StatusUnauthorized, "invalid credentials")
		return
	}

	familyID, err := newOpaqueToken()
	if err != nil {
		httpError(w, http.StatusInternalServerError, "internal error")
		return
	}
	a.issueTokens(w, u, familyID)
}

// POST /refresh  {"refresh_token": "..."}
// Trades a refresh token for a NEW access token and a NEW refresh token.
func (a *App) Refresh(w http.ResponseWriter, r *http.Request) {
	var req struct {
		RefreshToken string `json:"refresh_token"`
	}
	if !decodeJSON(w, r, &req) {
		return
	}

	rec, err := a.store.UseRefresh(req.RefreshToken)
	if err != nil {
		httpError(w, http.StatusUnauthorized, "invalid refresh token")
		return
	}
	u, ok := a.store.UserByID(rec.UserID)
	if !ok {
		httpError(w, http.StatusUnauthorized, "invalid refresh token")
		return
	}
	a.issueTokens(w, u, rec.FamilyID) // same family, so reuse detection keeps working
}

// POST /logout  {"refresh_token": "..."}
// The access token still works until it expires (max 10 min). That's the JWT trade-off.
func (a *App) Logout(w http.ResponseWriter, r *http.Request) {
	var req struct {
		RefreshToken string `json:"refresh_token"`
	}
	if !decodeJSON(w, r, &req) {
		return
	}
	a.store.RevokeByToken(req.RefreshToken)
	w.WriteHeader(http.StatusNoContent)
}

// GET /orders/{id}
// Being logged in is NOT enough. We check that THIS user may see THIS order.
func (a *App) GetOrder(w http.ResponseWriter, r *http.Request) {
	u := CurrentUser(r.Context())
	o, ok := a.store.Order(r.PathValue("id"))

	// 404 for both "doesn't exist" and "not yours", so nobody can
	// probe which order IDs exist.
	if !ok || (o.OwnerID != u.ID && u.Role != "admin") {
		httpError(w, http.StatusNotFound, "not found")
		return
	}
	writeJSON(w, http.StatusOK, o)
}

// GET /admin/orders  (admin only, enforced by RequireRole)
func (a *App) ListAllOrders(w http.ResponseWriter, r *http.Request) {
	writeJSON(w, http.StatusOK, a.store.AllOrders())
}

// ---------- helpers ----------

func (a *App) issueTokens(w http.ResponseWriter, u *User, familyID string) {
	access, err := a.tokens.IssueAccess(u)
	if err != nil {
		httpError(w, http.StatusInternalServerError, "internal error")
		return
	}
	refresh, err := newOpaqueToken()
	if err != nil {
		httpError(w, http.StatusInternalServerError, "internal error")
		return
	}
	a.store.SaveRefresh(refresh, u.ID, familyID)

	w.Header().Set("Cache-Control", "no-store") // never cache tokens
	writeJSON(w, http.StatusOK, tokenResponse{
		AccessToken:  access,
		RefreshToken: refresh,
		TokenType:    "Bearer",
		ExpiresIn:    int(accessTokenTTL.Seconds()),
	})
}

func decodeJSON(w http.ResponseWriter, r *http.Request, dst any) bool {
	r.Body = http.MaxBytesReader(w, r.Body, 1<<20) // 1 MB cap
	if err := json.NewDecoder(r.Body).Decode(dst); err != nil {
		httpError(w, http.StatusBadRequest, "bad request")
		return false
	}
	return true
}

func writeJSON(w http.ResponseWriter, status int, v any) {
	w.Header().Set("Content-Type", "application/json")
	w.WriteHeader(status)
	_ = json.NewEncoder(w).Encode(v)
}

func httpError(w http.ResponseWriter, status int, msg string) {
	writeJSON(w, status, map[string]string{"error": msg})
}
