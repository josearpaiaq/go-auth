package main

import (
	"context"
	"net/http"
	"strings"
)

type ctxKey struct{}

// Authenticate answers "who is calling?".
// It runs before the handler and puts the user in the request context.
func (a *App) Authenticate(next http.Handler) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		raw, ok := strings.CutPrefix(r.Header.Get("Authorization"), "Bearer ")
		if !ok || raw == "" {
			w.Header().Set("WWW-Authenticate", "Bearer")
			httpError(w, http.StatusUnauthorized, "missing token")
			return
		}

		claims, err := a.tokens.ParseAccess(raw)
		if err != nil {
			httpError(w, http.StatusUnauthorized, "invalid token")
			return
		}

		// Load the user fresh, so a role change or a deleted account
		// takes effect now, not when the token expires.
		u, ok := a.store.UserByID(claims.Subject)
		if !ok {
			httpError(w, http.StatusUnauthorized, "invalid token")
			return
		}

		ctx := context.WithValue(r.Context(), ctxKey{}, u)
		next.ServeHTTP(w, r.WithContext(ctx))
	})
}

// RequireRole answers "is this kind of user allowed on this route?".
// It must run AFTER Authenticate.
func RequireRole(role string, next http.Handler) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if CurrentUser(r.Context()).Role != role {
			httpError(w, http.StatusForbidden, "forbidden")
			return
		}
		next.ServeHTTP(w, r)
	})
}

func CurrentUser(ctx context.Context) *User {
	u, _ := ctx.Value(ctxKey{}).(*User)
	return u
}
