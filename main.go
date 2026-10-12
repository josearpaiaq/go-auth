package main

import (
	"log"
	"net/http"
	"os"
	"time"

	"github.com/joho/godotenv"
)

func main() {
	if err := godotenv.Load(); err != nil {
		log.Println("no .env file loaded, using environment variables:", err)
	}
	secret := os.Getenv("JWT_SECRET")
	if len(secret) < 32 {
		log.Fatal("set JWT_SECRET to at least 32 random characters")
	}

	port := os.Getenv("PORT")
	if len(port) == 0 {
		port = "8080"
	}

	store := NewStore()
	seed(store)

	dummy, err := HashPassword("dummy-password-for-timing")
	if err != nil {
		log.Fatal(err)
	}
	app := &App{store: store, tokens: &TokenService{secret: []byte(secret)}, dummyHash: dummy}

	mux := http.NewServeMux()

	// Public: no token needed
	mux.HandleFunc("POST /login", app.Login)
	mux.HandleFunc("POST /refresh", app.Refresh)
	mux.HandleFunc("POST /logout", app.Logout)

	// Authentication only (then the handler checks ownership)
	mux.Handle("GET /orders/{id}", app.Authenticate(http.HandlerFunc(app.GetOrder)))

	// Authentication + role check
	mux.Handle("GET /admin/orders",
		app.Authenticate(RequireRole("admin", http.HandlerFunc(app.ListAllOrders))))

	srv := &http.Server{Addr: ":" + port, Handler: mux, ReadHeaderTimeout: 5 * time.Second}
	log.Println("listening on port", port)
	log.Fatal(srv.ListenAndServe())
}

func seed(s *Store) {
	for _, u := range []struct{ id, email, pw, role string }{
		{"u1", "alice@example.com", "alice-pass", "user"},
		{"u2", "bob@example.com", "bob-pass", "user"},
		{"u3", "carol@example.com", "carol-pass", "admin"},
	} {
		h, err := HashPassword(u.pw)
		if err != nil {
			log.Fatal(err)
		}
		s.AddUser(&User{ID: u.id, Email: u.email, PasswordHash: h, Role: u.role})
	}
	s.AddOrder(&Order{ID: "o1", OwnerID: "u1", Item: "keyboard"})
	s.AddOrder(&Order{ID: "o2", OwnerID: "u2", Item: "monitor"})
}
