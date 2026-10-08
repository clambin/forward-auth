package server

import (
	"net/http"

	"github.com/clambin/forward-auth/internal/session"
)

func handleSessions(
	tokenManager *session.Manager,
) http.Handler {
	mux := http.NewServeMux()
	mux.Handle("GET /list", handleListSessions(tokenManager))
	mux.Handle("DELETE /session/{id}", handleDeleteSession())

	return mux
}

func handleListSessions(tokenManager *session.Manager) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		username := r.Header.Get(forwardedUserEmailHeader)
		if username == "" {
			http.Error(w, "missing X-Forwarded-User header", http.StatusBadRequest)
			return
		}
		//tokenManager.List(r.Context(), username)

	})
}

func handleDeleteSession() http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		//r.PathValue("id")
		//w.Write([]byte("delete session"))
	})
}
