package iitkgp_erp_login

import (
	"context"
	"crypto/rand"
	"encoding/hex"
	"errors"
	"fmt"
	"io/fs"
	"net/http"
	"os"
	"time"

	"github.com/pkg/browser"
	"golang.org/x/oauth2"
)

// fileExists reports whether the named file exists and is accessible.
func fileExists(filename string) bool {
	_, err := os.Stat(filename)
	return !errors.Is(err, fs.ErrNotExist)
}

// randomState returns a cryptographically-random OAuth2 state string used to
// protect the callback against CSRF.
func randomState() (string, error) {
	b := make([]byte, 16)
	if _, err := rand.Read(b); err != nil {
		return "", fmt.Errorf("generating oauth state: %w", err)
	}
	return hex.EncodeToString(b), nil
}

// generateToken runs the OAuth2 loopback flow: it opens the consent URL in a
// browser and serves a one-shot callback on :7007 to capture the token.
func generateToken(ctx context.Context, conf *oauth2.Config) (*oauth2.Token, error) {
	state, err := randomState()
	if err != nil {
		return nil, err
	}

	authURL := conf.AuthCodeURL(state)
	fmt.Println("Visit this URL for authentication: ", authURL)
	_ = browser.OpenURL(authURL)

	type result struct {
		token *oauth2.Token
		err   error
	}
	resultCh := make(chan result, 1)

	mux := http.NewServeMux()
	mux.HandleFunc("/", func(w http.ResponseWriter, r *http.Request) {
		if r.URL.Query().Get("state") != state {
			http.Error(w, "state mismatch", http.StatusBadRequest)
			resultCh <- result{nil, errors.New("oauth state mismatch")}
			return
		}
		token, err := conf.Exchange(r.Context(), r.URL.Query().Get("code"))
		fmt.Fprintln(w, "Authentication complete. Check your terminal.")
		resultCh <- result{token, err}
	})

	server := &http.Server{Addr: ":7007", Handler: mux}
	go func() {
		if err := server.ListenAndServe(); err != nil && !errors.Is(err, http.ErrServerClosed) {
			resultCh <- result{nil, fmt.Errorf("oauth callback server: %w", err)}
		}
	}()

	var res result
	select {
	case res = <-resultCh:
	case <-ctx.Done():
		res = result{nil, ctx.Err()}
	}

	shutdownCtx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()
	_ = server.Shutdown(shutdownCtx)

	if res.err != nil {
		return nil, res.err
	}
	return res.token, nil
}
