// Webhook receiver is a test HTTP server that captures audit events
// for integration and BDD testing. It stores received events in memory
// and provides endpoints to query, reset, and configure behaviour.
//
// This is a standalone binary, not part of the go-audit module.
package main

import (
	"encoding/json"
	"fmt"
	"log"
	"net/http"
	"os"
	"strconv"
	"sync"
	"time"
)

//nolint:govet // test utility; field order matches JSON output readability
type event struct {
	Body    json.RawMessage   `json:"body"`
	Headers map[string]string `json:"headers"`
	Time    time.Time         `json:"time"`
}

type config struct {
	StatusCode int           `json:"status_code"`
	Delay      time.Duration `json:"delay"`
}

type server struct {
	events []event
	cfg    config
	mu     sync.Mutex
}

func main() {
	port := "8080"
	if p := os.Getenv("PORT"); p != "" {
		port = p
	}

	s := &server{
		cfg: config{StatusCode: http.StatusOK},
	}

	mux := http.NewServeMux()
	mux.HandleFunc("POST /events", s.handlePostEvents)
	mux.HandleFunc("GET /events", s.handleGetEvents)
	mux.HandleFunc("POST /reset", s.handleReset)
	mux.HandleFunc("POST /configure", s.handleConfigure)
	mux.HandleFunc("GET /health", s.handleHealth)

	srv := &http.Server{
		Addr:         ":" + port,
		Handler:      mux,
		ReadTimeout:  30 * time.Second,
		WriteTimeout: 30 * time.Second,
		IdleTimeout:  60 * time.Second,
	}
	log.Printf("webhook-receiver listening on :%s", port)
	if err := srv.ListenAndServe(); err != nil {
		log.Fatal(err)
	}
}

// POST /events — store received event.
func (s *server) handlePostEvents(w http.ResponseWriter, r *http.Request) {
	s.mu.Lock()
	defer s.mu.Unlock()

	if s.cfg.Delay > 0 {
		time.Sleep(s.cfg.Delay)
	}

	var body json.RawMessage
	if err := json.NewDecoder(r.Body).Decode(&body); err != nil {
		// Store raw body as a string if not valid JSON.
		body = json.RawMessage(fmt.Sprintf("%q", "decode error"))
	}

	headers := make(map[string]string, len(r.Header))
	for k := range r.Header {
		headers[k] = r.Header.Get(k)
	}

	s.events = append(s.events, event{
		Body:    body,
		Headers: headers,
		Time:    time.Now(),
	})

	w.WriteHeader(s.cfg.StatusCode)
}

// GET /events — return all stored events.
func (s *server) handleGetEvents(w http.ResponseWriter, _ *http.Request) {
	s.mu.Lock()
	defer s.mu.Unlock()

	w.Header().Set("Content-Type", "application/json")
	if err := json.NewEncoder(w).Encode(s.events); err != nil {
		http.Error(w, err.Error(), http.StatusInternalServerError)
	}
}

// POST /reset — clear stored events.
func (s *server) handleReset(w http.ResponseWriter, _ *http.Request) {
	s.mu.Lock()
	defer s.mu.Unlock()

	s.events = nil
	s.cfg = config{StatusCode: http.StatusOK}
	w.WriteHeader(http.StatusNoContent)
}

// POST /configure — set response behaviour.
//
//	{"status_code": 503, "delay_ms": 500}
func (s *server) handleConfigure(w http.ResponseWriter, r *http.Request) {
	var req struct {
		StatusCode int `json:"status_code"`
		DelayMS    int `json:"delay_ms"`
	}
	if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
		http.Error(w, err.Error(), http.StatusBadRequest)
		return
	}

	s.mu.Lock()
	defer s.mu.Unlock()

	if req.StatusCode > 0 {
		s.cfg.StatusCode = req.StatusCode
	}
	s.cfg.Delay = time.Duration(req.DelayMS) * time.Millisecond

	w.Header().Set("Content-Type", "application/json")
	_ = json.NewEncoder(w).Encode(map[string]string{
		"status_code": strconv.Itoa(s.cfg.StatusCode),
		"delay_ms":    strconv.Itoa(req.DelayMS),
	})
}

// GET /health — readiness probe.
func (s *server) handleHealth(w http.ResponseWriter, _ *http.Request) {
	w.WriteHeader(http.StatusOK)
	_, _ = w.Write([]byte("ok"))
}
