// Copyright 2026 AxonOps Limited.
//
// Licensed under the Apache License, Version 2.0 (the "License");
// you may not use this file except in compliance with the License.
// You may obtain a copy of the License at
//
//     http://www.apache.org/licenses/LICENSE-2.0
//
// Unless required by applicable law or agreed to in writing, software
// distributed under the License is distributed on an "AS IS" BASIS,
// WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
// See the License for the specific language governing permissions and
// limitations under the License.

package main

import (
	"database/sql"
	"encoding/json"
	"net/http"

	audit "github.com/axonops/go-audit"
	"github.com/google/uuid"
)

type handlers struct {
	db *sql.DB
}

func (h *handlers) listItems(w http.ResponseWriter, r *http.Request) {
	items, err := queryItems(h.db)
	if err != nil {
		writeError(w, r, http.StatusInternalServerError, "list items failed")
		return
	}
	writeJSON(w, http.StatusOK, items)
}

func (h *handlers) getItem(w http.ResponseWriter, r *http.Request) {
	id := r.PathValue("id")
	if hints := audit.HintsFromContext(r.Context()); hints != nil {
		hints.TargetID = id
	}

	item, err := queryItem(h.db, id)
	if err != nil {
		writeError(w, r, http.StatusNotFound, "item not found")
		return
	}
	writeJSON(w, http.StatusOK, item)
}

func (h *handlers) createItem(w http.ResponseWriter, r *http.Request) {
	var req struct {
		Name        string `json:"name"`
		Description string `json:"description"`
	}
	// Production apps should wrap r.Body with http.MaxBytesReader
	// to bound request size: r.Body = http.MaxBytesReader(w, r.Body, 1<<20)
	if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
		writeError(w, r, http.StatusBadRequest, "invalid JSON body")
		return
	}
	if req.Name == "" {
		writeError(w, r, http.StatusBadRequest, "name is required")
		return
	}

	id := uuid.New().String()
	item, err := insertItem(h.db, id, req.Name, req.Description)
	if err != nil {
		writeError(w, r, http.StatusInternalServerError, "create item failed")
		return
	}

	if hints := audit.HintsFromContext(r.Context()); hints != nil {
		hints.TargetID = id
	}
	writeJSON(w, http.StatusCreated, item)
}

func (h *handlers) updateItem(w http.ResponseWriter, r *http.Request) {
	id := r.PathValue("id")
	if hints := audit.HintsFromContext(r.Context()); hints != nil {
		hints.TargetID = id
	}

	var req struct {
		Name        string `json:"name"`
		Description string `json:"description"`
	}
	// Production: use http.MaxBytesReader to bound request size.
	if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
		writeError(w, r, http.StatusBadRequest, "invalid JSON body")
		return
	}

	item, err := updateItemDB(h.db, id, req.Name, req.Description)
	if err != nil {
		writeError(w, r, http.StatusNotFound, "item not found")
		return
	}
	writeJSON(w, http.StatusOK, item)
}

func (h *handlers) deleteItem(w http.ResponseWriter, r *http.Request) {
	id := r.PathValue("id")
	if hints := audit.HintsFromContext(r.Context()); hints != nil {
		hints.TargetID = id
	}

	if err := deleteItemDB(h.db, id); err != nil {
		writeError(w, r, http.StatusNotFound, "item not found")
		return
	}
	w.WriteHeader(http.StatusNoContent)
}

func writeJSON(w http.ResponseWriter, status int, v any) {
	w.Header().Set("Content-Type", "application/json")
	w.WriteHeader(status)
	_ = json.NewEncoder(w).Encode(v)
}

func writeError(w http.ResponseWriter, r *http.Request, status int, msg string) {
	if hints := audit.HintsFromContext(r.Context()); hints != nil {
		hints.Outcome = "failure"
		hints.Error = msg
	}
	w.Header().Set("Content-Type", "application/json")
	w.WriteHeader(status)
	_ = json.NewEncoder(w).Encode(map[string]string{"error": msg})
}
