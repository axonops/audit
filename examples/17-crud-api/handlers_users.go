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
	"errors"
	"net/http"

	"github.com/axonops/audit"
	"github.com/google/uuid"
)

func (h *handlers) listUsers(w http.ResponseWriter, r *http.Request) {
	users, err := queryUsers(h.db)
	if err != nil {
		writeError(w, r, http.StatusInternalServerError, "list users failed")
		return
	}
	writeJSON(w, http.StatusOK, users)
}

func (h *handlers) getUser(w http.ResponseWriter, r *http.Request) {
	id := r.PathValue("id")
	if hints := audit.HintsFromContext(r.Context()); hints != nil {
		hints.TargetID = id
	}

	user, err := queryUser(h.db, id)
	if err != nil {
		writeError(w, r, http.StatusNotFound, "user not found")
		return
	}
	writeJSON(w, http.StatusOK, user)
}

func (h *handlers) createUser(w http.ResponseWriter, r *http.Request) {
	var req struct {
		Username string `json:"username"`
		Email    string `json:"email"`
		Phone    string `json:"phone"`
	}
	// Production: use http.MaxBytesReader to bound request size.
	if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
		writeError(w, r, http.StatusBadRequest, "invalid JSON body")
		return
	}
	if req.Username == "" {
		writeError(w, r, http.StatusBadRequest, "username is required")
		return
	}
	if req.Email == "" {
		writeError(w, r, http.StatusBadRequest, "email is required")
		return
	}

	id := uuid.New().String()
	user, err := insertUser(h.db, id, req.Username, req.Email, req.Phone)
	if err != nil {
		writeError(w, r, http.StatusInternalServerError, "create user failed")
		return
	}

	if hints := audit.HintsFromContext(r.Context()); hints != nil {
		hints.TargetID = id
		populatePIIHints(hints, req.Email, req.Phone)
	}
	writeJSON(w, http.StatusCreated, user)
}

func (h *handlers) updateUser(w http.ResponseWriter, r *http.Request) {
	id := r.PathValue("id")
	if hints := audit.HintsFromContext(r.Context()); hints != nil {
		hints.TargetID = id
	}

	var req struct {
		Username string `json:"username"`
		Email    string `json:"email"`
		Phone    string `json:"phone"`
	}
	// Production: use http.MaxBytesReader to bound request size.
	if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
		writeError(w, r, http.StatusBadRequest, "invalid JSON body")
		return
	}

	if req.Username == "" {
		writeError(w, r, http.StatusBadRequest, "username is required")
		return
	}
	if req.Email == "" {
		writeError(w, r, http.StatusBadRequest, "email is required")
		return
	}

	user, err := updateUserDB(h.db, id, req.Username, req.Email, req.Phone)
	if err != nil {
		writeError(w, r, http.StatusNotFound, "user not found")
		return
	}

	if hints := audit.HintsFromContext(r.Context()); hints != nil {
		populatePIIHints(hints, req.Email, req.Phone)
	}
	writeJSON(w, http.StatusOK, user)
}

func (h *handlers) deleteUser(w http.ResponseWriter, r *http.Request) {
	id := r.PathValue("id")
	if hints := audit.HintsFromContext(r.Context()); hints != nil {
		hints.TargetID = id
	}

	if err := deleteUserDB(h.db, id); err != nil {
		if errors.Is(err, sql.ErrNoRows) {
			writeError(w, r, http.StatusNotFound, "user not found")
		} else {
			// Foreign key violation — user has dependent orders.
			writeError(w, r, http.StatusConflict, "user has dependent orders")
		}
		return
	}
	w.WriteHeader(http.StatusNoContent)
}
