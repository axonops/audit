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
	"fmt"
	"time"

	_ "github.com/lib/pq" // Postgres driver
)

// Item is the CRUD resource.
type Item struct { //nolint:govet // fieldalignment: readability preferred
	ID          string    `json:"id"`
	Name        string    `json:"name"`
	Description string    `json:"description"`
	CreatedAt   time.Time `json:"created_at"`
	UpdatedAt   time.Time `json:"updated_at"`
}

func connectDB() (*sql.DB, error) {
	// sslmode=disable is for local Docker development only — use sslmode=require in production.
	dsn := envOr("DATABASE_URL", "postgres://demo:demo@localhost:5432/audit_demo?sslmode=disable")
	db, err := sql.Open("postgres", dsn)
	if err != nil {
		return nil, fmt.Errorf("open db: %w", err)
	}
	db.SetMaxOpenConns(10)
	db.SetMaxIdleConns(5)
	if err := db.Ping(); err != nil {
		_ = db.Close()
		return nil, fmt.Errorf("ping db: %w", err)
	}
	return db, nil
}

func createSchema(db *sql.DB) error {
	_, err := db.Exec(`
		CREATE TABLE IF NOT EXISTS items (
			id          TEXT PRIMARY KEY,
			name        TEXT NOT NULL,
			description TEXT NOT NULL DEFAULT '',
			created_at  TIMESTAMPTZ NOT NULL DEFAULT NOW(),
			updated_at  TIMESTAMPTZ NOT NULL DEFAULT NOW()
		)
	`)
	return err
}

func queryItems(db *sql.DB) ([]Item, error) {
	rows, err := db.Query("SELECT id, name, description, created_at, updated_at FROM items ORDER BY created_at")
	if err != nil {
		return nil, err
	}
	defer func() { _ = rows.Close() }()

	var items []Item
	for rows.Next() {
		var it Item
		if err := rows.Scan(&it.ID, &it.Name, &it.Description, &it.CreatedAt, &it.UpdatedAt); err != nil {
			return nil, err
		}
		items = append(items, it)
	}
	if items == nil {
		items = []Item{} // return empty array, not null
	}
	return items, rows.Err()
}

func queryItem(db *sql.DB, id string) (*Item, error) {
	var it Item
	err := db.QueryRow(
		"SELECT id, name, description, created_at, updated_at FROM items WHERE id = $1", id,
	).Scan(&it.ID, &it.Name, &it.Description, &it.CreatedAt, &it.UpdatedAt)
	if err != nil {
		return nil, err
	}
	return &it, nil
}

func insertItem(db *sql.DB, id, name, description string) (*Item, error) {
	var it Item
	err := db.QueryRow(
		"INSERT INTO items (id, name, description) VALUES ($1, $2, $3) RETURNING id, name, description, created_at, updated_at",
		id, name, description,
	).Scan(&it.ID, &it.Name, &it.Description, &it.CreatedAt, &it.UpdatedAt)
	if err != nil {
		return nil, err
	}
	return &it, nil
}

func updateItemDB(db *sql.DB, id, name, description string) (*Item, error) {
	var it Item
	err := db.QueryRow(
		"UPDATE items SET name = $2, description = $3, updated_at = NOW() WHERE id = $1 RETURNING id, name, description, created_at, updated_at",
		id, name, description,
	).Scan(&it.ID, &it.Name, &it.Description, &it.CreatedAt, &it.UpdatedAt)
	if err != nil {
		return nil, err
	}
	return &it, nil
}

func deleteItemDB(db *sql.DB, id string) error {
	result, err := db.Exec("DELETE FROM items WHERE id = $1", id)
	if err != nil {
		return err
	}
	n, rowsErr := result.RowsAffected()
	if rowsErr != nil {
		return fmt.Errorf("rows affected: %w", rowsErr)
	}
	if n == 0 {
		return sql.ErrNoRows
	}
	return nil
}
