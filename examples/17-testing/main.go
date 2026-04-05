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

// Testing demonstrates how to test code that uses go-audit.
// The main.go defines a UserService that emits audit events.
// The main_test.go shows three testing patterns using audittest.
package main

import (
	_ "embed"
	"fmt"
	"log"

	audit "github.com/axonops/go-audit"
	"github.com/axonops/go-audit/outputconfig"
)

//go:generate go run github.com/axonops/go-audit/cmd/audit-gen -input taxonomy.yaml -output audit_generated.go -package main

//go:embed taxonomy.yaml
var taxonomyYAML []byte

// UserService is a simple service that emits audit events.
// It takes a *audit.Logger as a dependency — making it testable.
type UserService struct {
	logger *audit.Logger
}

// NewUserService creates a UserService with the given logger.
func NewUserService(logger *audit.Logger) *UserService {
	return &UserService{logger: logger}
}

// CreateUser creates a user and emits an audit event.
func (s *UserService) CreateUser(actorID, email string) error {
	// ... business logic would go here ...

	return s.logger.AuditEvent(
		NewUserCreateEvent(actorID, "success").
			SetEmail(email),
	)
}

// Login attempts authentication and emits an audit event on failure.
func (s *UserService) Login(username, password string) error {
	// Simulate failed authentication.
	if password != "correct" {
		return s.logger.AuditEvent(
			NewAuthFailureEvent(username, "failure").
				SetReason("invalid password"),
		)
	}
	return nil
}

func main() {
	tax, err := audit.ParseTaxonomyYAML(taxonomyYAML)
	if err != nil {
		log.Fatalf("parse taxonomy: %v", err)
	}

	result, err := outputconfig.Load([]byte("version: 1\napp_name: testing-demo\nhost: localhost\noutputs:\n  console:\n    type: stdout\n"), &tax, nil)
	if err != nil {
		log.Fatalf("load outputs: %v", err)
	}

	opts := []audit.Option{audit.WithTaxonomy(tax)}
	opts = append(opts, result.Options...)
	logger, err := audit.NewLogger(result.Config, opts...)
	if err != nil {
		log.Fatalf("create logger: %v", err)
	}
	defer func() { _ = logger.Close() }()

	svc := NewUserService(logger)
	_ = svc.CreateUser("alice", "alice@example.com")
	_ = svc.Login("bob", "wrong")

	fmt.Println("Events emitted. See main_test.go for how to test this.")
}
