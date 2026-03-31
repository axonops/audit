@core @sensitivity
Feature: Field-Level Sensitivity Labels
  As a library consumer, I want to classify fields with sensitivity labels
  (e.g., pii, financial) and configure per-output exclusion filters so that
  sensitive data is stripped from outputs that should not receive it.

  Zero configuration means zero behaviour change — existing taxonomies
  without a sensitivity section work exactly as before with no overhead.

  # ---------------------------------------------------------------------------
  # Label definition and validation
  # ---------------------------------------------------------------------------

  Scenario: No sensitivity config — all fields delivered to all outputs
    Given a taxonomy without sensitivity labels:
      """
      version: 1
      categories:
        write:
          - user_create
      events:
        user_create:
          fields:
            outcome: {required: true}
            actor_id: {required: true}
            email: {}
      default_enabled: [write]
      """
    And a logger with stdout output
    When I audit event "user_create" with fields:
      | field    | value         |
      | outcome  | success       |
      | actor_id | alice         |
      | email    | a@example.com |
    Then the output should contain an event with field "email" value "a@example.com"

  Scenario: Label defined with global field mapping applies across events
    Given a taxonomy with sensitivity labels:
      """
      version: 1
      sensitivity:
        labels:
          pii:
            fields: [email]
      categories:
        write:
          - user_create
      events:
        user_create:
          fields:
            outcome: {required: true}
            email: {}
      default_enabled: [write]
      """
    Then the taxonomy should have field "email" labeled "pii" on event "user_create"

  Scenario: Label defined with regex pattern matches expected fields
    Given a taxonomy with sensitivity labels:
      """
      version: 1
      sensitivity:
        labels:
          financial:
            patterns: ["^card_"]
      categories:
        write:
          - payment
      events:
        payment:
          fields:
            outcome: {required: true}
            card_number: {}
            card_expiry: {}
            merchant: {}
      default_enabled: [write]
      """
    Then the taxonomy should have field "card_number" labeled "financial" on event "payment"
    And the taxonomy should have field "card_expiry" labeled "financial" on event "payment"
    And the taxonomy should not have field "merchant" labeled on event "payment"

  Scenario: Label defined with both fields and patterns — both apply
    Given a taxonomy with sensitivity labels:
      """
      version: 1
      sensitivity:
        labels:
          pii:
            fields: [email]
            patterns: ["_email$"]
      categories:
        write:
          - user_create
      events:
        user_create:
          fields:
            outcome: {required: true}
            email: {}
            contact_email: {}
      default_enabled: [write]
      """
    Then the taxonomy should have field "email" labeled "pii" on event "user_create"
    And the taxonomy should have field "contact_email" labeled "pii" on event "user_create"

  Scenario: Undefined label referenced on field annotation → taxonomy parse error
    When I try to parse taxonomy from YAML:
      """
      version: 1
      sensitivity:
        labels:
          pii:
            fields: [email]
      categories:
        write:
          - user_create
      events:
        user_create:
          fields:
            outcome: {required: true}
            email:
              labels: [nonexistent]
      default_enabled: [write]
      """
    Then the taxonomy parse should fail wrapping "ErrTaxonomyInvalid"
    And the taxonomy parse should fail with an error containing "undefined sensitivity label"

  Scenario: Invalid regex pattern → taxonomy parse error
    When I try to parse taxonomy from YAML:
      """
      version: 1
      sensitivity:
        labels:
          pii:
            patterns: ["[invalid"]
      categories:
        write:
          - user_create
      events:
        user_create:
          fields:
            outcome: {required: true}
      default_enabled: [write]
      """
    Then the taxonomy parse should fail wrapping "ErrTaxonomyInvalid"

  Scenario: Empty label name → taxonomy parse error
    When I try to parse taxonomy from YAML:
      """
      version: 1
      sensitivity:
        labels:
          "":
            fields: [email]
      categories:
        write:
          - user_create
      events:
        user_create:
          fields:
            outcome: {required: true}
      default_enabled: [write]
      """
    Then the taxonomy parse should fail wrapping "ErrTaxonomyInvalid"
    And the taxonomy parse should fail with an error containing "label name must not be empty"

  Scenario: Sensitivity section present but labels empty → valid no-op
    Given a taxonomy with sensitivity labels:
      """
      version: 1
      sensitivity:
        labels: {}
      categories:
        write:
          - user_create
      events:
        user_create:
          fields:
            outcome: {required: true}
      default_enabled: [write]
      """
    Then the taxonomy parse should succeed

  Scenario: Labels from same global mapping across multiple labels are additive
    Given a taxonomy with sensitivity labels:
      """
      version: 1
      sensitivity:
        labels:
          pii:
            fields: [email]
          financial:
            fields: [email]
      categories:
        write:
          - user_create
      events:
        user_create:
          fields:
            outcome: {required: true}
            email: {}
      default_enabled: [write]
      """
    Then the taxonomy should have field "email" labeled "pii" on event "user_create"
    And the taxonomy should have field "email" labeled "financial" on event "user_create"

  # ---------------------------------------------------------------------------
  # Per-field annotation
  # ---------------------------------------------------------------------------

  Scenario: Explicit field label in taxonomy YAML resolves correctly
    Given a taxonomy with sensitivity labels:
      """
      version: 1
      sensitivity:
        labels:
          confidential:
            description: "internal only"
      categories:
        write:
          - user_create
      events:
        user_create:
          fields:
            outcome: {required: true}
            session_token:
              labels: [confidential]
      default_enabled: [write]
      """
    Then the taxonomy should have field "session_token" labeled "confidential" on event "user_create"

  Scenario: Field label references undefined label → taxonomy parse error
    When I try to parse taxonomy from YAML:
      """
      version: 1
      sensitivity:
        labels:
          pii:
            description: "test"
      categories:
        write:
          - user_create
      events:
        user_create:
          fields:
            outcome: {required: true}
            email:
              labels: [unknown_label]
      default_enabled: [write]
      """
    Then the taxonomy parse should fail wrapping "ErrTaxonomyInvalid"
    And the taxonomy parse should fail with an error containing "undefined sensitivity label"

  Scenario: Labels from explicit annotation and global mapping are additive
    Given a taxonomy with sensitivity labels:
      """
      version: 1
      sensitivity:
        labels:
          pii:
            fields: [email]
          confidential:
            description: "internal"
      categories:
        write:
          - user_create
      events:
        user_create:
          fields:
            outcome: {required: true}
            email:
              labels: [confidential]
      default_enabled: [write]
      """
    Then the taxonomy should have field "email" labeled "pii" on event "user_create"
    And the taxonomy should have field "email" labeled "confidential" on event "user_create"

  Scenario: Labels from all three mechanisms merge into single set
    Given a taxonomy with sensitivity labels:
      """
      version: 1
      sensitivity:
        labels:
          pii:
            fields: [email]
            patterns: ["^user_"]
          confidential:
            description: "internal"
      categories:
        write:
          - user_create
      events:
        user_create:
          fields:
            outcome: {required: true}
            email:
              labels: [confidential]
            user_email: {}
      default_enabled: [write]
      """
    Then the taxonomy should have field "email" labeled "pii" on event "user_create"
    And the taxonomy should have field "email" labeled "confidential" on event "user_create"
    And the taxonomy should have field "user_email" labeled "pii" on event "user_create"

  # ---------------------------------------------------------------------------
  # Protected fields
  # ---------------------------------------------------------------------------

  Scenario: Labeling timestamp via explicit annotation → taxonomy parse error
    When I try to parse taxonomy from YAML:
      """
      version: 1
      sensitivity:
        labels:
          pii:
            description: "test"
      categories:
        write:
          - user_create
      events:
        user_create:
          fields:
            outcome: {required: true}
            timestamp:
              labels: [pii]
      default_enabled: [write]
      """
    Then the taxonomy parse should fail wrapping "ErrTaxonomyInvalid"
    And the taxonomy parse should fail with an error containing "protected framework field"

  Scenario: Labeling event_type via global field mapping → taxonomy parse error
    When I try to parse taxonomy from YAML:
      """
      version: 1
      sensitivity:
        labels:
          pii:
            fields: [event_type]
      categories:
        write:
          - user_create
      events:
        user_create:
          fields:
            outcome: {required: true}
      default_enabled: [write]
      """
    Then the taxonomy parse should fail wrapping "ErrTaxonomyInvalid"
    And the taxonomy parse should fail with an error containing "protected framework field"

  Scenario: Regex matching severity → taxonomy parse error
    When I try to parse taxonomy from YAML:
      """
      version: 1
      sensitivity:
        labels:
          pii:
            patterns: ["^sever"]
      categories:
        write:
          - user_create
      events:
        user_create:
          fields:
            outcome: {required: true}
      default_enabled: [write]
      """
    Then the taxonomy parse should fail wrapping "ErrTaxonomyInvalid"
    And the taxonomy parse should fail with an error containing "protected framework field"

  Scenario: Regex matching duration_ms → taxonomy parse error
    When I try to parse taxonomy from YAML:
      """
      version: 1
      sensitivity:
        labels:
          internal:
            patterns: ["duration_ms"]
      categories:
        write:
          - user_create
      events:
        user_create:
          fields:
            outcome: {required: true}
      default_enabled: [write]
      """
    Then the taxonomy parse should fail wrapping "ErrTaxonomyInvalid"
    And the taxonomy parse should fail with an error containing "protected framework field"
