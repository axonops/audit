@core
Feature: Event interface taxonomy metadata
  As a library consumer building middleware that introspects audit
  events, I need access to event-type metadata (description,
  category memberships with severity, per-field labels and required
  flags) so that I can implement cross-cutting concerns like field
  redaction, severity-based routing, or context-aware audit
  augmentation without having to look up the taxonomy myself.

  The Event interface (#597) and EventHandle expose Description(),
  Categories(), and FieldInfoMap(). Generated builders carry full
  metadata; events constructed via NewEvent / NewEventKV are
  taxonomy-agnostic and return zero values.

  Scenario: NewEvent returns taxonomy-agnostic event with zero metadata
    Given a standard test taxonomy
    When I call NewEvent for "user_create" with required fields
    Then the event Description should be empty
    And the event Categories should be empty
    And the event FieldInfoMap should be empty

  Scenario: EventHandle exposes Description from the taxonomy
    Given the following taxonomy:
      """
      version: 1
      categories:
        write:
          - user_create
      events:
        user_create:
          description: "Create a new user account"
          fields:
            outcome: {required: true}
            actor_id: {required: true}
      """
    And an auditor with stdout output
    When I obtain a handle for "user_create"
    Then the handle Description should equal "Create a new user account"

  Scenario: EventHandle exposes Categories from the taxonomy with severity
    Given the following taxonomy:
      """
      version: 1
      categories:
        security:
          severity: 7
          events:
            - auth_failure
      events:
        auth_failure:
          fields:
            outcome: {required: true}
            actor_id: {required: true}
      """
    And an auditor with stdout output
    When I obtain a handle for "auth_failure"
    Then the handle Categories should contain exactly "security"
    And the handle Categories "security" should have severity 7

  Scenario: EventHandle exposes Categories with no severity when taxonomy omits it
    Given a standard test taxonomy
    And an auditor with stdout output
    When I obtain a handle for "user_create"
    Then the handle Categories should contain exactly "write"
    And the handle Categories "write" should have no severity

  Scenario: EventHandle exposes FieldInfoMap with required and optional flags
    Given a standard test taxonomy
    And an auditor with stdout output
    When I obtain a handle for "user_create"
    Then the handle FieldInfoMap should mark "outcome" as required
    And the handle FieldInfoMap should include "actor_id"
    And the handle FieldInfoMap should mark "marker" as optional

  Scenario: EventHandle exposes FieldInfoMap with sensitivity labels
    Given the following taxonomy:
      """
      version: 1
      sensitivity:
        labels:
          pii:
            description: "Personally identifiable information"
      categories:
        write:
          - user_create
      events:
        user_create:
          fields:
            outcome: {required: true}
            actor_id: {required: true, labels: [pii]}
      """
    And an auditor with stdout output
    When I obtain a handle for "user_create"
    Then the handle FieldInfoMap entry for "actor_id" should carry label "pii"
