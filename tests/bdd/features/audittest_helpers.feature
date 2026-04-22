@core @audittest
Feature: audittest Consumer Test Helpers
  As a library consumer writing tests for my application, I want helpers
  that let me wait for asynchronously-delivered events and verify that
  sensitivity labels strip fields correctly — so that I can assert on
  audit behaviour without hand-rolling drain synchronisation or raw
  taxonomy scaffolding.

  These helpers live in the `audittest` package and delegate to the
  same validation and pipeline as production. Tests below use only the
  public API surface a consumer would touch.

  # ---------------------------------------------------------------------------
  # WaitForN — async-mode wait-until-ready barrier
  # ---------------------------------------------------------------------------

  Scenario: WaitForN returns true when the target is reached asynchronously
    Given an audittest auditor in async mode with taxonomy:
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
      """
    When 3 "user_create" events are emitted from a background goroutine
    Then Recorder.WaitForN 3 within "2s" should return true
    And the recorder should contain at least 3 events

  Scenario: WaitForN returns false on timeout when no events arrive
    Given an audittest auditor in async mode with taxonomy:
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
      """
    When no events are emitted
    Then Recorder.WaitForN 1 within "50ms" should return false
    And the recorder should contain 0 events

  # ---------------------------------------------------------------------------
  # WithExcludeLabels — sensitivity-stripping compliance workflow
  # ---------------------------------------------------------------------------

  Scenario: WithExcludeLabels strips pii-labelled fields from the recorder
    Given an audittest auditor with WithExcludeLabels "pii" and taxonomy:
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
            actor_id: {required: true}
            email: {}
      """
    When an event "user_create" is emitted with fields:
      | field    | value             |
      | outcome  | success           |
      | actor_id | alice             |
      | email    | alice@example.com |
    Then the recorded event should have field "actor_id" equal to "alice"
    And the recorded event should not have field "email"

  Scenario: WithExcludeLabels with multiple labels strips every listed label
    Given an audittest auditor with WithExcludeLabels "pii,financial" and taxonomy:
      """
      version: 1
      sensitivity:
        labels:
          pii:
            fields: [email]
          financial:
            fields: [credit_card]
      categories:
        write:
          - user_create
      events:
        user_create:
          fields:
            outcome: {required: true}
            actor_id: {required: true}
            email: {}
            credit_card: {}
            locale: {}
      """
    When an event "user_create" is emitted with fields:
      | field       | value               |
      | outcome     | success             |
      | actor_id    | bob                 |
      | email       | bob@example.com     |
      | credit_card | 4111-1111-1111-1111 |
      | locale      | en-GB               |
    Then the recorded event should not have field "email"
    And the recorded event should not have field "credit_card"
    And the recorded event should have field "locale" equal to "en-GB"
