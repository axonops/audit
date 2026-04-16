@core @metadata
Feature: MetadataWriter Interface
  As an output backend developer, I want to receive structured event
  metadata (event type, severity, category, timestamp) alongside
  pre-serialised bytes so that I can build Loki labels, Elasticsearch
  index routes, or similar metadata-driven features without parsing
  the serialised output.

  Background:
    Given a standard test taxonomy

  Scenario: MetadataWriter output receives correct event_type
    Given an auditor with a MetadataWriter output
    When I audit event "user_create" with fields:
      | field    | value   |
      | outcome  | success |
      | actor_id | alice   |
    Then the MetadataWriter should have received event_type "user_create"

  Scenario: MetadataWriter output receives correct severity
    Given an auditor with a MetadataWriter output
    When I audit event "user_create" with fields:
      | field    | value   |
      | outcome  | success |
      | actor_id | alice   |
    Then the MetadataWriter should have received severity 5

  Scenario: MetadataWriter output receives delivery-specific category
    Given an auditor with a MetadataWriter output
    When I audit event "user_create" with fields:
      | field    | value   |
      | outcome  | success |
      | actor_id | alice   |
    Then the MetadataWriter should have received category "write"

  Scenario: Non-MetadataWriter output still receives events
    Given an auditor with stdout output
    When I audit event "user_create" with fields:
      | field    | value   |
      | outcome  | success |
      | actor_id | alice   |
    Then the event should be delivered successfully
