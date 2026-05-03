@core @schema-artifacts
Feature: Generated JSON Schema validates representative audit events
  As a SIEM rule author or non-Go consumer of the audit library, I
  want a published JSON Schema describing the audit event JSON shape
  so I can validate events without re-deriving the schema from Go
  source.

  These scenarios verify that audit-gen's JSON Schema output (#548)
  is a faithful description of audit.JSONFormatter's wire format. A
  representative event is built with the fixture taxonomy, the
  schema is generated from the same taxonomy, and the schema is
  asked to validate the event.

  Scenario: Generated schema validates a representative user_create event
    Given a JSON Schema generated from the fixture taxonomy
    When I validate a user_create event with all required fields against the schema
    Then the schema validates the event

  Scenario: Generated schema rejects an event missing a required custom field
    Given a JSON Schema generated from the fixture taxonomy
    When I validate a user_create event missing the actor_id field against the schema
    Then the schema rejects the event with a missing-required-property error

  Scenario: Generated schema rejects an event with an unknown property
    Given a JSON Schema generated from the fixture taxonomy
    When I validate a user_create event with extra unknown field "made_up_field" against the schema
    Then the schema rejects the event with an additional-property error

  Scenario: Generated schema rejects an event whose event_type is not in the taxonomy
    Given a JSON Schema generated from the fixture taxonomy
    When I validate an event with event_type "not_a_real_event" against the schema
    Then the schema rejects the event with a oneOf-mismatch error
