@core @errors
Feature: Error Discrimination
  As a library consumer, I want to distinguish validation errors
  programmatically using errors.Is so that I can handle different
  failure modes without parsing error strings.

  Background:
    Given a standard test taxonomy

  # --- Unknown event type ---

  Scenario: Unknown event type wraps ErrValidation and ErrUnknownEventType
    Given an auditor with stdout output
    When I audit event "nonexistent_event" with fields:
      | field   | value   |
      | outcome | success |
    Then the audit call should return an error matching:
      """
      audit: unknown event type "nonexistent_event"
      """
    And the audit call should return an error wrapping "ErrValidation"
    And the audit call should return an error wrapping "ErrUnknownEventType"
    And the audit call should return an error NOT wrapping "ErrMissingRequiredField"
    And the audit call should return an error NOT wrapping "ErrUnknownField"

  # --- Missing required field ---

  Scenario: Missing required field wraps ErrValidation and ErrMissingRequiredField
    Given an auditor with stdout output
    When I audit event "auth_failure" with fields:
      | field | value |
    Then the audit call should return an error wrapping "ErrValidation"
    And the audit call should return an error wrapping "ErrMissingRequiredField"
    And the audit call should return an error NOT wrapping "ErrUnknownEventType"
    And the audit call should return an error NOT wrapping "ErrUnknownField"

  # --- Unknown field (strict mode) ---

  Scenario: Unknown field in strict mode wraps ErrValidation and ErrUnknownField
    Given an auditor with stdout output
    When I audit event "auth_failure" with required fields and an unknown field "bogus"
    Then the audit call should return an error wrapping "ErrValidation"
    And the audit call should return an error wrapping "ErrUnknownField"
    And the audit call should return an error NOT wrapping "ErrUnknownEventType"
    And the audit call should return an error NOT wrapping "ErrMissingRequiredField"

  # --- Non-validation errors ---

  Scenario: ErrClosed is not ErrValidation
    Given an auditor with stdout output
    When I close the auditor
    And I audit event "auth_failure" with required fields
    Then the audit call should return an error wrapping "ErrClosed"
    And the audit call should return an error NOT wrapping "ErrValidation"
