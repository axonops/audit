@core @lifecycle
Feature: Lifecycle Events
  As a library consumer, I want the logger to emit startup and shutdown
  events so that I have a complete audit trail of application lifecycle.

  Lifecycle events ("startup" and "shutdown") are automatically injected
  into the taxonomy if not already defined. The shutdown event is only
  emitted if EmitStartup was called successfully.

  Background:
    Given a standard test taxonomy

  Scenario: Startup event is emitted with app name
    Given a logger with file output at a temporary path
    When I emit startup with app name "my-service"
    And I close the logger
    Then the file should contain an event with event_type "startup"
    And the file should contain an event with event_type "startup" and field "app_name" with value "my-service"

  Scenario: Shutdown event is emitted automatically after startup
    Given a logger with file output at a temporary path
    When I emit startup with app name "my-service"
    And I close the logger
    Then the file should contain an event with event_type "shutdown"
    And the file should contain an event with event_type "shutdown" and field "app_name" with value "my-service"

  Scenario: No shutdown event without prior startup
    Given a logger with file output at a temporary path
    When I close the logger
    Then the file should not contain an event with event_type "shutdown"

  Scenario: Startup and shutdown events both present in output
    Given a logger with file output at a temporary path
    When I emit startup with app name "lifecycle-test"
    And I audit event "user_create" with required fields
    And I close the logger
    Then the file should contain an event with event_type "startup"
    And the file should contain an event with event_type "user_create"
    And the file should contain an event with event_type "shutdown"

  Scenario: EmitStartup missing app_name returns exact error
    Given a logger with file output at a temporary path
    When I emit startup without app name
    Then the startup call should return an error matching:
      """
      audit: event "startup" missing required fields: [app_name]
      """

  Scenario: EmitStartup after Close returns ErrClosed
    Given a logger with file output at a temporary path
    When I close the logger
    And I try to emit startup with app name "too-late"
    Then the startup call should return an error wrapping "ErrClosed"

  Scenario: EmitStartup on full buffer returns ErrBufferFull
    Given a logger with file output at a temporary path and buffer size 1
    When I fill the buffer and emit startup with app name "full-buffer"
    Then the startup call should return an error wrapping "ErrBufferFull"

  Scenario: EmitStartup called twice succeeds and uses last app name
    Given a logger with file output at a temporary path
    When I emit startup with app name "first-name"
    And I emit startup with app name "second-name"
    And I close the logger
    Then the file should contain an event with event_type "shutdown" and field "app_name" with value "second-name"

  Scenario: Failed EmitStartup means no shutdown on close
    Given a logger with file output at a temporary path
    When I emit startup without app name
    And I close the logger
    Then the file should not contain an event with event_type "shutdown"
