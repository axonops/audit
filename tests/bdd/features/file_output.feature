@file
Feature: File Output
  As a library consumer, I want to write audit events to a log file
  so that I have a persistent local record of all audit activity.

  The file output supports automatic rotation by size, backup retention,
  gzip compression, and configurable permissions. Symlinks are rejected
  for security.

  Background:
    Given a standard test taxonomy

  # --- Write & format ---

  Scenario: Write JSON event to file with complete field verification
    Given a logger with file output at a temporary path
    When I audit event "user_create" with fields:
      | field       | value      |
      | outcome     | success    |
      | actor_id    | alice      |
      | marker      | file_test  |
      | target_id   | user-42    |
    And I close the logger
    Then every event in the file should be valid JSON
    And the file should contain an event matching:
      | field       | value       |
      | event_type  | user_create |
      | outcome     | success     |
      | actor_id    | alice       |
      | marker      | file_test   |
      | target_id   | user-42     |
      | target_type |             |
      | reason      |             |
      | source_ip   |             |
      | user_agent  |             |
      | request_id  |             |
      | duration_ms |             |

  Scenario: Multiple writes produce one event per line
    Given a logger with file output at a temporary path
    When I audit 5 events rapidly
    And I close the logger
    Then the file should contain exactly 5 events
    And every event in the file should be valid JSON

  Scenario: Concurrent writes do not interleave lines
    Given a logger with file output at a temporary path
    When I audit 100 events from 10 concurrent goroutines
    And I close the logger
    Then the file should contain exactly 100 events
    And every event in the file should be valid JSON

  # --- Permissions ---

  Scenario: Default file permissions are 0600
    Given a logger with file output at a temporary path
    When I audit event "user_create" with required fields
    And I close the logger
    Then the file should have permissions "0600"

  Scenario: Custom file permissions are applied
    Given a logger with file output with permissions "0640"
    When I audit event "user_create" with required fields
    And I close the logger
    Then the file should have permissions "0640"

  Scenario: Symlink path is rejected at construction
    When I try to create a file output with a symlink path
    Then the file output construction should fail with an error

  # --- Rotation ---

  Scenario: File rotates when MaxSizeMB exceeded
    Given a logger with file output configured for 1 MB max size
    When I write enough events to exceed 1 MB
    And I close the logger
    Then more than one file should exist in the output directory

  Scenario: Rotated backup has timestamp in filename
    Given a logger with file output configured for 1 MB max size
    When I write enough events to exceed 1 MB
    And I close the logger
    Then a backup file with a timestamp pattern should exist in the output directory

  Scenario: Compressed backups have .gz extension
    Given a logger with file output configured for 1 MB max size with compression
    When I write enough events to exceed 1 MB
    And I close the logger
    Then a .gz backup file should exist in the output directory

  Scenario: Compression disabled preserves plain backup
    Given a logger with file output configured for 1 MB max size without compression
    When I write enough events to exceed 1 MB
    And I close the logger
    Then no .gz files should exist in the output directory

  # --- Config validation ---

  Scenario: Empty path is rejected with exact error
    When I try to create a file output with empty path
    Then the file output construction should fail with error:
      """
      audit: file output path must not be empty
      """

  Scenario: MaxSizeMB exceeding limit is rejected
    When I try to create a file output with MaxSizeMB 20000
    Then the file output construction should fail with an error

  Scenario: Non-existent parent directory is rejected
    When I try to create a file output at "/nonexistent/dir/audit.log"
    Then the file output construction should fail with an error

  Scenario: MaxBackups exceeding limit is rejected
    When I try to create a file output with MaxBackups 200
    Then the file output construction should fail with an error

  Scenario: Invalid permissions string is rejected
    When I try to create a file output with permissions "notoctal"
    Then the file output construction should fail with an error

  # --- Lifecycle ---

  Scenario: Write after close returns error
    Given a logger with file output at a temporary path
    When I close the logger
    And I try to audit event "user_create" with required fields
    Then the audit call should return an error wrapping "ErrClosed"

  Scenario: Close is idempotent
    Given a logger with file output at a temporary path
    When I audit event "user_create" with required fields
    And I close the logger
    And I close the logger again
    Then the second close should return no error

  # --- File-specific metrics ---

  Scenario: Rotation triggers RecordFileRotation callback
    Given mock file metrics are configured
    And a logger with file output configured for 1 MB max size with file metrics
    When I write enough events to exceed 1 MB
    And I close the logger
    Then the file metrics should have recorded at least 1 rotation

  Scenario: MaxBackups enforced — excess deleted
    Given a logger with file output configured for 1 MB max size and max backups 2
    When I write enough events to exceed 4 MB
    And I close the logger
    Then at most 3 files should exist in the output directory

  Scenario: Multiple rotations trigger multiple metric callbacks
    Given mock file metrics are configured
    And a logger with file output configured for 1 MB max size with file metrics
    When I write enough events to exceed 3 MB
    And I close the logger
    Then the file metrics should have recorded at least 2 rotations

  Scenario: Nil file metrics does not panic on rotation
    Given a logger with file output configured for 1 MB max size
    When I write enough events to exceed 1 MB
    And I close the logger
    Then the file should contain events
