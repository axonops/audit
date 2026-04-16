@core @isolation
Feature: Output Isolation
  As a library consumer, I want a slow or dead output to NOT block
  delivery to other outputs so that a DDoS on one output endpoint
  does not cascade to silence all auditing.

  All outputs except stdout have internal async buffers. Write()
  copies data into a buffered channel and returns immediately. A
  background goroutine handles the actual I/O. This ensures one
  output's I/O latency does not block the drain goroutine from
  delivering to other outputs.

  Background:
    Given a standard test taxonomy

  Scenario: Events delivered to all outputs after close
    Given an auditor with stdout and a recording mock output
    When I audit 5 events rapidly
    And I close the auditor
    Then stdout should have received all 5 events
    And the recording output should have received all 5 events

  Scenario: Stdout remains synchronous
    Given an auditor with stdout output only
    When I audit event "user_create" with required fields
    And I close the auditor
    Then stdout should have received the event before close returned

  Scenario: Multiple recording outputs each receive all events
    Given an auditor with two recording mock outputs
    When I audit 5 events rapidly
    And I close the auditor
    Then both recording outputs should have received all 5 events

  @docker @syslog
  Scenario: Unreachable syslog does not block file delivery
    Given an auditor with file and syslog outputs
    When I stop the syslog-ng process
    And I audit 5 uniquely marked events after syslog down
    And I close the auditor
    Then the file should contain exactly 5 events
