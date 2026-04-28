@core @stdout
Feature: Stdout Output
  As a library consumer, I want non-panicking convenience constructors
  (NewStdout, NewStderr, NewWriter) that wrap an io.Writer in a
  StdoutOutput so that I can emit audit events to a destination I
  choose without writing boilerplate config, and without any
  constructor panicking on a programmatic error.

  The three constructors are thin wrappers over
  NewStdoutOutput(StdoutConfig{Writer: w}) with the Writer field set
  to os.Stdout, os.Stderr, or the caller-supplied io.Writer
  respectively. They replace the panicking Stdout() helper that was
  removed in #578.

  Background:
    Given a standard test taxonomy

  Scenario: NewStdout writes emitted events to os.Stdout
    Given an auditor with output from NewStdout
    When I audit a uniquely marked "user_create" event
    And I close the auditor
    Then the captured stdout should contain the marker

  Scenario: NewStderr writes emitted events to os.Stderr
    Given an auditor with output from NewStderr
    When I audit a uniquely marked "user_create" event
    And I close the auditor
    Then the captured stderr should contain the marker

  Scenario: NewWriter writes emitted events to the supplied io.Writer
    Given an auditor with output from NewWriter pointed at a buffer
    When I audit a uniquely marked "user_create" event
    And I close the auditor
    Then the supplied buffer should contain the marker

  Scenario: NewWriter with nil writer falls back to os.Stdout
    Given an auditor with output from NewWriter with a nil writer
    When I audit a uniquely marked "user_create" event
    And I close the auditor
    Then the captured stdout should contain the marker

  # --- Failure mode: broken pipe / EPIPE downstream (#562) ---
  #
  # The audit stdout output backed by an os.Pipe whose read end is
  # closed must surface EPIPE (or the platform-equivalent
  # "broken pipe" / "closed pipe") to the caller. Operators
  # piping audit logs to a downstream process that exits expect a
  # clean error rather than a silent write that disappears.
  Scenario: Stdout output to a closed pipe surfaces broken-pipe error
    Then a stdout output bound to a closed pipe surfaces the broken-pipe error
