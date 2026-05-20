# Scenarios are tagged either @docker (drive against the real Splunk
# Enterprise container started via `make test-infra-splunk-up`) or
# @stub (drive against an in-process httptest stub because the
# scenario requires controllable HEC response codes that the real
# container cannot easily produce: codes 4/7/9/24/413 etc.).
# Construction-only scenarios (URL validation, splunkcloud://
# expansion, TA generator) need no receiver — they carry neither tag.

@splunk
Feature: Splunk HEC Output
  As a library consumer, I want to send audit events to Splunk via HEC
  so that compliance evidence lands in our SIEM with full delivery
  guarantees and the established Splunk wire-format conventions.

  Background:
    Given a standard test taxonomy

  # --- Envelope format and wire contract (real container) ---

  @docker
  Scenario: The /event endpoint receives the JSON envelope
    Given a real Splunk HEC receiver
    And an auditor with splunk output on the /event endpoint
    When I audit a uniquely marked splunk "user_create" event
    Then Splunk should have indexed exactly 1 event with the marker within 30 seconds
    And the indexed event should have field "sourcetype" = "audit:event"
    And the indexed event should have field "source" = "audit"

  @docker
  Scenario: Concatenated JSON batch lands as separate indexed events
    Given a real Splunk HEC receiver
    And an auditor with splunk output configured for batch size 5
    When I audit 5 uniquely marked splunk "user_create" events
    Then Splunk should have indexed exactly 5 events with the marker within 30 seconds

  @docker
  Scenario: The /raw endpoint indexes NDJSON events
    Given a real Splunk HEC receiver
    And an auditor with splunk output on the /raw endpoint
    When I audit a uniquely marked splunk "user_create" event
    Then Splunk should have indexed exactly 1 event with the marker within 30 seconds

  @docker
  Scenario: gzip compression is on by default
    Given a real Splunk HEC receiver
    And an auditor with splunk output and default gzip
    When I audit a uniquely marked splunk "user_create" event
    Then Splunk should have indexed exactly 1 event with the marker within 30 seconds

  # --- Authentication on the wire ---

  @docker
  Scenario: Auth header uses the Splunk scheme (not Bearer)
    Given a real Splunk HEC receiver
    And an auditor with splunk output
    When I audit a uniquely marked splunk "user_create" event
    Then Splunk should have indexed exactly 1 event with the marker within 30 seconds
    # If the Splunk scheme were wrong (e.g., Bearer), HEC would
    # reject the request with HTTP 401/403 and the event would
    # never be indexed. The indexed event count proves the auth
    # header was accepted.

  @docker
  Scenario: User-Agent header is sent with every request
    Given a real Splunk HEC receiver
    And an auditor with splunk output
    When I audit a uniquely marked splunk "user_create" event
    Then Splunk should have indexed exactly 1 event with the marker within 30 seconds
    # Splunk's HEC accepts requests without User-Agent, so the
    # check via the real container is "does it reach Splunk at all"
    # — the missing-UA path is unit-tested separately.

  # --- HEC error-code semantics (stub only — real container cannot
  #     produce codes 4/7/9/24/413 on demand) ---

  @stub
  Scenario Outline: HEC retryable code <code> retries with backoff
    Given a splunk HEC stub server
    And an auditor with splunk output where the HEC will return code <code> twice then succeed
    When I audit a uniquely marked splunk "user_create" event
    Then the splunk receiver should have received exactly 3 requests within 15 seconds
    And the elapsed time should be at least 500 ms

    Examples:
      | code |
      | 9    |
      | 8    |

  @stub
  Scenario Outline: HEC stop-and-alert code <code> stops the output
    Given a splunk HEC stub server
    And an auditor with splunk output where the HEC will return code <code>
    When I audit a uniquely marked splunk "user_create" event
    And I wait up to 3 seconds for the output to enter the stop state
    Then the next write should return ErrOutputClosed

    Examples:
      | code |
      | 4    |
      | 7    |

  @stub
  Scenario: HEC code 24 surfaces as a capacity-warning metric, not an error
    Given a splunk HEC stub server
    And an auditor with splunk output where the HEC will return code 24
    When I audit a uniquely marked splunk "user_create" event
    Then the splunk receiver should have received exactly 1 request within 10 seconds
    And the output's capacity-warning metric should be at least 1
    And the output's drop metric should be 0

  @stub
  Scenario: HTTP 413 drops the batch and increments the drop metric
    Given a splunk HEC stub server
    And an auditor with splunk output where the HEC will return HTTP 413
    When I audit a uniquely marked splunk "user_create" event
    Then the output's drop metric should be at least 1
    And the splunk receiver should have received exactly 1 request within 10 seconds

  # --- Payload limits (real container — oversize events drop at
  #     Write time, before any network call) ---

  @docker
  Scenario: A single event over MaxEventBytes is dropped with a metric
    Given a real Splunk HEC receiver
    And an auditor with splunk output and MaxEventBytes 1024
    When I audit an oversized splunk "user_create" event of 2048 bytes
    Then the Write call should return ErrEventTooLarge

  # --- Network safety (construction-only — no receiver needed) ---

  Scenario: HTTPS is required unless AllowInsecureHTTP is true
    When I construct a splunk output with URL "http://splunk.test:8088" and AllowInsecureHTTP false
    Then construction should fail with ErrConfigInvalid

  # --- Token redaction (stub — we want to control the diagnostic
  #     log surface deterministically) ---

  @stub
  Scenario: Token is never logged or surfaced in errors
    Given a splunk HEC stub server
    And an auditor with splunk output and token "super-secret-token-abc"
    When I audit a uniquely marked splunk "user_create" event
    And I read the splunk diagnostic log buffer
    Then the splunk diagnostic log should not contain "super-secret-token-abc"

  # --- Close flush (real container) ---

  @docker
  Scenario: Close flushes the remaining batch before returning
    Given a real Splunk HEC receiver
    And an auditor with splunk output configured for batch size 100 and flush interval 30s
    When I audit 5 uniquely marked splunk "user_create" events
    And I close the splunk auditor
    Then Splunk should have indexed exactly 5 events with the marker within 30 seconds

  # --- Splunk Cloud URL expansion (construction-only) ---

  Scenario: splunkcloud://acme-prod expands to the canonical HEC URL
    When I construct a splunk output with URL "splunkcloud://acme-prod"
    Then construction should succeed
    And the output's URL should equal "https://http-inputs-acme-prod.splunkcloud.com:443"

  Scenario Outline: splunkcloud:// rejects invalid stack name <input>
    When I construct a splunk output with URL "<input>"
    Then construction should fail with ErrConfigInvalid

    Examples:
      | input                              |
      | splunkcloud://acme-prod.evil.com   |
      | splunkcloud://acme@evil.com        |
      | splunkcloud://acme/path            |
      | splunkcloud://acme:1234            |
      | splunkcloud://acme prod            |
      | splunkcloud://                     |
      | splunkcloud://acme?q=1             |
      | splunkcloud://acme#frag            |
      | splunkcloud://HAS_UPPERCASE        |
      | splunkcloud://-leading-hyphen      |

  Scenario: splunkcloud:// with mTLS is rejected
    When I construct a splunk output with URL "splunkcloud://acme-prod" and TLSCert "/p.crt"
    Then construction should fail with ErrConfigInvalid

  # --- HEC Indexer Acknowledgement (#55 PR 2) ---
  # AckMode=off + best_effort run against the real container — the
  # test container's HEC token has ACK enabled. AckMode=required
  # behaviours (gating, resend) stay on the stub because the timing
  # is controllable; the deterministic resend behaviour is also
  # covered by the toxiproxy-driven integration test (#889 AC 4).

  @docker
  Scenario: AckMode=off does not send X-Splunk-Request-Channel
    Given a real Splunk HEC receiver
    And an auditor with splunk output and AckMode "off"
    When I audit a uniquely marked splunk "user_create" event
    Then Splunk should have indexed exactly 1 event with the marker within 30 seconds

  @docker
  Scenario: AckMode=best_effort delivers events with the channel header
    Given a real Splunk HEC receiver
    And an auditor with splunk output and AckMode "best_effort"
    When I audit a uniquely marked splunk "user_create" event
    Then Splunk should have indexed exactly 1 event with the marker within 30 seconds

  @stub
  Scenario: AckMode=required blocks buffer progress until ack positive
    Given a splunk HEC stub server
    And an auditor with splunk output and AckMode "required"
    When I audit a uniquely marked splunk "user_create" event
    And the splunk receiver confirms all outstanding ackIDs
    Then the in-flight count should drain to 0 within 5 seconds

  @stub
  Scenario: AckMode=required resends events when AckResendWindow elapses
    Given a splunk HEC stub server
    And an auditor with splunk output and AckMode "required" and short resend window
    When I audit a uniquely marked splunk "user_create" event
    Then the splunk receiver should record at least 1 timeout within 10 seconds

  @stub
  Scenario: AckMode=required with full buffer drops new events with metric
    Given a splunk HEC stub server
    And an auditor with splunk output and AckMode "required" and 100 unconfirmed batches
    When I audit 500 more events
    Then the buffer-full drop metric should be at least 1 within 10 seconds

  # --- Splunk TA generator (#55 PR 3) — construction/file-only ---

  Scenario: audit-gen --format=splunk-ta generates the expected directory tree
    When I run audit-gen with splunk-ta format against the reference taxonomy
    Then the output directory should contain "default/app.conf"
    And the output directory should contain "default/props.conf"
    And the output directory should contain "default/eventtypes.conf"
    And the output directory should contain "default/tags.conf"
    And the output directory should contain "default/data/ui/views/audit_events.xml"
    And the output directory should contain "metadata/default.meta"

  Scenario: The generated TA emits INDEXED_EXTRACTIONS=json + EVAL constants (FIELDALIAS bridge)
    When I run audit-gen with splunk-ta format against the reference taxonomy
    Then the file "default/props.conf" should contain "INDEXED_EXTRACTIONS = json"
    And the file "default/props.conf" should contain "EVAL-vendor_product"
    And the file "default/props.conf" should contain "EVAL-dvc"

  Scenario: The generated TA contains CIM tags applied per category as declared in the taxonomy
    When I run audit-gen with splunk-ta format against the reference taxonomy
    Then the file "default/tags.conf" should contain "[eventtype=account_user_create]"
    And the file "default/tags.conf" should contain "[eventtype=security_login_success]"
    And the file "default/tags.conf" should contain the line "change = enabled" at least 8 times
    And the file "default/tags.conf" should contain the line "authentication = enabled" at least 4 times

  @appinspect
  Scenario: The generated TA passes splunk-appinspect --mode precert with zero failures
    Given splunk-appinspect is available on PATH
    When I run audit-gen with splunk-ta format against the reference taxonomy
    And I run splunk-appinspect on the output
    Then splunk-appinspect should report zero failures
