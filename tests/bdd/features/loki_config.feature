@loki
Feature: Loki Output Configuration Validation
  As a library consumer, I want clear error messages when I misconfigure
  the Loki output so that I can fix issues quickly.

  Background:
    Given a standard test taxonomy

  # --- URL validation ---

  Scenario: Empty URL rejected
    When I try to create a loki output with empty URL
    Then the loki construction should fail with an error containing "url must not be empty"

  Scenario: HTTP URL rejected without AllowInsecureHTTP
    When I try to create a loki output to "http://loki:3100/loki/api/v1/push"
    Then the loki construction should fail with an error containing "must be https"

  Scenario: Credentials in URL rejected
    When I try to create a loki output to "https://user:pass@loki:3100/push"
    Then the loki construction should fail with an error containing "must not contain credentials"

  Scenario: FTP scheme rejected
    When I try to create a loki output to "ftp://loki:3100/push"
    Then the loki construction should fail with an error containing "scheme must be http or https"

  # --- Auth mutual exclusivity ---

  Scenario: BasicAuth and BearerToken mutually exclusive
    When I try to create a loki output with basic auth and bearer token
    Then the loki construction should fail with an error containing "mutually exclusive"

  Scenario: BasicAuth with empty username rejected
    When I try to create a loki output with basic auth username "" and password "secret"
    Then the loki construction should fail with an error containing "basic_auth.username must not be empty"

  # --- Static label validation ---

  Scenario Outline: Invalid static label name rejected
    When I try to create a loki output with static label "<name>" = "value"
    Then the loki construction should fail with an error containing "invalid"

    Examples:
      | name       |
      | my-label   |
      | 1bad       |
      | bad name   |
      | my.label   |

  Scenario: Static label with empty value rejected
    When I try to create a loki output with static label "env" = ""
    Then the loki construction should fail with an error containing "empty value"

  Scenario: Static label with control characters rejected
    When I try to create a loki output with static label "env" containing control chars
    Then the loki construction should fail with an error containing "control characters"

  # --- Dynamic label validation ---

  Scenario: Unknown dynamic label rejected
    When I try to create a loki output with unknown dynamic label "actor_id"
    Then the loki construction should fail with an error containing "unknown dynamic label"

  # --- Header validation ---

  Scenario: CRLF in header rejected
    When I try to create a loki output with header containing CRLF
    Then the loki construction should fail with an error containing "CR/LF"

  Scenario Outline: Restricted header rejected
    When I try to create a loki output with restricted header "<header>"
    Then the loki construction should fail with an error containing "managed by the library"

    Examples:
      | header           |
      | Authorization    |
      | X-Scope-OrgID    |
      | Content-Type     |
      | Content-Encoding |
      | Host             |

  # --- Bounds validation ---

  Scenario Outline: Out-of-range <field> rejected
    When I try to create a loki output with <field> set to <value>
    Then the loki construction should fail with an error containing "<field>"

    Examples:
      | field           | value   |
      | batch_size      | -1      |
      | batch_size      | 10001   |
      | buffer_size     | 99      |
      | buffer_size     | 1000001 |
      | max_retries     | -1      |
      | max_retries     | 21      |

  # --- TLS validation ---

  Scenario: TLS cert without key rejected
    When I try to create a loki output with tls_cert but no tls_key
    Then the loki construction should fail with an error containing "tls_cert and tls_key must both be set"

  # --- Config.String() credential redaction ---

  Scenario: Config string redacts basic auth credentials
    Given a loki config with basic auth username "alice" and password "super-secret"
    Then the config string should not contain "alice"
    And the config string should not contain "super-secret"
    And the config string should contain "basic_auth"

  Scenario: Config string redacts bearer token
    Given a loki config with bearer token "jwt-secret-token"
    Then the config string should not contain "jwt-secret-token"
    And the config string should contain "bearer_token"
