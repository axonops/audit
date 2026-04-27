@core @secrets
Feature: Secret reference resolution in output configuration
  As a library consumer
  I want to store sensitive config values (HMAC salts, credentials) in a secret
  store and reference them from the output YAML
  So that plaintext secrets never appear in config files or version control

  # The secret reference syntax is: ref+SCHEME://PATH#KEY
  # where SCHEME identifies the provider, PATH is the secret path
  # within the store, and KEY is the field name within the secret.
  # The "ref+" prefix is mandatory and distinguishes references from
  # literal values.

  Background:
    Given a test taxonomy

  # ---------------------------------------------------------------------------
  # Scenario 1: Literal HMAC values require no secret providers
  # ---------------------------------------------------------------------------
  Scenario: Literal HMAC values work without any secret provider registered
    Given the following output configuration YAML with secret providers:
      """
      version: 1
      app_name: test
      host: test
      outputs:
        audit_log:
          type: stdout
          hmac:
            enabled: true
            salt:
              version: v1
              value: my-literal-salt-32-bytes!!!!!!!
            algorithm: HMAC-SHA-256
      """
    Then the config load should succeed
    And the HMAC config should have salt "my-literal-salt-32-bytes!!!!!!!"
    And the HMAC config should have version "v1"

  # ---------------------------------------------------------------------------
  # Scenario 2: Environment variable HMAC values work without secret providers
  # ---------------------------------------------------------------------------
  Scenario: Environment variable HMAC values work without any secret provider registered
    Given the environment variable "BDD_HMAC_SALT_LITERAL" is set to "literal-salt-value-32-bytes!!!!!"
    And the following output configuration YAML with secret providers:
      """
      version: 1
      app_name: test
      host: test
      outputs:
        audit_log:
          type: stdout
          hmac:
            enabled: true
            salt:
              version: v1
              value: ${BDD_HMAC_SALT_LITERAL}
            algorithm: HMAC-SHA-256
      """
    Then the config load should succeed
    And the HMAC config should have salt "literal-salt-value-32-bytes!!!!!"
    And the HMAC config should have version "v1"

  # ---------------------------------------------------------------------------
  # Scenario 3: Secret reference resolved from a registered provider
  # ---------------------------------------------------------------------------
  Scenario: Secret reference is resolved when a matching provider is registered
    Given a mock secret provider with scheme "mock"
    And the mock provider has secret at path "secret/data/hmac" key "salt" value "resolved-salt-value-32-bytes!!!!"
    And the mock provider has secret at path "secret/data/hmac" key "version" value "v2"
    And the following output configuration YAML with secret providers:
      """
      version: 1
      app_name: test
      host: test
      outputs:
        audit_log:
          type: stdout
          hmac:
            enabled: true
            salt:
              version: ref+mock://secret/data/hmac#version
              value: ref+mock://secret/data/hmac#salt
            algorithm: HMAC-SHA-256
      """
    Then the config load should succeed
    And the HMAC config should have salt "resolved-salt-value-32-bytes!!!!"
    And the HMAC config should have version "v2"
    And the HMAC config should have algorithm "HMAC-SHA-256"

  # ---------------------------------------------------------------------------
  # Scenario 4: Environment variable that expands to a ref is then resolved
  # ---------------------------------------------------------------------------
  Scenario: Environment variable that expands to a secret reference is resolved
    Given a mock secret provider with scheme "mock"
    And the mock provider has secret at path "secret/data/hmac" key "salt" value "env-indirected-salt-32-bytes!!!!"
    And the environment variable "BDD_HMAC_SALT_REF" is set to "ref+mock://secret/data/hmac#salt"
    And the following output configuration YAML with secret providers:
      """
      version: 1
      app_name: test
      host: test
      outputs:
        audit_log:
          type: stdout
          hmac:
            enabled: true
            salt:
              version: v1
              value: ${BDD_HMAC_SALT_REF}
            algorithm: HMAC-SHA-256
      """
    Then the config load should succeed
    And the HMAC config should have salt "env-indirected-salt-32-bytes!!!!"
    And the HMAC config should have version "v1"

  # ---------------------------------------------------------------------------
  # Scenario 5: Inline literal, env-var, and ref can be mixed in the same config
  # ---------------------------------------------------------------------------
  Scenario: Inline literal, environment variable, and secret reference can be mixed in the same HMAC config
    Given a mock secret provider with scheme "mock"
    And the mock provider has secret at path "secret/data/hmac" key "salt" value "mixed-source-salt-32-bytes!!!!!!"
    And the environment variable "BDD_HMAC_VERSION" is set to "v3"
    And the following output configuration YAML with secret providers:
      """
      version: 1
      app_name: test
      host: test
      outputs:
        audit_log:
          type: stdout
          hmac:
            enabled: true
            salt:
              version: ${BDD_HMAC_VERSION}
              value: ref+mock://secret/data/hmac#salt
            algorithm: HMAC-SHA-256
      """
    Then the config load should succeed
    And the HMAC config should have salt "mixed-source-salt-32-bytes!!!!!!"
    And the HMAC config should have version "v3"
    And the HMAC config should have algorithm "HMAC-SHA-256"

  # ---------------------------------------------------------------------------
  # Scenario 6: Unresolved reference fails when no provider is registered
  #
  # A ref+ URI in a top-level field (app_name) is caught by the safety-net
  # scanner that runs after env-var expansion regardless of whether a provider
  # is registered.
  # ---------------------------------------------------------------------------
  Scenario: Unresolved secret reference fails with a clear error when no provider is registered
    Given the following output configuration YAML with secret providers:
      """
      version: 1
      app_name: ref+openbao://secret/data/config#app
      host: test
      outputs:
        audit_log:
          type: stdout
      """
    Then the config load should fail with an error containing "unresolved secret reference"

  # ---------------------------------------------------------------------------
  # Scenario 7: Unregistered scheme is rejected
  # ---------------------------------------------------------------------------
  Scenario: A ref with a scheme for which no provider is registered is rejected
    Given a mock secret provider with scheme "mock"
    And the mock provider has secret at path "secret/data/hmac" key "salt" value "registered-salt-32-bytes!!!!!!!!"
    And the following output configuration YAML with secret providers:
      """
      version: 1
      app_name: test
      host: test
      outputs:
        audit_log:
          type: stdout
          hmac:
            enabled: true
            salt:
              version: v1
              value: ref+vault://secret/data/hmac#salt
            algorithm: HMAC-SHA-256
      """
    Then the config load should fail with an error containing "no provider registered for scheme"

  # ---------------------------------------------------------------------------
  # Scenario 8: Malformed ref with missing key fragment is rejected
  # ---------------------------------------------------------------------------
  Scenario: A secret reference with a missing key fragment is rejected as malformed
    Given a mock secret provider with scheme "mock"
    And the following output configuration YAML with secret providers:
      """
      version: 1
      app_name: test
      host: test
      outputs:
        audit_log:
          type: stdout
          hmac:
            enabled: true
            salt:
              version: v1
              value: ref+mock://secret/data/hmac
            algorithm: HMAC-SHA-256
      """
    Then the config load should fail with an error containing "malformed secret reference"

  # ---------------------------------------------------------------------------
  # Scenario 9: Path with traversal segments is rejected
  # ---------------------------------------------------------------------------
  Scenario: A secret reference containing path traversal segments is rejected
    Given a mock secret provider with scheme "mock"
    And the following output configuration YAML with secret providers:
      """
      version: 1
      app_name: test
      host: test
      outputs:
        audit_log:
          type: stdout
          hmac:
            enabled: true
            salt:
              version: v1
              value: ref+mock://secret/../data/hmac#salt
            algorithm: HMAC-SHA-256
      """
    Then the config load should fail with an error containing "malformed secret reference"

  # ---------------------------------------------------------------------------
  # Scenario 10: Error message does not contain the resolved secret value
  # ---------------------------------------------------------------------------
  Scenario: Error messages never contain resolved secret values
    Given a mock secret provider with scheme "mock"
    And the mock provider has secret at path "secret/data/hmac" key "salt" value "SUPER-SECRET-MUST-NOT-APPEAR-IN-ERRORS"
    And the mock provider has secret at path "secret/data/hmac" key "enabled" value "true"
    And the following output configuration YAML with secret providers:
      """
      version: 1
      app_name: test
      host: test
      outputs:
        audit_log:
          type: stdout
          hmac:
            enabled: ref+mock://secret/data/hmac#enabled
            salt:
              version: v1
              value: ref+mock://secret/data/hmac#salt
            algorithm: ref+mock://nonexistent/path#algorithm
      """
    Then the config load should fail
    And the error message should not contain "SUPER-SECRET-MUST-NOT-APPEAR-IN-ERRORS"

  # ---------------------------------------------------------------------------
  # Scenario 11: HMAC disabled via secret store skips remaining refs
  # ---------------------------------------------------------------------------
  Scenario: When HMAC enabled is resolved to false via a secret ref the remaining refs are not fetched
    Given a mock secret provider with scheme "mock"
    And the mock provider has secret at path "secret/data/hmac" key "enabled" value "false"
    And the following output configuration YAML with secret providers:
      """
      version: 1
      app_name: test
      host: test
      outputs:
        audit_log:
          type: stdout
          hmac:
            enabled: ref+mock://secret/data/hmac#enabled
            salt:
              version: ref+mock://nonexistent/path#version
              value: ref+mock://nonexistent/path#salt
            algorithm: ref+mock://nonexistent/path#algorithm
      """
    Then the config load should succeed
    And the mock provider call count should be 1

  # ---------------------------------------------------------------------------
  # Scenario 12: HMAC enabled via secret store requires all fields to resolve
  # ---------------------------------------------------------------------------
  Scenario: When HMAC enabled is resolved to true via a secret ref all other HMAC fields must also resolve
    Given a mock secret provider with scheme "mock"
    And the mock provider has secret at path "secret/data/hmac" key "enabled" value "true"
    And the following output configuration YAML with secret providers:
      """
      version: 1
      app_name: test
      host: test
      outputs:
        audit_log:
          type: stdout
          hmac:
            enabled: ref+mock://secret/data/hmac#enabled
            salt:
              version: v1
              value: ref+mock://nonexistent/path#salt
            algorithm: HMAC-SHA-256
      """
    Then the config load should fail with an error containing "secret not found"

  # ---------------------------------------------------------------------------
  # Scenario 13: HMAC disabled with non-existent vault paths does not error
  # ---------------------------------------------------------------------------
  Scenario: HMAC with enabled as literal false and non-existent ref paths does not error and needs no provider
    Given the following output configuration YAML with secret providers:
      """
      version: 1
      app_name: test
      host: test
      outputs:
        audit_log:
          type: stdout
          hmac:
            enabled: false
            salt:
              version: ref+nonexistent://path/does/not/matter#version
              value: ref+nonexistent://path/does/not/matter#salt
            algorithm: ref+nonexistent://path/does/not/matter#hash
      """
    Then the config load should succeed

  # ---------------------------------------------------------------------------
  # Scenario 14: Same ref used in multiple outputs is resolved once
  # ---------------------------------------------------------------------------
  Scenario: The same secret reference used in multiple outputs is resolved exactly once per Load call
    Given a mock secret provider with scheme "mock"
    And the mock provider has secret at path "secret/data/config" key "name" value "shared-app-name"
    And the following output configuration YAML with secret providers:
      """
      version: 1
      app_name: ref+mock://secret/data/config#name
      host: ref+mock://secret/data/config#name
      outputs:
        console:
          type: stdout
      """
    Then the config load should succeed
    And the mock provider call count should be 1

  # ---------------------------------------------------------------------------
  # Scenario: Resolver cache does not leak across Load invocations (#479)
  # ---------------------------------------------------------------------------
  # Proves the resolver's in-memory caches (pathCache, refCache) do
  # not persist across Load calls — a second Load with the same
  # provider and same refs must re-consult the provider. This is the
  # observable contract of the clearCaches() call in Load plus the
  # natural fact that each Load builds a fresh resolver. Defence
  # against a future refactor accidentally sharing state across
  # Loads (e.g. a package-level cache).
  Scenario: Resolver cache does not leak across Load invocations
    Given a mock secret provider with scheme "mock"
    And the mock provider has secret at path "secret/data/hmac" key "salt" value "salt-32-bytes-long-value!!!!!!!!"
    And the mock provider has secret at path "secret/data/hmac" key "version" value "v1"
    When I load the following output configuration YAML with secret providers twice:
      """
      version: 1
      app_name: test
      host: test
      outputs:
        audit_log:
          type: stdout
          hmac:
            enabled: true
            salt:
              version: ref+mock://secret/data/hmac#version
              value: ref+mock://secret/data/hmac#salt
            algorithm: HMAC-SHA-256
      """
    Then the config load should succeed
    And the mock provider call count should be 2

  # ---------------------------------------------------------------------------
  # Scenario 15: Provider timeout produces a clear error
  # ---------------------------------------------------------------------------
  Scenario: A secret provider that does not respond within the timeout produces a clear error
    Given a mock secret provider with scheme "slow" that delays 500ms
    And the mock provider has secret at path "secret/data/hmac" key "salt" value "any-value"
    And the secret resolution timeout is 50ms
    And the following output configuration YAML with secret providers:
      """
      version: 1
      app_name: test
      host: test
      outputs:
        audit_log:
          type: stdout
          hmac:
            enabled: true
            salt:
              version: v1
              value: ref+slow://secret/data/hmac#salt
            algorithm: HMAC-SHA-256
      """
    Then the config load should fail with an error containing "context"

  # ---------------------------------------------------------------------------
  # Scenario 16: Mixed literal, env-var, and ref in the same config
  # ---------------------------------------------------------------------------
  Scenario: Literal values, environment variables, and secret references coexist in the same config
    Given a mock secret provider with scheme "mock"
    And the mock provider has secret at path "secret/data/svc" key "app" value "svc-from-vault"
    And the environment variable "BDD_HOST_VALUE" is set to "host-from-env"
    And the following output configuration YAML with secret providers:
      """
      version: 1
      app_name: ref+mock://secret/data/svc#app
      host: ${BDD_HOST_VALUE}
      outputs:
        console:
          type: stdout
      """
    Then the config load should succeed
    And the loaded auditor metadata should have app_name "svc-from-vault"
    And the loaded auditor metadata should have host "host-from-env"

  # ---------------------------------------------------------------------------
  # Scenario 17: Disabled output with unresolvable refs does not cause an error
  # ---------------------------------------------------------------------------
  Scenario: An output with enabled false and secret references in its type config does not error on load
    Given the following output configuration YAML with secret providers:
      """
      version: 1
      app_name: test
      host: test
      outputs:
        active:
          type: stdout
        disabled_with_refs:
          enabled: false
          type: stdout
          stdout:
            format: ref+nonexistent://path/does/not/matter#format
      """
    Then the config load should succeed
    And the loaded outputs should number 1
    And the loaded outputs should not include "disabled_with_refs"

  # ---------------------------------------------------------------------------
  # Scenario 18: HMAC enabled as literal boolean true with ref salt
  # ---------------------------------------------------------------------------
  Scenario: HMAC enabled as literal boolean true resolves ref+ salt value from a provider
    Given a mock secret provider with scheme "mock"
    And the mock provider has secret at path "secret/data/hmac" key "salt" value "literal-true-resolved-salt-32bytes"
    And the mock provider has secret at path "secret/data/hmac" key "version" value "v4"
    And the following output configuration YAML with secret providers:
      """
      version: 1
      app_name: test
      host: test
      outputs:
        audit_log:
          type: stdout
          hmac:
            enabled: true
            salt:
              version: ref+mock://secret/data/hmac#version
              value: ref+mock://secret/data/hmac#salt
            algorithm: HMAC-SHA-256
      """
    Then the config load should succeed
    And the HMAC config should have salt "literal-true-resolved-salt-32bytes"
    And the HMAC config should have version "v4"

  # ---------------------------------------------------------------------------
  # Scenario 19: Secret reference resolved in a non-HMAC field
  # ---------------------------------------------------------------------------
  Scenario: Secret reference in a CEF formatter vendor field is resolved from a provider
    Given a mock secret provider with scheme "mock"
    And the mock provider has secret at path "secret/data/cef" key "vendor" value "AcmeCorp"
    And the following output configuration YAML with secret providers:
      """
      version: 1
      app_name: test
      host: test
      outputs:
        audit_log:
          type: stdout
          formatter:
            type: cef
            vendor: ref+mock://secret/data/cef#vendor
            product: AuditService
            version: "1.0"
      """
    Then the config load should succeed

  # ---------------------------------------------------------------------------
  # Scenario 20: Duplicate provider scheme returns error
  # ---------------------------------------------------------------------------
  Scenario: Registering two providers with the same scheme causes Load to fail with a clear error
    Given a mock secret provider with scheme "mock"
    And a mock secret provider with scheme "mock"
    And the following output configuration YAML with secret providers:
      """
      version: 1
      app_name: test
      host: test
      outputs:
        audit_log:
          type: stdout
      """
    Then the config load should fail with an error containing "duplicate secret provider for scheme"

  # ---------------------------------------------------------------------------
  # Scenario 21: Nil provider rejected
  # ---------------------------------------------------------------------------
  Scenario: A nil secret provider passed to WithSecretProvider is rejected with a clear error
    Given a nil secret provider is registered
    And the following output configuration YAML with secret providers:
      """
      version: 1
      app_name: test
      host: test
      outputs:
        audit_log:
          type: stdout
      """
    Then the config load should fail with an error containing "secret provider must not be nil"

  # ---------------------------------------------------------------------------
  # Scenario 22: Single-pass guarantee
  # ---------------------------------------------------------------------------
  Scenario: A provider that returns a value containing ref+ causes the safety-net to reject the config
    Given a mock secret provider with scheme "mock"
    And the mock provider has secret at path "secret/data/hmac" key "salt" value "ref+mock://secret/data/hmac#other"
    And the following output configuration YAML with secret providers:
      """
      version: 1
      app_name: ref+mock://secret/data/hmac#salt
      host: test
      outputs:
        audit_log:
          type: stdout
      """
    Then the config load should fail with an error containing "unresolved secret reference"

  # ---------------------------------------------------------------------------
  # Scenario 23: Vault provider with expired server certificate (#552 AC#2)
  #
  # The provider points at an in-process HTTPS receiver presenting a
  # cert that is signed by the runtime CA the audit client trusts but
  # whose NotAfter is one hour in the past. The TLS handshake must fail
  # with "expired" rather than the provider hanging or silently
  # succeeding. The error surfaces through outputconfig.Load because
  # provider.Resolve is what runs the HTTPS GET.
  # ---------------------------------------------------------------------------
  Scenario: Vault provider rejects an expired server certificate during Load
    Given a vault HTTPS provider with an expired server certificate
    And the following output configuration YAML with secret providers:
      """
      version: 1
      app_name: test
      host: test
      outputs:
        audit_log:
          type: stdout
          hmac:
            enabled: true
            salt:
              version: v1
              value: ref+vault://secret/data/hmac#salt
            algorithm: HMAC-SHA-256
      """
    Then the config load should fail with an error containing "expired"

  # ---------------------------------------------------------------------------
  # Scenario 24: OpenBao provider with expired server certificate (#552 AC#2)
  # ---------------------------------------------------------------------------
  Scenario: OpenBao provider rejects an expired server certificate during Load
    Given an openbao HTTPS provider with an expired server certificate
    And the following output configuration YAML with secret providers:
      """
      version: 1
      app_name: test
      host: test
      outputs:
        audit_log:
          type: stdout
          hmac:
            enabled: true
            salt:
              version: v1
              value: ref+openbao://secret/data/hmac#salt
            algorithm: HMAC-SHA-256
      """
    Then the config load should fail with an error containing "expired"
