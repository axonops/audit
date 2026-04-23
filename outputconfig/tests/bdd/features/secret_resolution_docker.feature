@secrets @docker
Feature: Secret provider resolution with real containers
  As a library consumer
  I want HMAC configuration resolved from real OpenBao and Vault servers
  So that I can verify end-to-end secret resolution works in production

  These scenarios run against real OpenBao and Vault containers in
  Docker with dev-tls mode. Each scenario runs twice — once per
  provider — via Scenario Outline with Examples.

  Prerequisites:
    make test-infra-openbao-up
    make test-infra-vault-up

  Background:
    Given a test taxonomy

  Scenario Outline: All HMAC fields resolved from real <provider> server
    Given a real <provider> provider at "<addr>" with token "test-root-token" from container "<container>"
    And the real provider has secret at path "secret/data/bdd/hmac" with:
      | key       | value                            |
      | salt      | bdd-real-salt-value-32-bytes!!!! |
      | version   | v1                               |
      | algorithm | HMAC-SHA-256                     |
      | enabled   | true                             |
    When the following output configuration YAML is loaded with the real provider:
      """
      version: 1
      app_name: test
      host: test
      outputs:
        audit_log:
          type: stdout
          hmac:
            enabled: ref+<scheme>://secret/data/bdd/hmac#enabled
            salt:
              version: ref+<scheme>://secret/data/bdd/hmac#version
              value: ref+<scheme>://secret/data/bdd/hmac#salt
            algorithm: ref+<scheme>://secret/data/bdd/hmac#algorithm
      """
    Then the config load should succeed
    And the HMAC config should have salt "bdd-real-salt-value-32-bytes!!!!"
    And the HMAC config should have algorithm "HMAC-SHA-256"

    Examples:
      | provider | scheme  | addr                   | container      |
      | openbao  | openbao | https://localhost:8200  | bdd-openbao-1  |
      | vault    | vault   | https://localhost:8210  | bdd-vault-1    |

  Scenario Outline: Environment variable expanding to ref resolved from real <provider>
    Given a real <provider> provider at "<addr>" with token "test-root-token" from container "<container>"
    And the real provider has secret at path "secret/data/bdd/envref" with:
      | key  | value                            |
      | salt | env-to-ref-salt-value-32-bytes!! |
    And the environment variable "BDD_HMAC_SALT" is set to "ref+<scheme>://secret/data/bdd/envref#salt"
    When the following output configuration YAML is loaded with the real provider:
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
              value: ${BDD_HMAC_SALT}
            algorithm: HMAC-SHA-256
      """
    Then the config load should succeed
    And the HMAC config should have salt "env-to-ref-salt-value-32-bytes!!"

    Examples:
      | provider | scheme  | addr                   | container      |
      | openbao  | openbao | https://localhost:8200  | bdd-openbao-1  |
      | vault    | vault   | https://localhost:8210  | bdd-vault-1    |

  Scenario Outline: Mixed literal, env var, and real <provider> ref in same HMAC config
    Given a real <provider> provider at "<addr>" with token "test-root-token" from container "<container>"
    And the real provider has secret at path "secret/data/bdd/mixed" with:
      | key  | value                            |
      | salt | mixed-real-salt-value-32-bytes!! |
    And the environment variable "BDD_HMAC_VERSION" is set to "v2"
    When the following output configuration YAML is loaded with the real provider:
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
              value: ref+<scheme>://secret/data/bdd/mixed#salt
            algorithm: HMAC-SHA-256
      """
    Then the config load should succeed
    And the HMAC config should have salt "mixed-real-salt-value-32-bytes!!"

    Examples:
      | provider | scheme  | addr                   | container      |
      | openbao  | openbao | https://localhost:8200  | bdd-openbao-1  |
      | vault    | vault   | https://localhost:8210  | bdd-vault-1    |
