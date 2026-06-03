@core @tls
Feature: TLS encrypted-key support (PKCS#8 v2)
  As a library consumer, I want the audit library to load mTLS client
  certificates whose private key file is a PKCS#8 v2 ENCRYPTED PRIVATE
  KEY PEM block, so that I can store the key material at rest in
  encrypted form and unseal it only at output construction time using
  a password sourced from my secret provider.

  The library decrypts PBES2-wrapped keys using PBKDF2-HMAC-SHA1 /
  SHA256 / SHA512 (RFC 8018) or scrypt (RFC 7914), each with
  AES-128/192/256-CBC. Legacy PKCS#1 `Proc-Type: 4,ENCRYPTED` keys
  are refused with audit.ErrLegacyEncryptedPEMKey and the rewrap
  recipe.

  Background:
    Given a standard test taxonomy

  Scenario: PKCS#8 v2 AES-256 key with correct password loads via the helper
    Given a freshly-generated ECDSA P-256 client key encrypted with PBES2/PBKDF2-SHA256/AES-256-CBC and password "correct-horse-battery-staple"
    And a matching self-signed client certificate
    When I call audit.LoadX509KeyPairWithPassword with the correct password
    Then the call should return a tls.Certificate with a parsed PrivateKey
    And no error should be returned

  Scenario: Wrong password keeps the password bytes out of the error
    Given a freshly-generated ECDSA P-256 client key encrypted with PBES2/PBKDF2-SHA256/AES-256-CBC and password "real-password"
    When I call audit.LoadX509KeyPairWithPassword with password "wrong-password"
    Then the call should return an error
    And the helper error message should not contain "real-password"
    And the helper error message should not contain "wrong-password"

  Scenario: Legacy PKCS#1 DEK-Info key is refused with the rewrap recipe
    Given a PEM block with header "Proc-Type: 4,ENCRYPTED"
    When I call audit.LoadX509KeyPairWithPassword with any password
    Then the call should return an error that satisfies errors.Is(err, audit.ErrLegacyEncryptedPEMKey)
    And the helper error message should contain "openssl pkcs8 -topk8 -v2 aes256"

  Scenario: Encrypted key with an empty password is refused
    Given a freshly-generated ECDSA P-256 client key encrypted with PBES2/PBKDF2-SHA256/AES-256-CBC and password "real-password"
    When I call audit.LoadX509KeyPairWithPassword with empty password
    Then the call should return an error containing "requires a non-empty key_password"

  Scenario: Unencrypted key with a non-empty password is refused
    Given a freshly-generated ECDSA P-256 client key in plain PKCS#8 PEM form
    When I call audit.LoadX509KeyPairWithPassword with password "unexpected"
    Then the call should return an error containing "not encrypted"

  Scenario: Plain unencrypted key with empty password still loads
    Given a freshly-generated ECDSA P-256 client key in plain PKCS#8 PEM form
    And a matching self-signed client certificate
    When I call audit.LoadX509KeyPairWithPassword with empty password
    Then the call should return a tls.Certificate with a parsed PrivateKey

  Scenario: Malformed key file produces a PEM-diagnostic error
    Given a key file containing the bytes "not a PEM file"
    When I call audit.LoadX509KeyPairWithPassword with empty password
    Then the call should return an error containing "PEM block"

  Scenario: Missing cert file produces a read-certificate error
    Given a missing cert path "/nonexistent/cert.pem"
    And a freshly-generated ECDSA P-256 client key in plain PKCS#8 PEM form
    When I call audit.LoadX509KeyPairWithPassword with empty password
    Then the call should return an error containing "read certificate"

  Scenario: webhook YAML config parses tls.key_password and redacts it
    Given a webhook YAML config with an encrypted tls.key and tls.key_password "secret-pw-42"
    When I parse the YAML via the webhook factory
    Then Config.TLSKeyPassword should equal "secret-pw-42"
    And Config.String() should contain "tls_key_password=[REDACTED]"
    And Config.String() should not contain "secret-pw-42"

  # Notes (#896): the helper-level scenarios above are covered
  # exhaustively at the unit-test layer in tls_keypair_test.go (9
  # named tests, all passing). The BDD scenarios here lock the
  # contract from the BDD-feature consumer perspective: any future
  # refactor that drops a contract above will fail this feature even
  # if the unit tests are accidentally edited.
