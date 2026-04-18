@core @ssrf
Feature: SSRF protection classifies every blocked address with a typed reason
  As a consumer operating in a cloud environment, I want every SSRF
  rejection to expose a structured reason so I can route metrics and
  alerting on why an address was blocked (cloud metadata exfil
  attempt vs. config typo vs. legitimate private-range block).

  The library's public `CheckSSRFIP` function returns a typed error
  `*audit.SSRFBlockedError` whose `Reason` field is one of the
  stable `SSRFReason*` constants. The sentinel `ErrSSRFBlocked` is
  always wrapped for broad `errors.Is` discrimination.

  Background:
    Given I want to classify SSRF rejections by reason

  # --- Cloud metadata endpoints (always blocked) ---

  Scenario Outline: Cloud metadata address <description> is blocked with reason cloud_metadata
    When I check SSRF classification for IP "<ip>" with AllowPrivateRanges "<allow_private>"
    Then the SSRF classification should wrap ErrSSRFBlocked
    And the SSRF classification reason should be "cloud_metadata"

    Examples:
      | ip                       | allow_private | description                                  |
      | 169.254.169.254          | false         | AWS/GCP/Azure IPv4 IMDS (default config)     |
      | 169.254.169.254          | true          | AWS/GCP/Azure IPv4 IMDS (with AllowPrivate)  |
      | fd00:ec2::254            | false         | AWS IMDSv2 over IPv6                         |
      | fd00:ec2::254            | true          | AWS IMDSv2 over IPv6 (with AllowPrivate)     |
      | ::ffff:169.254.169.254   | false         | IPv4-mapped IPv6 alias of IPv4 IMDS          |

  # --- CGNAT (RFC 6598) ---

  Scenario Outline: CGNAT address <ip> is blocked with reason cgnat
    When I check SSRF classification for IP "<ip>" with AllowPrivateRanges "true"
    Then the SSRF classification should wrap ErrSSRFBlocked
    And the SSRF classification reason should be "cgnat"

    Examples:
      | ip            |
      | 100.64.0.1    |
      | 100.127.255.1 |

  # --- Deprecated IPv6 site-local (fec0::/10) ---

  Scenario Outline: Deprecated site-local IPv6 <ip> is blocked with reason deprecated_site_local
    When I check SSRF classification for IP "<ip>" with AllowPrivateRanges "true"
    Then the SSRF classification should wrap ErrSSRFBlocked
    And the SSRF classification reason should be "deprecated_site_local"

    Examples:
      | ip      |
      | fec0::1 |
      | fec0::f |

  # --- Link-local ---

  Scenario Outline: Link-local address <ip> is blocked with reason link_local
    When I check SSRF classification for IP "<ip>" with AllowPrivateRanges "false"
    Then the SSRF classification should wrap ErrSSRFBlocked
    And the SSRF classification reason should be "link_local"

    Examples:
      | ip          |
      | 169.254.0.1 |
      | fe80::1     |

  # --- Multicast ---

  Scenario Outline: Multicast address <ip> is blocked with reason multicast
    When I check SSRF classification for IP "<ip>" with AllowPrivateRanges "false"
    Then the SSRF classification should wrap ErrSSRFBlocked
    And the SSRF classification reason should be "multicast"

    Examples:
      | ip        |
      | 224.1.1.1 |
      | ff0e::1   |

  # --- Unspecified ---

  Scenario Outline: Unspecified address <ip> is blocked with reason unspecified
    When I check SSRF classification for IP "<ip>" with AllowPrivateRanges "false"
    Then the SSRF classification should wrap ErrSSRFBlocked
    And the SSRF classification reason should be "unspecified"

    Examples:
      | ip      |
      | 0.0.0.0 |
      | ::      |

  # --- Loopback (blocked by default, allowed with AllowPrivateRanges) ---

  Scenario Outline: Loopback address <ip> is blocked with reason loopback when AllowPrivateRanges is false
    When I check SSRF classification for IP "<ip>" with AllowPrivateRanges "false"
    Then the SSRF classification should wrap ErrSSRFBlocked
    And the SSRF classification reason should be "loopback"

    Examples:
      | ip        |
      | 127.0.0.1 |
      | ::1       |

  Scenario Outline: Loopback address <ip> is permitted when AllowPrivateRanges is true
    When I check SSRF classification for IP "<ip>" with AllowPrivateRanges "true"
    Then the SSRF classification should succeed

    Examples:
      | ip        |
      | 127.0.0.1 |
      | ::1       |

  # --- Private RFC 1918 / IPv6 ULA (blocked by default) ---

  Scenario Outline: Private address <ip> is blocked with reason private when AllowPrivateRanges is false
    When I check SSRF classification for IP "<ip>" with AllowPrivateRanges "false"
    Then the SSRF classification should wrap ErrSSRFBlocked
    And the SSRF classification reason should be "private"

    Examples:
      | ip              | description           |
      | 10.0.0.1        | RFC 1918 10/8         |
      | 172.16.0.1      | RFC 1918 172.16/12    |
      | 192.168.1.1     | RFC 1918 192.168/16   |
      | fd12:3456::1    | IPv6 ULA fc00::/7     |

  # --- IPv4-mapped IPv6 forms of private addresses ---

  Scenario Outline: IPv4-mapped IPv6 address <ip> is blocked with reason private
    When I check SSRF classification for IP "<ip>" with AllowPrivateRanges "false"
    Then the SSRF classification should wrap ErrSSRFBlocked
    And the SSRF classification reason should be "private"

    Examples:
      | ip                |
      | ::ffff:10.0.0.1   |
      | ::ffff:172.16.0.1 |
      | ::ffff:192.168.1.1 |

  # --- Public addresses pass through ---

  Scenario Outline: Public address <ip> is permitted with default config
    When I check SSRF classification for IP "<ip>" with AllowPrivateRanges "false"
    Then the SSRF classification should succeed

    Examples:
      | ip      |
      | 8.8.8.8 |
      | 1.1.1.1 |
      | 2001:4860:4860::8888 |
