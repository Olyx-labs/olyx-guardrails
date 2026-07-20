# frozen_string_literal: true

require_relative "test_helper"

class SecretScannerTest < Minitest::Test
  def test_detects_confidentiality_marker
    result = Olyx::Guardrails::SecretScanner.scan("This document is confidential")
    assert result[:leaked]
    assert result[:findings].any? { |f| f[:category] == "confidentiality_marker" }
  end

  def test_detects_internal_endpoint
    result = Olyx::Guardrails::SecretScanner.scan("call http://api.internal/v1/data")
    assert result[:leaked]
    assert result[:findings].any? { |f| f[:category] == "internal_endpoint" }
  end

  def test_detects_private_ip_in_url
    result = Olyx::Guardrails::SecretScanner.scan("endpoint=http://10.0.0.1/api")
    assert result[:leaked]
    assert result[:findings].any? { |f| f[:category] == "private_network_address" }
  end

  def test_rejects_invalid_private_ip_octets
    result = Olyx::Guardrails::SecretScanner.scan("endpoint=http://10.999.999.999/api")
    refute result[:findings].any? { |f| f[:category] == "private_network_address" }
  end

  def test_detects_github_token
    result = Olyx::Guardrails::SecretScanner.scan("token=ghp_abc123defgh456ijklmn")
    assert result[:leaked]
    assert result[:findings].any? { |f| f[:category] == "secret_token" }
  end

  def test_clean_text_passes
    result = Olyx::Guardrails::SecretScanner.scan("The weather is nice today")
    refute result[:leaked]
    assert_empty result[:findings]
  end

  def test_scan_bang_returns_clean_result
    result = Olyx::Guardrails::SecretScanner.scan!("The weather is nice today")
    refute result[:leaked]
  end

  def test_scan_only_detects
    result = Olyx::Guardrails::SecretScanner.scan("call http://api.internal/v1")
    assert result[:leaked]
    refute result.key?(:text)
  end

  def test_scan_bang_raises
    assert_raises(Olyx::Guardrails::SecretScanner::Blocked) do
      Olyx::Guardrails::SecretScanner.scan!("call http://api.internal/v1")
    end
  end

  def test_redact_replaces_content
    result = Olyx::Guardrails::SecretScanner.redact("call http://api.internal/v1")
    assert result[:leaked]
    assert_includes result[:text], "[REDACTED]"
  end

  def test_scan_with_custom_patterns
    result = Olyx::Guardrails::SecretScanner.scan(
      "project codename: wolverine",
      custom_patterns: ["wolverine"]
    )
    assert result[:leaked]
    assert result[:findings].any? { |f| f[:category] == "custom_pattern" }
  end

  def test_blocked_exception_carries_findings
    error = assert_raises(Olyx::Guardrails::SecretScanner::Blocked) do
      Olyx::Guardrails::SecretScanner.scan!("call http://api.internal/v1")
    end
    assert error.findings.any?
  end

  def test_detects_aws_access_key_id
    result = Olyx::Guardrails::SecretScanner.scan("key=AKIAIOSFODNN7EXAMPLE here")
    assert result[:leaked]
    assert result[:findings].any? { |f| f[:category] == "aws_access_key" }
  end

  def test_detects_aws_asia_key_id
    result = Olyx::Guardrails::SecretScanner.scan("Using ASIAIOSFODNN7EXAMPLE for temp creds")
    assert result[:leaked]
    assert result[:findings].any? { |f| f[:category] == "aws_access_key" }
  end

  def test_detects_aws_secret_key
    result = Olyx::Guardrails::SecretScanner.scan(
      "aws_secret_access_key = wJalrXUtnFEMI/K7MDENG/bPxRfiCYEXAMPLEKEY"
    )
    assert result[:leaked]
    assert result[:findings].any? { |f| f[:category] == "aws_secret_key" }
  end

  def test_detects_anthropic_api_key
    result = Olyx::Guardrails::SecretScanner.scan(
      "Authorization: Bearer sk-ant-api03-abcdefghijklmnopqrstuvwxyz1234567890ABCD"
    )
    assert result[:leaked]
    assert result[:findings].any? { |f| f[:category] == "secret_token" }
  end

  def test_redact_fully_removes_long_aws_secret_key
    secret = "wJalrXUtnFEMI/K7MDENG/bPxRfiCYEXAMPLEKEY"
    result = Olyx::Guardrails::SecretScanner.redact("aws_secret_access_key = #{secret}")
    refute_includes result[:text], secret[25..]
    assert_includes result[:text], "[REDACTED]"
  end

  def test_redact_fully_removes_long_token
    token = "ghp_" + ("a" * 60)
    result = Olyx::Guardrails::SecretScanner.redact("token=#{token}")
    refute_includes result[:text], token[40..]
    assert_includes result[:text], "[REDACTED]"
  end

  def test_findings_mask_and_fingerprint_secret_values
    secret = "wJalrXUtnFEMI/K7MDENG/bPxRfiCYEXAMPLEKEY"
    result = Olyx::Guardrails::SecretScanner.scan("aws_secret_access_key = #{secret}")
    finding = result[:findings].find { |f| f[:category] == "aws_secret_key" }
    refute_includes finding[:matched], secret
    assert_match(/\Asha256:[a-f0-9]{12}\z/, finding[:fingerprint])
    assert_kind_of Integer, finding[:start]
    assert_kind_of Integer, finding[:end]
  end

  def test_redact_removes_every_secret_in_same_category
    first  = "ghp_#{'a' * 36}"
    second = "ghp_#{'b' * 36}"
    result = Olyx::Guardrails::SecretScanner.redact("#{first} #{second}")

    refute_includes result[:text], first
    refute_includes result[:text], second
    assert_equal 2, result[:findings].count { |finding| finding[:category] == "secret_token" }
  end

  def test_redact_removes_every_custom_pattern_match
    result = Olyx::Guardrails::SecretScanner.redact(
      "code-alpha then code-beta",
      custom_patterns: ["code-(?:alpha|beta)"]
    )

    assert_equal "[REDACTED] then [REDACTED]", result[:text]
    assert_equal 2, result[:findings].count { |finding| finding[:category] == "custom_pattern" }
  end

  def test_redact_merges_overlapping_builtin_and_custom_matches
    token = "ghp_#{'a' * 36}"
    result = Olyx::Guardrails::SecretScanner.redact(
      token,
      custom_patterns: [Regexp.escape(token)]
    )

    assert_equal "[REDACTED]", result[:text]
    assert_equal 2, result[:findings].length
  end

  def test_confidentiality_marker_redacts_whole_input
    result = Olyx::Guardrails::SecretScanner.redact("CONFIDENTIAL: database password is hunter2")
    assert_equal "[REDACTED]", result[:text]
  end

  def test_invalid_custom_pattern_raises
    assert_raises(ArgumentError) do
      Olyx::Guardrails::SecretScanner.scan("hello", custom_patterns: ["["])
    end
  end

  def test_custom_patterns_must_be_an_array_of_strings
    assert_raises(ArgumentError) do
      Olyx::Guardrails::SecretScanner.scan("hello", custom_patterns: nil)
    end
  end
end
