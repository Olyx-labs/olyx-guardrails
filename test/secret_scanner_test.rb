# frozen_string_literal: true

require_relative "test_helper"

class SecretScannerTest < Minitest::Test
  def test_detects_confidentiality_marker
    result = Olyx::Guardrails::SecretScanner.baseline_scan("This document is confidential")
    assert result[:leaked]
    assert result[:findings].any? { |f| f[:category] == "confidentiality_marker" }
  end

  def test_detects_internal_endpoint
    result = Olyx::Guardrails::SecretScanner.baseline_scan("call http://api.internal/v1/data")
    assert result[:leaked]
    assert result[:findings].any? { |f| f[:category] == "internal_endpoint" }
  end

  def test_detects_private_ip_in_url
    result = Olyx::Guardrails::SecretScanner.baseline_scan("endpoint=http://10.0.0.1/api")
    assert result[:leaked]
    assert result[:findings].any? { |f| f[:category] == "private_network_address" }
  end

  def test_detects_github_token
    result = Olyx::Guardrails::SecretScanner.baseline_scan("token=ghp_abc123defgh456ijklmn")
    assert result[:leaked]
    assert result[:findings].any? { |f| f[:category] == "secret_token" }
  end

  def test_clean_text_passes
    result = Olyx::Guardrails::SecretScanner.baseline_scan("The weather is nice today")
    refute result[:leaked]
    assert_empty result[:findings]
  end

  def test_scan_with_alert_action_allows_through
    result = Olyx::Guardrails::SecretScanner.scan("call http://api.internal/v1", secret_action: "alert")
    assert result[:leaked]
    assert result[:text].include?("api.internal")
  end

  def test_scan_with_block_action_raises
    assert_raises(Olyx::Guardrails::SecretScanner::Blocked) do
      Olyx::Guardrails::SecretScanner.scan("call http://api.internal/v1", secret_action: "block")
    end
  end

  def test_scan_with_redact_action_replaces_content
    result = Olyx::Guardrails::SecretScanner.scan("call http://api.internal/v1", secret_action: "redact")
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
      Olyx::Guardrails::SecretScanner.scan("call http://api.internal/v1", secret_action: "block")
    end
    assert error.findings.any?
  end

  def test_detects_aws_access_key_id
    result = Olyx::Guardrails::SecretScanner.baseline_scan("key=AKIAIOSFODNN7EXAMPLE here")
    assert result[:leaked]
    assert result[:findings].any? { |f| f[:category] == "aws_access_key" }
  end

  def test_detects_aws_asia_key_id
    result = Olyx::Guardrails::SecretScanner.baseline_scan("Using ASIAIOSFODNN7EXAMPLE for temp creds")
    assert result[:leaked]
    assert result[:findings].any? { |f| f[:category] == "aws_access_key" }
  end

  def test_detects_aws_secret_key
    result = Olyx::Guardrails::SecretScanner.baseline_scan(
      "aws_secret_access_key = wJalrXUtnFEMI/K7MDENG/bPxRfiCYEXAMPLEKEY"
    )
    assert result[:leaked]
    assert result[:findings].any? { |f| f[:category] == "aws_secret_key" }
  end

  def test_detects_anthropic_api_key
    result = Olyx::Guardrails::SecretScanner.baseline_scan(
      "Authorization: Bearer sk-ant-api03-abcdefghijklmnopqrstuvwxyz1234567890ABCD"
    )
    assert result[:leaked]
    assert result[:findings].any? { |f| f[:category] == "secret_token" }
  end

  def test_redact_fully_removes_long_aws_secret_key
    secret = "wJalrXUtnFEMI/K7MDENG/bPxRfiCYEXAMPLEKEY"
    result = Olyx::Guardrails::SecretScanner.scan(
      "aws_secret_access_key = #{secret}",
      secret_action: "redact"
    )
    refute_includes result[:text], secret[25..]
    assert_includes result[:text], "[REDACTED]"
  end

  def test_redact_fully_removes_long_token
    token = "ghp_" + ("a" * 60)
    result = Olyx::Guardrails::SecretScanner.scan("token=#{token}", secret_action: "redact")
    refute_includes result[:text], token[40..]
    assert_includes result[:text], "[REDACTED]"
  end

  def test_display_matched_value_still_truncated_for_long_secret
    secret = "wJalrXUtnFEMI/K7MDENG/bPxRfiCYEXAMPLEKEY"
    result = Olyx::Guardrails::SecretScanner.baseline_scan("aws_secret_access_key = #{secret}")
    finding = result[:findings].find { |f| f[:category] == "aws_secret_key" }
    refute_equal secret, finding[:matched]
    assert_includes finding[:matched], "…"
  end
end
