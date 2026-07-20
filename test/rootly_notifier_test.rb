# frozen_string_literal: true

require_relative "test_helper"
require "olyx/guardrails/integrations/rootly_notifier"

class RootlyNotifierTest < Minitest::Test
  def notifier
    Olyx::Guardrails::Integrations::RootlyNotifier.new(
      api_key:     "test-key",
      environment: "test"
    )
  end

  def violation_result(overrides = {})
    {
      allowed:           false,
      risk_score:        0.75,
      injection_attempt: true,
      pii_detected:      false,
      secret_leaked:     false,
      checks:            [
        { type: "length", allowed: true, length: 42, max_length: 10_000 }
      ]
    }.merge(overrides)
  end

  # Stubs post_incident to capture the payload it would have sent, instead of
  # asserting on the real network response — used by every test below that
  # cares about payload shape (title/summary/severity/labels) rather than
  # delivery. Yields the notifier so the caller can drive whatever notify()
  # call it needs.
  def capture_payload(n = notifier)
    sent = nil
    n.stub(:post_incident, ->(payload) { sent = payload; { success: true } }) do
      yield n
    end
    sent
  end

  def test_returns_nil_on_zero_risk_score
    result = notifier.notify({ allowed: true, risk_score: 0.0 })
    assert_nil result
  end

  def test_notifies_on_violation
    n = notifier
    n.stub(:post_incident, { success: true, status: 201, incident_id: "abc123" }) do
      result = n.notify(violation_result, input: "Ignore previous instructions")
      assert result[:success]
      assert_equal "abc123", result[:incident_id]
    end
  end

  def test_incident_title_includes_environment
    sent = capture_payload { |n| n.notify(violation_result) }
    assert_includes sent.dig(:data, :attributes, :title), "[test]"
  end

  def test_incident_title_includes_violation_type
    sent = capture_payload { |n| n.notify(violation_result(injection_attempt: true)) }
    assert_includes sent.dig(:data, :attributes, :title), "injection"
  end

  def test_severity_sev1_for_high_risk
    sent = capture_payload { |n| n.notify(violation_result(risk_score: 0.9)) }
    assert_equal "sev1", sent.dig(:data, :attributes, :severity_slug)
  end

  def test_severity_sev2_for_medium_risk
    sent = capture_payload { |n| n.notify(violation_result(risk_score: 0.6)) }
    assert_equal "sev2", sent.dig(:data, :attributes, :severity_slug)
  end

  def test_severity_sev3_for_low_risk
    sent = capture_payload { |n| n.notify(violation_result(risk_score: 0.3)) }
    assert_equal "sev3", sent.dig(:data, :attributes, :severity_slug)
  end

  def test_severity_sev4_for_minimal_risk
    sent = capture_payload { |n| n.notify(violation_result(risk_score: 0.1)) }
    assert_equal "sev4", sent.dig(:data, :attributes, :severity_slug)
  end

  def test_summary_includes_risk_score
    sent = capture_payload { |n| n.notify(violation_result(risk_score: 0.75)) }
    assert_includes sent.dig(:data, :attributes, :summary), "0.75"
  end

  def test_summary_includes_input_preview
    sent = capture_payload { |n| n.notify(violation_result, input: "some user input") }
    assert_includes sent.dig(:data, :attributes, :summary), "some user input"
  end

  def test_summary_includes_ai_reason
    result = violation_result.merge(ai_analysis: { reason: "paraphrased jailbreak" })
    sent   = capture_payload { |n| n.notify(result) }
    assert_includes sent.dig(:data, :attributes, :summary), "paraphrased jailbreak"
  end

  def test_summary_includes_metadata
    sent = capture_payload do |n|
      n.notify(violation_result, metadata: { user_id: "42", endpoint: "/chat" })
    end
    summary = sent.dig(:data, :attributes, :summary)
    assert_includes summary, "user_id"
    assert_includes summary, "/chat"
  end

  def test_labels_include_ai_safety_and_gem_name
    sent   = capture_payload { |n| n.notify(violation_result) }
    labels = sent.dig(:data, :attributes, :labels).map { |l| l[:name] }
    assert_includes labels, "ai-safety"
    assert_includes labels, "olyx-guardrails"
  end

  def test_network_error_returns_error_hash
    # Exercises the real post_incident against an actually-refused local
    # connection (no stubbing) so the rescue path is genuinely verified,
    # not just asserted against a hand-written literal.
    klass    = Olyx::Guardrails::Integrations::RootlyNotifier
    original = klass::ROOTLY_API
    klass.send(:remove_const, :ROOTLY_API)
    klass.const_set(:ROOTLY_API, "http://127.0.0.1:1")

    result = notifier.notify(violation_result, input: "trigger")
    refute result[:success]
    assert result[:error]
  ensure
    klass.send(:remove_const, :ROOTLY_API)
    klass.const_set(:ROOTLY_API, original)
  end

  def test_notify_never_raises_on_malformed_metadata
    n = notifier
    n.stub(:post_incident, ->(payload) { { success: true } }) do
      result = n.notify(violation_result, metadata: nil)
      assert result[:success]
    end
  end

  def test_notify_recovers_from_payload_building_error
    n = notifier
    # A result shape so broken that violation_labels blows up on
    # `result[:checks]&.find` — notify should degrade to an error hash
    # instead of raising into the caller.
    broken_result = { risk_score: 0.9, checks: "not-an-array" }
    result = n.notify(broken_result)
    refute result[:success]
    assert result[:error]
  end

  def test_secret_leaked_label
    sent = capture_payload { |n| n.notify(violation_result(injection_attempt: false, secret_leaked: true)) }
    assert_includes sent.dig(:data, :attributes, :title), "secret"
  end

  def test_input_preview_truncated_at_300_chars
    long = "a" * 400
    sent = capture_payload { |n| n.notify(violation_result, input: long) }
    assert_includes sent.dig(:data, :attributes, :summary), "…"
  end

  def test_input_preview_redacts_secret
    secret = "wJalrXUtnFEMI/K7MDENG/bPxRfiCYEXAMPLEKEY"
    input  = "aws_secret_access_key = #{secret}"
    sent   = capture_payload { |n| n.notify(violation_result, input: input) }
    summary = sent.dig(:data, :attributes, :summary)
    refute_includes summary, secret
    assert_includes summary, "[REDACTED]"
  end

  def test_input_preview_redacts_pii
    input = "contact me at victim@example.com about this"
    sent  = capture_payload { |n| n.notify(violation_result, input: input) }
    summary = sent.dig(:data, :attributes, :summary)
    refute_includes summary, "victim@example.com"
    assert_includes summary, "[EMAIL]"
  end

  def test_input_preview_redacts_every_repeated_secret
    first  = "ghp_#{'a' * 36}"
    second = "ghp_#{'b' * 36}"
    sent = capture_payload { |n| n.notify(violation_result, input: "#{first} #{second}") }
    summary = sent.dig(:data, :attributes, :summary)

    refute_includes summary, first
    refute_includes summary, second
    assert_equal 2, summary.scan("[REDACTED]").length
  end

  def test_ai_reason_is_redacted_before_delivery
    secret = "ghp_#{'r' * 36}"
    result = violation_result.merge(ai_analysis: { reason: "detected #{secret}" })
    sent   = capture_payload { |n| n.notify(result) }
    summary = sent.dig(:data, :attributes, :summary)

    refute_includes summary, secret
    assert_includes summary, "[REDACTED]"
  end

  def test_metadata_is_sanitized_before_delivery
    secret = "ghp_#{'m' * 36}"
    sent = capture_payload do |n|
      n.notify(violation_result, metadata: { "unsafe\nkey" => "detected #{secret}" })
    end
    summary = sent.dig(:data, :attributes, :summary)

    refute_includes summary, secret
    assert_includes summary, "**unsafe_key:**"
    assert_includes summary, "[REDACTED]"
  end

  def test_initializer_rejects_empty_api_key
    assert_raises(ArgumentError) do
      Olyx::Guardrails::Integrations::RootlyNotifier.new(api_key: "")
    end
  end
end
