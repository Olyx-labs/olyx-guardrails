# frozen_string_literal: true

require_relative 'test_helper'

class NotifierTest < Minitest::Test
  def policy(**)
    Olyx::Guardrails::Policy.new(**)
  end

  def violation_result(overrides = {})
    {
      allowed: false,
      risk_score: 0.75,
      injection_attempt: true,
      pii_detected: false,
      secret_leaked: false,
      policy_violated: false,
      policy_findings: [],
      checks: [{ type: 'length', allowed: true, length: 42, max_length: 10_000 }]
    }.merge(overrides)
  end

  def notifier(policy: Olyx::Guardrails::Policy.default, handlers: nil)
    handlers ||= { capture: ->(_event) {} }
    Olyx::Guardrails::Notifier.new(policy: policy, handlers: handlers)
  end

  def test_zero_risk_does_not_invoke_handlers
    called = false
    configured = notifier(handlers: { capture: ->(_event) { called = true } })

    result = configured.notify({ allowed: true, risk_score: 0.0 })

    assert_nil result
    refute called
  end

  def test_dispatches_one_vendor_neutral_event_to_every_handler
    received = []
    configured = notifier(
      handlers: {
        audit_log: ->(event) { received << event },
        incident_queue: ->(event) { received << event }
      }
    )

    result = configured.notify(violation_result, input: 'unsafe request')

    assert result[:success]
    assert_equal 2, result[:deliveries].length
    assert(result[:deliveries].all? { |delivery| delivery[:success] })
    assert_equal [result[:event], result[:event]], received
  end

  def test_event_has_a_stable_machine_readable_contract
    result = violation_result(
      injection_attempt: true,
      secret_leaked: true,
      pii_detected: true,
      policy_violated: true,
      policy_findings: [{ rule: 'confidential_project', blocked: true }],
      checks: [{ type: 'length', allowed: false }]
    )

    event = notifier.notify(result, metadata: { request_id: 42 })[:event]

    assert_equal 1, event[:schema_version]
    assert_equal 'guardrail.violation', event[:event]
    assert_equal 'default', event[:policy_name]
    refute event[:allowed]
    assert_in_delta(0.75, event[:risk_score])
    assert_equal 1, event[:policy_rule_count]
    assert_equal %w[
      injection_attempt secret_leaked pii_detected restricted_content
      input_length_exceeded
    ], event[:violations]
    assert_equal({ 'request_id' => '42' }, event[:metadata])
  end

  def test_policy_redacts_every_untrusted_event_field
    restricted = 'Project Falcon'
    credential = "company-token-#{'c' * 24}"
    email = 'owner@example.com'
    configured_policy = policy(
      name: 'production',
      secret_patterns: ['company-token-[a-z0-9]{24}'],
      rules: [{
        name: :confidential_project,
        patterns: ['project[ -]falcon'],
        replacement: '[CONFIDENTIAL_PROJECT]'
      }]
    )
    result = violation_result(
      secret_leaked: true,
      pii_detected: true,
      policy_violated: true,
      policy_findings: [{ rule: 'confidential_project', blocked: true }],
      ai_analysis: { reason: "#{restricted} #{credential} #{email}" }
    )
    input = "#{restricted} #{credential} #{email}"

    event = notifier(policy: configured_policy).notify(
      result,
      input: input,
      metadata: { restricted => input, credential => email }
    )[:event]
    serialized = event.to_s

    refute_includes serialized.downcase, restricted.downcase
    refute_includes serialized, credential
    refute_includes serialized, email
    assert_includes serialized, 'CONFIDENTIAL_PROJECT'
    assert_includes serialized, 'REDACTED'
    assert_includes serialized, 'EMAIL'
  end

  def test_sanitized_metadata_key_collisions_are_preserved_with_suffixes
    configured_policy = policy(
      rules: [{ name: :restricted, patterns: ['project[ -]falcon'], replacement: '[PROJECT]' }]
    )

    event = notifier(policy: configured_policy).notify(
      violation_result,
      metadata: { 'Project Falcon' => 1, 'project-falcon' => 2 }
    )[:event]

    assert_equal %w[_PROJECT_ _PROJECT__2], event[:metadata].keys
    assert_equal %w[1 2], event[:metadata].values
  end

  def test_metadata_and_preview_are_bounded
    metadata = (1..25).to_h { |index| ["key_#{index}", 'value'] }
    input = 'a' * 400

    event = notifier.notify(violation_result, input: input, metadata: metadata)[:event]

    assert_equal 20, event[:metadata].length
    assert_equal 301, event[:input_preview].length
    assert event[:input_preview].end_with?('…')
  end

  def test_event_is_deeply_frozen_before_delivery
    event = notifier.notify(violation_result, metadata: { request_id: 42 })[:event]

    assert_predicate event, :frozen?
    assert_predicate event[:violations], :frozen?
    assert_predicate event[:metadata], :frozen?
    assert_raises(FrozenError) { event[:metadata]['request_id'] = 'changed' }
  end

  def test_one_handler_failure_does_not_stop_other_handlers
    delivered = false
    configured = notifier(
      handlers: {
        broken: ->(_event) { raise 'offline' },
        working: ->(_event) { delivered = true }
      }
    )

    result = configured.notify(violation_result)

    refute result[:success]
    assert delivered
    assert_equal([false, true], result[:deliveries].map { |delivery| delivery[:success] })
    assert_equal 'offline', result[:deliveries].first[:error]
  end

  def test_handler_error_messages_are_policy_redacted
    credential = "company-token-#{'e' * 24}"
    configured_policy = policy(secret_patterns: ['company-token-[a-z0-9]{24}'])
    configured = notifier(
      policy: configured_policy,
      handlers: { broken: ->(_event) { raise "failed with #{credential}" } }
    )

    result = configured.notify(violation_result)
    error = result[:deliveries].first[:error]

    refute_includes error, credential
    assert_includes error, '[REDACTED]'
  end

  def test_payload_building_errors_return_a_failure_without_dispatch
    called = false
    configured = notifier(handlers: { capture: ->(_event) { called = true } })

    result = configured.notify(violation_result(checks: 'invalid'))

    refute result[:success]
    assert_empty result[:deliveries]
    refute called
  end

  def test_non_hash_metadata_is_treated_as_empty
    event = notifier.notify(violation_result, metadata: nil)[:event]

    assert_empty event[:metadata]
  end

  def test_requires_a_policy
    error = assert_raises(ArgumentError) do
      Olyx::Guardrails::Notifier.new(policy: Object.new, handlers: { capture: ->(_event) {} })
    end

    assert_equal 'policy must be an Olyx::Guardrails::Policy', error.message
  end

  def test_requires_a_bounded_non_empty_handler_hash
    [nil, {}, { capture: Object.new }, (1..21).to_h { |index| ["h#{index}", ->(_event) {}] }].each do |handlers|
      assert_raises(ArgumentError) do
        Olyx::Guardrails::Notifier.new(policy: policy, handlers: handlers)
      end
    end
  end

  def test_rejects_invalid_or_duplicate_handler_names
    invalid_names = ['', 'has spaces', 123]

    invalid_names.each do |name|
      assert_raises(ArgumentError) do
        notifier(handlers: { name => ->(_event) {} })
      end
    end

    assert_raises(ArgumentError) do
      notifier(handlers: { capture: ->(_event) {}, 'capture' => ->(_event) {} })
    end
  end
end
