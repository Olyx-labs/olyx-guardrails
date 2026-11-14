# frozen_string_literal: true

require_relative 'test_helper'

class EvaluationContractTest < Minitest::Test
  def test_text_and_single_user_message_share_provider_context_and_decision
    observed = []
    provider = lambda do |text, context|
      observed << [text, context]
      { pii_detected: true, reason: 'contextual identifier' }
    end
    text = 'customer reference'
    decision = Olyx::Guardrails.check(text, llm_provider: provider)
    messages = Olyx::Guardrails.check_messages([{ role: 'user', content: text }], llm_provider: provider)

    assert_equal decision, messages
    assert_equal observed.first, observed.last
    assert_equal(%w[pii injection secret policy length], decision[:checks].map { |check| check[:type] })
  end

  def test_invalid_message_options_are_rejected_before_content_is_read
    message = {}.tap { |value| value.define_singleton_method(:[]) { |_| raise 'content read too early' } }

    assert_raises(ArgumentError) { Olyx::Guardrails.check_messages([message], policy: nil) }
    assert_raises(ArgumentError) { Olyx::Guardrails.check_messages([message], llm_provider: Object.new) }
    assert_raises(ArgumentError) { Olyx::Guardrails.check_messages(nil, policy: nil) }
  end

  def test_oversized_messages_skip_scanners_and_provider
    policy = Olyx::Guardrails::Policy.new(max_input_length: 3)
    result = Olyx::Guardrails.check_messages(
      [{ role: 'user', content: 'test@example.com' }], policy: policy,
                                                       llm_provider: lambda { |*|
                                                         flunk 'provider must not run for oversized messages'
                                                       }
    )

    refute result[:allowed]
    assert(result[:checks].reject { |check| check[:type] == 'length' }.all? { |check| check[:skipped] })
    refute result.key?(:llm_analysis)
  end

  def test_provider_symbol_flags_take_precedence_and_unknown_fields_are_omitted
    output = { pii_detected: false, 'pii_detected' => true, reason: 'x' * 600, private_data: 'not public' }
    original = output.dup
    result = Olyx::Guardrails.check('safe', llm_provider: ->(*) { output })

    refute result[:pii_detected]
    refute result[:llm_analysis].key?(:private_data)
    assert_equal 500, result[:llm_analysis][:reason].length
    assert_equal original, output
  end

  def test_schema_conversion_exceptions_are_sanitized
    schema = Object.new
    schema.define_singleton_method(:deep_to_h) { raise 'private provider payload' }
    result = Olyx::Guardrails.check('safe', llm_provider: ->(*) { schema })

    assert_equal({ error: 'llm_provider failed' }, result[:llm_analysis])
    refute_includes result.to_s, 'private provider payload'
  end

  def test_mixed_message_keys_preserve_extraction_and_redaction_semantics
    [nil, false].each do |empty|
      message = { 'content' => empty, content: 'test@example.com', 'role' => empty, role: 'user' }

      assert Olyx::Guardrails.check_messages([message])[:pii_detected]
      assert_equal [message], Olyx::Guardrails::PiiScrubber.scrub_messages([message])

      block = { 'text' => empty, text: 'test@example.com' }
      messages = [{ content: [block] }]

      assert Olyx::Guardrails.check_messages(messages)[:pii_detected]
      assert_equal messages, Olyx::Guardrails::PiiScrubber.scrub_messages(messages)
    end
  end

  def test_numeric_birth_dates_preserve_calendar_and_two_digit_year_rules
    ['2000-02-29', '29/02/2000', '02/29/2000', '29/02/00'].each do |date|
      refute_equal "DOB: #{date}", Olyx::Guardrails::PiiScrubber.scrub("DOB: #{date}")
    end
    ['1900-02-29', '31/04/2000', '00/10/2000'].each do |date|
      assert_equal "DOB: #{date}", Olyx::Guardrails::PiiScrubber.scrub("DOB: #{date}")
    end
  end
end
