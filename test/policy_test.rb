# frozen_string_literal: true

require_relative 'test_helper'

class PolicyTest < Minitest::Test
  def rule(**)
    Olyx::Guardrails::PolicyRule.new(**)
  end

  def policy(**)
    Olyx::Guardrails::Policy.new(**)
  end

  def test_named_blocking_rule_produces_a_distinct_policy_finding
    configured = policy(
      name: 'customer-data-boundary',
      rules: [
        rule(
          name: :confidential_project,
          description: 'Confidential project names',
          patterns: ['project[ -]falcon'],
          block: true
        )
      ]
    )

    result = Olyx::Guardrails.check('Discuss Project Falcon', policy: configured)
    finding = result[:policy_findings].first

    refute result[:allowed]
    assert result[:policy_violated]
    refute result[:secret_leaked]
    assert_equal 'customer-data-boundary', result[:policy_name]
    assert_equal 'confidential_project', finding[:rule]
    assert_equal 'Confidential project names', finding[:description]
    assert finding[:blocked]
    refute_includes finding[:matched].downcase, 'falcon'
    assert_match(/\Asha256:[a-f0-9]{12}\z/, finding[:fingerprint])
  end

  def test_non_blocking_rule_flags_without_rejecting
    configured = policy(
      rules: [{ name: :competitor_reference, patterns: ['competitor corp'], block: false }]
    )

    result = Olyx::Guardrails.check('Compare us with Competitor Corp', policy: configured)

    assert result[:allowed]
    assert result[:policy_violated]
    refute result[:policy_findings].first[:blocked]
    assert_in_delta 0.25, result[:risk_score], 0.001
  end

  def test_literal_terms_do_not_require_regex_escaping
    configured = policy(rules: [{ name: :project, terms: ['Project (Falcon)'] }])

    assert Olyx::Guardrails.check('Discuss project (falcon)', policy: configured)[:policy_violated]
    refute Olyx::Guardrails.check('Discuss project Falcon', policy: configured)[:policy_violated]
  end

  def test_policy_can_block_pii
    configured = policy(block_pii: true)
    result = Olyx::Guardrails.check('email user@example.com', policy: configured)

    refute result[:allowed]
    assert result[:pii_detected]
  end

  def test_policy_can_block_pii_reported_by_ai
    analyzer = ->(_text, _context) { { pii_detected: true } }
    configured = policy(block_pii: true)
    result = Olyx::Guardrails.check(
      'customer record',
      policy: configured,
      ai_analyzer: analyzer
    )

    refute result[:allowed]
    assert result[:pii_detected]
  end

  def test_custom_credential_patterns_remain_distinct_from_policy_rules
    configured = policy(
      block_secrets: true,
      secret_patterns: ['credential-[a-z0-9]+']
    )
    result = Olyx::Guardrails.check('credential-alpha123', policy: configured)

    refute result[:allowed]
    assert result[:secret_leaked]
    refute result[:policy_violated]
  end

  def test_custom_credential_patterns_are_redacted
    configured = policy(secret_patterns: ['credential-[a-z0-9]+'])
    result = Olyx::Guardrails.redact('credential-alpha123', policy: configured)

    assert_equal '[REDACTED]', result[:text]
    assert result[:secret_leaked]
    refute result[:policy_violated]
  end

  def test_redact_replaces_every_restricted_match
    configured = policy(
      rules: [
        {
          name: :confidential_project,
          patterns: ['project[ -]falcon'],
          replacement: '[CONFIDENTIAL_PROJECT]'
        }
      ]
    )

    result = Olyx::Guardrails.redact(
      'Project Falcon then project-falcon',
      policy: configured
    )

    assert_equal '[CONFIDENTIAL_PROJECT] then [CONFIDENTIAL_PROJECT]', result[:text]
    assert result[:redacted]
    assert result[:policy_violated]
    assert_equal 2, result[:policy_findings].length
  end

  def test_redact_replaces_a_policy_match_that_spans_pii
    configured = policy(
      rules: [{
        name: :restricted_contact,
        patterns: ['project owner@example\\.com'],
        replacement: '[RESTRICTED_CONTACT]'
      }]
    )

    result = Olyx::Guardrails.redact(
      'Project owner@example.com',
      policy: configured
    )

    assert_equal '[RESTRICTED_CONTACT]', result[:text]
    assert result[:pii_detected]
    assert result[:policy_violated]
  end

  def test_rule_name_provides_the_default_replacement
    configured = policy(rules: [{ name: :restricted_term, patterns: ['forbiddenword'] }])

    result = Olyx::Guardrails.redact('forbiddenword', policy: configured)

    assert_equal '[RESTRICTED:RESTRICTED_TERM]', result[:text]
  end

  def test_overlapping_rules_use_the_first_configured_replacement
    configured = policy(
      rules: [
        { name: :project, patterns: ['project falcon'], replacement: '[PROJECT]' },
        { name: :codename, patterns: ['falcon'], replacement: '[CODENAME]' }
      ]
    )

    result = Olyx::Guardrails.redact('project falcon', policy: configured)

    assert_equal '[PROJECT]', result[:text]
    assert_equal 2, result[:policy_findings].length
  end

  def test_regexp_patterns_keep_their_case_sensitivity
    configured = policy(rules: [{ name: :exact_term, patterns: [/ExactTerm/] }])

    refute Olyx::Guardrails.check('exactterm', policy: configured)[:policy_violated]
    assert Olyx::Guardrails.check('ExactTerm', policy: configured)[:policy_violated]
  end

  def test_policy_can_be_loaded_from_string_keyed_configuration
    configured = Olyx::Guardrails::Policy.from_h(
      'name' => 'yaml-policy',
      'block_secrets' => true,
      'rules' => [
        { 'name' => 'internal_term', 'patterns' => ['internal only'], 'block' => true }
      ]
    )

    assert_equal 'yaml-policy', configured.name
    assert_predicate configured, :block_secrets?
    assert_equal 'internal_term', configured.rules.first.name
  end

  def test_matched_policy_rules_are_exposed_to_the_ai_context
    context = nil
    analyzer = lambda { |_text, received|
      context = received
      {}
    }
    configured = policy(rules: [{ name: :restricted_term, patterns: ['restricted'] }])

    Olyx::Guardrails.check('restricted', policy: configured, ai_analyzer: analyzer)

    assert context[:policy_violated]
    assert_equal ['restricted_term'], context[:policy_rules]
  end

  def test_policy_and_rules_are_immutable
    configured = policy(rules: [{ name: :restricted, patterns: ['restricted'] }])

    assert_predicate configured, :frozen?
    assert_predicate configured.rules, :frozen?
    assert_predicate configured.rules.first, :frozen?
    assert_predicate configured.rules.first.patterns, :frozen?
  end

  def test_default_policy_is_reused
    assert_same Olyx::Guardrails::Policy.default, Olyx::Guardrails::Policy.default
  end

  def test_rejects_duplicate_rule_names
    assert_raises(ArgumentError) do
      policy(rules: [
               { name: :duplicate, patterns: ['first'] },
               { name: :duplicate, patterns: ['second'] }
             ])
    end
  end

  def test_rejects_invalid_rule_configuration
    invalid_rules = [
      { name: 'spaces are invalid', patterns: ['term'] },
      { name: :empty, patterns: [] },
      { name: :bad_term, terms: [123] },
      { name: :wrong_type, patterns: [123] },
      { name: :empty_match, patterns: ['.*'] },
      { name: :bad_block, patterns: ['term'], block: :yes },
      { name: :bad_description, patterns: ['term'], description: '' },
      { name: :bad_replacement, patterns: ['term'], replacement: "bad\nvalue" }
    ]

    invalid_rules.each do |invalid|
      assert_raises(ArgumentError) { policy(rules: [invalid]) }
    end
  end

  def test_rejects_invalid_policy_configuration
    assert_raises(ArgumentError) { Olyx::Guardrails::Policy.from_h(nil) }
    assert_raises(ArgumentError) { Olyx::Guardrails::Policy.from_h(1 => 'invalid key') }
    assert_raises(ArgumentError) { policy(name: '') }
    assert_raises(ArgumentError) { policy(rules: nil) }
    assert_raises(ArgumentError) { policy(rules: [Object.new]) }
    assert_raises(ArgumentError) { policy(secret_patterns: ['[']) }
    assert_raises(ArgumentError) { Olyx::Guardrails.check('hello', policy: Object.new) }
    assert_raises(ArgumentError) { Olyx::Guardrails.redact('hello', policy: Object.new) }
  end
end
