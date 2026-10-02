# frozen_string_literal: true

require_relative 'injection_detector'
require_relative 'pii/text_scrubber'
require_relative 'policy_scanner'
require_relative 'secret_scanner'

module Olyx
  module Guardrails
    # Coordinates independent deterministic checks for one normalized input.
    class CheckSet
      def self.call(source, policy:, messages: nil)
        length = length_check(source, policy)
        content = length[:allowed] ? scan(source, policy, messages) : skipped_checks
        content.merge(length: length)
      end

      def self.scan(source, policy, messages)
        {
          pii: pii_check(source, policy),
          injection: injection_check(source, policy, messages),
          secret: secret_check(source, policy),
          policy: policy_check(source, policy)
        }
      end

      def self.length_check(source, policy)
        length = source.length
        maximum = policy.max_input_length
        { type: 'length', allowed: length <= maximum, length: length, max_length: maximum }
      end

      def self.pii_check(source, policy)
        detected = Pii::TextScrubber.detect?(source)
        { type: 'pii', allowed: !detected || !policy.block_pii?, detected: detected }
      end

      def self.injection_check(source, policy, messages)
        scan = InjectionDetector.scan(messages || [{ 'role' => 'user', 'content' => source }])
        attempt = scan[:injection_attempt]
        {
          type: 'injection',
          allowed: !attempt || !policy.block_injections?,
          injection_attempt: attempt,
          patterns: scan[:patterns]
        }
      end

      def self.secret_check(source, policy)
        scan = SecretScanner.scan(source, custom_patterns: policy.secret_patterns)
        leaked = scan[:leaked]
        { type: 'secret', allowed: !leaked || !policy.block_secrets?, leaked: leaked, count: scan[:findings].size }
      end

      def self.policy_check(source, policy)
        scan = PolicyScanner.scan(source, policy: policy)
        findings = scan[:findings]
        {
          type: 'policy', allowed: !scan[:blocked], violated: scan[:violated],
          count: findings.size, findings: findings
        }
      end

      def self.skipped_checks
        {
          pii: skipped('pii', detected: false),
          injection: skipped('injection', injection_attempt: false, patterns: []),
          secret: skipped('secret', leaked: false, count: 0),
          policy: skipped('policy', violated: false, count: 0, findings: [])
        }
      end

      def self.skipped(type, **fields)
        { type: type, allowed: true, skipped: true, **fields }
      end
      private_class_method :injection_check, :length_check, :pii_check, :policy_check, :scan,
                           :secret_check, :skipped, :skipped_checks
    end
  end
end
