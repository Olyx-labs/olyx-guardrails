# frozen_string_literal: true

require_relative 'multi_turn_injection_detector'
require_relative 'single_message_injection_detector'
require_relative 'validation'

module Olyx
  module Guardrails
    # Coordinates phrase, structure, and adjacent-turn injection detectors.
    class InjectionDetector
      def self.scan(messages)
        Validation.array_of!(messages, Hash, name: 'messages')
        findings = messages.flat_map { |message| SingleMessageInjectionDetector.call(message) }
        findings.concat(MultiTurnInjectionDetector.call(messages))
        { injection_attempt: findings.any?, patterns: findings.uniq { |finding| finding[:match] } }
      end

      def self.check(messages)
        scan(messages)
      end

      def self.injection?(text)
        scan([{ 'role' => 'user', 'content' => text.to_s }])[:injection_attempt]
      end
    end
  end
end
