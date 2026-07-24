# frozen_string_literal: true

require_relative 'multi_turn_injection_detector'
require_relative 'single_message_injection_detector'
require_relative 'validation'

module Olyx # :nodoc:
  module Guardrails
    # Detects known prompt-injection structures, phrases, and adjacent-turn
    # combinations.
    #
    # Detection checks bounded normalized and decoded variants. A false result
    # does not prove that arbitrary text is safe.
    class InjectionDetector
      # :call-seq:
      #   InjectionDetector.scan(messages) -> Hash
      #
      # Scans +messages+, which must be an Array of Hashes, and returns an
      # +:injection_attempt+ Boolean with the matched pattern fragments.
      # Individual messages and adjacent user-to-assistant turns are checked.
      # Invalid structure raises ArgumentError.
      def self.scan(messages)
        Validation.array_of!(messages, Hash, name: 'messages')
        findings = messages.flat_map { |message| SingleMessageInjectionDetector.call(message) }
        findings.concat(MultiTurnInjectionDetector.call(messages))
        { injection_attempt: findings.any?, patterns: findings.uniq { |finding| finding[:match] } }
      end

      # :call-seq:
      #   InjectionDetector.check(messages) -> Hash
      #
      # Delegates to scan. +messages+ follows the same contract.
      def self.check(messages)
        scan(messages)
      end

      # :call-seq:
      #   InjectionDetector.injection?(text) -> true or false
      #
      # Converts +text+ with +to_s+, scans it as one user message, and returns
      # whether a known injection pattern was detected.
      def self.injection?(text)
        scan([{ 'role' => 'user', 'content' => text.to_s }])[:injection_attempt]
      end
    end
  end
end
