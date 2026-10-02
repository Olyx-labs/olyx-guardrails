# frozen_string_literal: true

require_relative 'check_analyzer'
require_relative 'check_result_builder'
require_relative 'check_set'
require_relative 'message_source'
require_relative 'policy'
require_relative 'validation'

module Olyx
  module Guardrails
    # Orchestrates checks for structured chat messages.
    class MessageCheckRunner
      def self.call(messages, policy: Policy.default, llm_provider: nil)
        Validation.array_of!(messages, Hash, name: 'messages')
        raise ArgumentError, 'policy must be an Olyx::Guardrails::Policy' unless policy.is_a?(Policy)

        Validation.callable_or_nil!(llm_provider, name: 'llm_provider')
        source = MessageSource.call(messages)
        checks = CheckSet.call(source, policy: policy, messages: messages)
        merged, analysis = CheckAnalyzer.call(checks, provider: llm_provider, source: source, policy: policy)
        CheckResultBuilder.call(merged, analysis, policy)
      end
    end
  end
end
