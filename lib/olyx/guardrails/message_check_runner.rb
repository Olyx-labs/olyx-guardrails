# frozen_string_literal: true

require_relative 'check_pipeline'
require_relative 'message_check_set'
require_relative 'message_source'
require_relative 'policy'
require_relative 'validation'

module Olyx
  module Guardrails
    # Orchestrates checks for structured chat messages.
    class MessageCheckRunner
      def self.call(messages, policy: Policy.default, ai_analyzer: nil)
        Validation.array_of!(messages, Hash, name: 'messages')
        raise ArgumentError, 'policy must be an Olyx::Guardrails::Policy' unless policy.is_a?(Policy)

        Validation.callable_or_nil!(ai_analyzer, name: 'ai_analyzer')
        source = MessageSource.call(messages)
        checks = MessageCheckSet.call(source, messages, policy: policy)
        CheckPipeline.call(source, checks, policy: policy, ai_analyzer: ai_analyzer)
      end
    end
  end
end
