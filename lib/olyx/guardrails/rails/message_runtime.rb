# frozen_string_literal: true

require_relative 'message_evaluation_service'

module Olyx
  module Guardrails
    module Rails
      # Executes configured checks for structured conversation messages.
      class MessageRuntime
        def initialize(registry)
          @registry = registry
        end

        def check_messages(messages, metadata: {})
          MessageEvaluationService.call(messages, metadata: metadata, configuration: @registry.ready)
        end
      end
    end
  end
end
