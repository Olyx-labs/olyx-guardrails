# frozen_string_literal: true

require_relative 'evaluation_service'
require_relative 'redaction_service'

module Olyx
  module Guardrails
    module Rails
      # Executes configured checks and redaction for inbound text.
      class InputRuntime
        def initialize(registry)
          @registry = registry
        end

        def check(input, metadata: {})
          EvaluationService.call(input, metadata: metadata, configuration: @registry.ready)
        end

        def redact(input)
          RedactionService.call(input, configuration: @registry.ready)
        end
      end
    end
  end
end
