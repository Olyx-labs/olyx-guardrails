# frozen_string_literal: true

require_relative 'evaluation_service'
require_relative 'redaction_service'

module Olyx
  module Guardrails
    module Rails
      # Executes configured checks and redaction for completed model output.
      class OutputRuntime
        def initialize(registry)
          @registry = registry
        end

        def check_output(output, metadata: {})
          context = { direction: 'output' }.merge(metadata)
          EvaluationService.call(output, metadata: context, configuration: @registry.ready)
        end

        def redact_output(output)
          RedactionService.call(output, configuration: @registry.ready)
        end
      end
    end
  end
end
