# frozen_string_literal: true

require_relative 'instrumentation'
require_relative 'timer'

module Olyx
  module Guardrails
    module Rails
      # Runs one configured transformation and publishes safe telemetry.
      module RedactionService
        module_function

        def call(input, configuration:)
          result, duration = Timer.call { Guardrails.redact(input, policy: configuration.policy) }
          Instrumentation.publish_redaction(result, duration)
          result
        end
      end
    end
  end
end
