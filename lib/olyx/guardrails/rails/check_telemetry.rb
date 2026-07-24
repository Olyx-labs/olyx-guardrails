# frozen_string_literal: true

require_relative 'instrumentation'

module Olyx
  module Guardrails
    module Rails
      # Publishes check and violation telemetry from one decision summary.
      module CheckTelemetry
        module_function

        def call(result, duration)
          Instrumentation.publish_check(result, duration)
          Instrumentation.publish_violation(result, duration) if result[:risk_score].to_f.positive?
        end
      end
    end
  end
end
