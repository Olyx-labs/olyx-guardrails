# frozen_string_literal: true

require_relative 'check_telemetry'
require_relative 'notification_dispatcher'
require_relative 'timer'

module Olyx
  module Guardrails
    module Rails
      # Applies the common telemetry and notification lifecycle to a decision.
      module EvaluationLifecycle
        module_function

        def call(notification_input, metadata:, configuration:, &)
          result, duration = Timer.call(&)
          CheckTelemetry.call(result, duration)
          NotificationDispatcher.call(configuration, result, notification_input, metadata)
          result
        end
      end
    end
  end
end
