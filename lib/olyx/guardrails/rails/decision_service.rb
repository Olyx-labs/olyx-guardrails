# frozen_string_literal: true

require_relative 'evaluation_lifecycle'

module Olyx
  module Guardrails
    module Rails
      # Configures a reusable Rails lifecycle around one public decision operation.
      class DecisionService
        def initialize(operation, notification_input: nil)
          @operation = operation
          @notification_input = notification_input
        end

        def call(input, metadata:, configuration:)
          notification_input = @notification_input ? @notification_input.call(input) : input
          EvaluationLifecycle.call(notification_input, metadata: metadata, configuration: configuration) do
            Guardrails.public_send(
              @operation, input, policy: configuration.policy, llm_provider: configuration.llm_provider
            )
          end
        end
      end
    end
  end
end
