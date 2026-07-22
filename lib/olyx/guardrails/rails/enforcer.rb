# frozen_string_literal: true

require_relative 'result_summary'

module Olyx
  module Guardrails
    module Rails
      # Provides reusable exception-driven enforcement for Rails entry points.
      module Enforcer
        module_function

        def check!(input, metadata: {})
          enforce(Guardrails::Rails.check(input, metadata: metadata))
        end

        def check_messages!(messages, metadata: {})
          enforce(Guardrails::Rails.check_messages(messages, metadata: metadata))
        end

        def check_output!(output, metadata: {})
          enforce(Guardrails::Rails.check_output(output, metadata: metadata))
        end

        def enforce(result)
          return result if result[:allowed]

          raise Blocked, ResultSummary.call(result)
        end
        private_class_method :enforce
      end
    end
  end
end
