# frozen_string_literal: true

require_relative 'check_set'
require_relative 'checks/message_injection_check'

module Olyx
  module Guardrails
    # Runs deterministic checks while retaining structured-message injection context.
    module MessageCheckSet
      module_function

      def call(source, messages, policy:)
        checks = CheckSet.call(source, policy: policy)
        return checks unless checks[:length][:allowed]

        checks.merge(injection: Checks::MessageInjectionCheck.call(messages, policy))
      end
    end
  end
end
