# frozen_string_literal: true

require_relative '../injection_detector'
require_relative 'injection_result'

module Olyx
  module Guardrails
    module Checks
      # Decides whether structured-message injection findings are allowed.
      module MessageInjectionCheck
        module_function

        def call(messages, policy)
          InjectionResult.call(InjectionDetector.scan(messages), policy)
        end
      end
    end
  end
end
