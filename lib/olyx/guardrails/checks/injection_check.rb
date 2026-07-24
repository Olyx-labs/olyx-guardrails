# frozen_string_literal: true

require_relative '../injection_detector'
require_relative 'injection_result'

module Olyx
  module Guardrails
    module Checks
      # Decides whether deterministic injection findings are allowed.
      module InjectionCheck
        module_function

        def call(source, policy)
          scan = InjectionDetector.scan([{ 'role' => 'user', 'content' => source }])
          InjectionResult.call(scan, policy)
        end
      end
    end
  end
end
