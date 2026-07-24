# frozen_string_literal: true

module Olyx
  module Guardrails
    module Checks
      # Builds the shared injection check decision from detector output.
      module InjectionResult
        module_function

        def call(scan, policy)
          attempt = scan[:injection_attempt]
          {
            type: 'injection',
            allowed: !attempt || !policy.block_injections?,
            injection_attempt: attempt,
            patterns: scan[:patterns]
          }
        end
      end
    end
  end
end
