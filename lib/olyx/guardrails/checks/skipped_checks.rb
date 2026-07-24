# frozen_string_literal: true

module Olyx
  module Guardrails
    module Checks
      # Produces stable check contracts when the length guard short-circuits.
      module SkippedChecks
        module_function

        def call
          {
            pii: skipped('pii', detected: false),
            injection: skipped('injection', injection_attempt: false, patterns: []),
            secret: skipped('secret', leaked: false, count: 0),
            policy: skipped('policy', violated: false, count: 0, findings: [])
          }
        end

        def skipped(type, **fields)
          { type: type, allowed: true, skipped: true, **fields }
        end
        private_class_method :skipped
      end
    end
  end
end
