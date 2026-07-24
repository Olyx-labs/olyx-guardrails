# frozen_string_literal: true

require_relative '../policy_scanner'

module Olyx
  module Guardrails
    module Checks
      # Presents named restricted-content matches as one policy check.
      module PolicyCheck
        module_function

        def call(source, policy)
          scan = PolicyScanner.scan(source, policy: policy)
          findings = scan[:findings]
          {
            type: 'policy',
            allowed: !scan[:blocked],
            violated: scan[:violated],
            count: findings.size,
            findings: findings
          }
        end
      end
    end
  end
end
