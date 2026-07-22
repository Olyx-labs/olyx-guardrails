# frozen_string_literal: true

require_relative '../secret_scanner'

module Olyx
  module Guardrails
    module Checks
      # Decides whether secret findings are allowed by policy.
      module SecretCheck
        module_function

        def call(source, policy)
          scan = SecretScanner.scan(source, custom_patterns: policy.secret_patterns)
          result(scan, policy)
        end

        def result(scan, policy)
          leaked = scan[:leaked]
          {
            type: 'secret',
            allowed: !leaked || !policy.block_secrets?,
            leaked: leaked,
            count: scan[:findings].size
          }
        end
        private_class_method :result
      end
    end
  end
end
