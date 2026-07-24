# frozen_string_literal: true

module Olyx
  module Guardrails
    module Checks
      # Enforces the bounded-input invariant before content scanners run.
      module LengthCheck
        module_function

        def call(source, policy)
          length = source.length
          maximum = policy.max_input_length
          { type: 'length', allowed: length <= maximum, length: length, max_length: maximum }
        end
      end
    end
  end
end
