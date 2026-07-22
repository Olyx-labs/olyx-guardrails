# frozen_string_literal: true

module Olyx
  module Guardrails
    module Redaction
      # Validates redaction policy type and configured length limit.
      module InputValidator
        module_function

        def call(source, policy)
          raise ArgumentError, 'policy must be an Olyx::Guardrails::Policy' unless policy.is_a?(Policy)
          raise ArgumentError, 'input exceeds max_input_length' if source.length > policy.max_input_length
        end
      end
    end
  end
end
