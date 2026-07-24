# frozen_string_literal: true

module Olyx
  module Guardrails
    module Rails
      # Normalizes an optional path-like configuration value.
      module PathValue
        module_function

        def call(value)
          return nil if value.nil?

          normalized = normalize(value)
          return normalized.dup.freeze if valid?(normalized)

          raise ArgumentError, 'Rails policy_path must be a path-like value'
        end

        def normalize(value)
          value.respond_to?(:to_path) ? value.to_path : value
        end

        def valid?(value)
          value.is_a?(String) && !value.empty?
        end
        private_class_method :normalize, :valid?
      end
    end
  end
end
