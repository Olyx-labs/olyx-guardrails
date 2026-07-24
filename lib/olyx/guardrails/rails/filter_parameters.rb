# frozen_string_literal: true

module Olyx
  module Guardrails
    module Rails
      # Normalizes Rails parameter-filter names.
      module FilterParameters
        module_function

        def call(value)
          unless valid?(value)
            raise ArgumentError,
                  'Rails filter_parameters must be an Array of String or Symbol values'
          end

          value.map(&:to_sym).uniq.freeze
        end

        def valid?(value)
          value.is_a?(Array) && value.all? { |item| item.is_a?(String) || item.is_a?(Symbol) }
        end
        private_class_method :valid?
      end
    end
  end
end
