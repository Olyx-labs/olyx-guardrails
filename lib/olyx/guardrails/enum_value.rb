# frozen_string_literal: true

module Olyx
  module Guardrails
    # Callable validator for a closed public option set.
    class EnumValue
      def initialize(allowed:, error:)
        @allowed = allowed.freeze
        @error = error
      end

      def call(value)
        normalized = value.to_sym if value.respond_to?(:to_sym)
        return normalized if @allowed.include?(normalized)

        raise ArgumentError, @error
      end
    end
  end
end
