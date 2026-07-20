# frozen_string_literal: true

module Olyx
  module Guardrails
    # Shared internal validators for public collection arguments.
    module Validation
      def self.array_of!(value, item_class, name:)
        valid = value.is_a?(Array) && value.all? { |item| item.is_a?(item_class) }
        return value if valid

        raise ArgumentError, "#{name} must be an Array of #{item_class} values"
      end

      def self.boolean!(value, name:)
        return value if [true, false].include?(value)

        raise ArgumentError, "#{name} must be true or false"
      end

      def self.non_negative_integer!(value, name:)
        return value if value.is_a?(Integer) && value >= 0

        raise ArgumentError, "#{name} must be a non-negative Integer"
      end

      def self.callable_or_nil!(value, name:)
        return value if value.nil? || value.respond_to?(:call)

        raise ArgumentError, "#{name} must respond to call"
      end
    end
  end
end
