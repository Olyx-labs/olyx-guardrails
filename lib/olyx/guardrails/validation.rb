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
    end
  end
end
