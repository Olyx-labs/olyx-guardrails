# frozen_string_literal: true

module Olyx
  module Guardrails
    module Notification
      # Recursively freezes Hash and Array event structures.
      module DeepFreezer
        module_function

        def call(value)
          children(value).each { |child| call(child) }
          value.freeze
        end

        def children(value)
          return value.flat_map { |key, item| [key, item] } if value.is_a?(Hash)
          return value if value.is_a?(Array)

          []
        end
        private_class_method :children
      end
    end
  end
end
