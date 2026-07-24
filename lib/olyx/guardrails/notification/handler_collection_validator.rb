# frozen_string_literal: true

module Olyx
  module Guardrails
    module Notification
      # Validates handler collection shape and normalized-name uniqueness.
      module HandlerCollectionValidator
        module_function

        def input!(handlers, maximum:)
          return if handlers.is_a?(Hash) && !handlers.empty? && handlers.length <= maximum

          raise ArgumentError, "handlers must be a non-empty Hash with at most #{maximum} entries"
        end

        def unique!(handlers)
          names = handlers.map(&:first)
          raise ArgumentError, 'handler names must be unique' unless names.uniq.length == names.length
        end
      end
    end
  end
end
