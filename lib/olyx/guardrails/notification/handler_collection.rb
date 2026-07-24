# frozen_string_literal: true

require_relative 'handler'
require_relative 'handler_collection_validator'

module Olyx
  module Guardrails
    module Notification
      # Validates and freezes named notification handlers.
      module HandlerCollection
        MAXIMUM = 20

        module_function

        def call(handlers)
          HandlerCollectionValidator.input!(handlers, maximum: MAXIMUM)

          normalized = handlers.map { |name, handler| Handler.call(name, handler) }
          HandlerCollectionValidator.unique!(normalized)
          normalized.freeze
        end
      end
    end
  end
end
