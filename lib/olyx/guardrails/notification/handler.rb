# frozen_string_literal: true

module Olyx
  module Guardrails
    module Notification
      # Validates and normalizes one named notification handler.
      module Handler
        NAME = /\A[a-z][a-z0-9_.:-]*\z/i

        module_function

        def call(name, callable)
          normalized = name.to_s
          validate_name!(name, normalized)
          validate_callable!(normalized, callable)

          [normalized.freeze, callable].freeze
        end

        def validate_name!(name, normalized)
          type = name.is_a?(String) || name.is_a?(Symbol)
          valid = type && normalized.length <= 100 && normalized.match?(NAME)
          raise ArgumentError, 'handler names must be String or Symbol identifiers' unless valid
        end

        def validate_callable!(name, callable)
          raise ArgumentError, "handler #{name.inspect} must respond to call" unless callable.respond_to?(:call)
        end
        private_class_method :validate_name!, :validate_callable!
      end
    end
  end
end
