# frozen_string_literal: true

module Olyx
  module Guardrails
    module Rails
      # Owns runtime integration assignments during Rails boot.
      module IntegrationConfiguration
        def enabled=(value)
          mutable!
          @enabled = Validation.boolean!(value, name: 'Rails integration enabled')
        end

        def ai_analyzer=(value)
          mutable!
          @ai_analyzer = Validation.callable_or_nil!(value, name: 'Rails integration ai_analyzer')
        end

        def notifier_handlers=(value)
          mutable!
          raise ArgumentError, 'Rails notifier_handlers must be a Hash' unless value.is_a?(Hash)

          @notifier_handlers = value.dup.freeze
        end
      end
    end
  end
end
