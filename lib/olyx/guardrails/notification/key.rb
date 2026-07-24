# frozen_string_literal: true

module Olyx
  module Guardrails
    module Notification
      # Normalizes a redacted metadata key.
      module Key
        LENGTH = 50

        module_function

        def call(value, scrubber)
          normalized = scrubber.call(value).gsub(/[^A-Za-z0-9_.-]/, '_')[0...LENGTH]
          normalized.empty? ? 'metadata' : normalized
        end
      end
    end
  end
end
