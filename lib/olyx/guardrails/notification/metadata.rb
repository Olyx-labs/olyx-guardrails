# frozen_string_literal: true

module Olyx
  module Guardrails
    module Notification
      # Bounds, sanitizes, and collision-proofs notification metadata.
      module Metadata
        MAX_ENTRIES = 20
        KEY_LENGTH = 50

        module_function

        def call(metadata, sanitizer)
          metadata.first(MAX_ENTRIES).each_with_object({}) do |(key, value), output|
            safe_key = unique_key(sanitizer.key(key), output)
            output[safe_key] = sanitizer.field(value)
          end
        end

        def unique_key(base, output)
          index = 1
          candidate = base
          while output.key?(candidate)
            index += 1
            suffix = "_#{index}"
            candidate = "#{base[0...(KEY_LENGTH - suffix.length)]}#{suffix}"
          end
          candidate
        end
        private_class_method :unique_key
      end
    end
  end
end
