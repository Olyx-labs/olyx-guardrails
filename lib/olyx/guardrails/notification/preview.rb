# frozen_string_literal: true

module Olyx
  module Guardrails
    module Notification
      # Produces a bounded redacted preview with a truncation marker.
      module Preview
        LENGTH = 300

        module_function

        def call(value, scrubber)
          source = value.to_s
          scrubbed = scrubber.call(source)
          preview = scrubbed[0...LENGTH]
          preview += '…' if truncated?(source, scrubbed)
          preview
        end

        def truncated?(source, scrubbed)
          scrubbed.length > LENGTH || source.length > Scrubber::WINDOW
        end
        private_class_method :truncated?
      end
    end
  end
end
