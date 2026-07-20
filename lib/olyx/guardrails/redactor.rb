# frozen_string_literal: true

require_relative "pii_scrubber"
require_relative "secret_scanner"
require_relative "validation"

module Olyx
  module Guardrails
    # Applies the explicit PII-and-secret transformation used by
    # {Guardrails.redact}.
    class Redactor
      def self.call(input, max_input_length:, custom_patterns:)
        new(input, max_input_length, custom_patterns).call
      end

      def initialize(input, max_input_length, custom_patterns)
        @source = input.to_s
        @max_input_length = max_input_length
        @custom_patterns = custom_patterns
      end

      def call
        validate!
        secret_result = SecretScanner.redact(@source, custom_patterns: @custom_patterns)
        redacted_text = PiiScrubber.scrub(secret_result[:text])

        {
          text: redacted_text,
          redacted: redacted_text != @source,
          pii_detected: PiiScrubber.scrub(@source) != @source,
          secret_leaked: secret_result[:leaked],
          findings: secret_result[:findings]
        }
      end

      private

      def validate!
        Validation.non_negative_integer!(@max_input_length, name: "max_input_length")
        return if @source.length <= @max_input_length

        raise ArgumentError, "input exceeds max_input_length"
      end
    end
  end
end
