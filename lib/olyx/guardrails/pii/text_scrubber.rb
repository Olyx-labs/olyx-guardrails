# frozen_string_literal: true

require_relative 'pattern_catalog'

module Olyx
  module Guardrails
    module Pii
      # Redacts recognized PII from one String.
      module TextScrubber
        module_function

        def call(text)
          return text unless text.is_a?(String)

          PatternCatalog::ENTRIES.reduce(text) { |output, entry| replace(output, entry) }
        end

        def detect?(text)
          return false unless text.is_a?(String)

          PatternCatalog::ENTRIES.any? { |entry| matches?(text, entry) }
        end

        def replace(text, entry)
          pattern, replacement, validator = entry
          return text.gsub(pattern, replacement) unless validator

          text.gsub(pattern) { |match| validator.call(match) ? replacement : match }
        end

        def matches?(text, entry)
          pattern, _, validator = entry
          text.to_enum(:scan, pattern).any? do
            match = Regexp.last_match[0]
            !validator || validator.call(match)
          end
        end
        private_class_method :matches?, :replace
      end
    end
  end
end
