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

        def replace(text, entry)
          pattern, replacement, validator = entry
          return text.gsub(pattern, replacement) unless validator

          text.gsub(pattern) { |match| validator.call(match) ? replacement : match }
        end
        private_class_method :replace
      end
    end
  end
end
