# frozen_string_literal: true

require_relative 'hash_key'
require_relative 'text_scrubber'

module Olyx
  module Guardrails
    module Pii
      # Redacts a text content block while preserving its Hash shape.
      module BlockScrubber
        module_function

        def call(block)
          return [block, false] unless block.is_a?(Hash)

          key = HashKey.call(block, 'text')
          text = block[key] if key
          return [block, false] unless text.is_a?(String)

          result(block, key, text, TextScrubber.call(text))
        end

        def result(block, key, text, redacted)
          changed = redacted != text
          [changed ? block.merge(key => redacted) : block, changed]
        end
        private_class_method :result
      end
    end
  end
end
