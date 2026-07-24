# frozen_string_literal: true

require_relative 'block_scrubber'
require_relative 'text_scrubber'

module Olyx
  module Guardrails
    module Pii
      # Redacts String or array-style message content.
      module ContentScrubber
        module_function

        def call(content)
          return scrub_text(content) if content.is_a?(String)
          return scrub_blocks(content) if content.is_a?(Array)

          [content, false]
        end

        def scrub_text(text)
          redacted = TextScrubber.call(text)
          [redacted, redacted != text]
        end

        def scrub_blocks(blocks)
          results = blocks.map { |block| BlockScrubber.call(block) }
          [results.map(&:first), results.any?(&:last)]
        end
        private_class_method :scrub_text, :scrub_blocks
      end
    end
  end
end
