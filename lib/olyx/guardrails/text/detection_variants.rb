# frozen_string_literal: true

require_relative 'base64_decoder'
require_relative 'html_decoder'
require_relative 'normalizer'
require_relative 'unicode_escape_decoder'
require_relative 'url_decoder'

module Olyx
  module Guardrails
    module Text
      # Produces bounded single-layer variants for evasion-resistant detection.
      module DetectionVariants
        WINDOW = 20_000
        OVERLAP = 256
        DECODERS = [HtmlDecoder, UrlDecoder, UnicodeEscapeDecoder, Base64Decoder].freeze

        module_function

        def call(value)
          chunks(value.to_s).flat_map { |source| variants(source) }.uniq
        end

        def variants(source)
          normalized = Normalizer.call(source)
          decoded = DECODERS.map { |decoder| decoder.call(normalized) }
          [source, normalized, *decoded].uniq
        end

        def chunks(source)
          return [source] if source.length <= WINDOW

          step = WINDOW - OVERLAP
          (0...source.length).step(step).map { |offset| source[offset, WINDOW] }
        end
        private_class_method :chunks, :variants
      end
    end
  end
end
