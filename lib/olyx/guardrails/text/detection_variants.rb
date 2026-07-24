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
        DECODERS = [HtmlDecoder, UrlDecoder, UnicodeEscapeDecoder, Base64Decoder].freeze

        module_function

        def call(value)
          source = value.to_s[0...WINDOW]
          normalized = Normalizer.call(source)
          decoded = DECODERS.map { |decoder| decoder.call(normalized) }
          [source, normalized, *decoded].uniq
        end
      end
    end
  end
end
