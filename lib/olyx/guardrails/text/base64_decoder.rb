# frozen_string_literal: true

require 'base64'

module Olyx
  module Guardrails
    module Text
      # Decodes one bounded layer of standalone Base64-looking runs. A run is
      # only substituted when it both decodes cleanly and produces printable
      # text, so ordinary alphanumeric text (hex hashes, identifiers) is never
      # corrupted by a coincidental decode.
      module Base64Decoder
        RUN = %r{(?<![A-Za-z0-9+/=])[A-Za-z0-9+/]{16,}={0,2}(?![A-Za-z0-9+/=])}

        # Padding needed to reach a multiple of 4, keyed by length % 4.
        # Unpadded base64 can only end on remainder 0 (none needed), 2, or 3;
        # remainder 1 is not a valid unpadded length and maps to no padding
        # rather than guessing, so decode simply fails for it below.
        PADDING_FOR_REMAINDER = { 0 => '', 2 => '==', 3 => '=' }.freeze

        module_function

        def call(value)
          value.gsub(RUN) { |run| decode(run) || run }
        end

        def decode(run)
          decoded = Base64.strict_decode64(pad(run))
          decoded if printable?(decoded)
        rescue ArgumentError
          nil
        end

        def pad(run) = run + PADDING_FOR_REMAINDER.fetch(run.length % 4, '')

        # [:print:] already covers space; \t/\n/\r are the only extra
        # whitespace worth tolerating, listed explicitly to avoid an overlap
        # with [:print:] inside the negated class.
        def printable?(text) = text.valid_encoding? && !text.match?(/[^[:print:]\t\n\r]/)

        private_class_method :decode, :pad, :printable?
      end
    end
  end
end
