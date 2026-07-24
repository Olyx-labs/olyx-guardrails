# frozen_string_literal: true

module Olyx
  module Guardrails
    module Text
      # Decodes one layer of JSON-style Unicode escapes.
      module UnicodeEscapeDecoder
        ESCAPE = /\\u([0-9a-fA-F]{4})/

        module_function

        def call(value)
          value.gsub(ESCAPE) { [::Regexp.last_match(1).to_i(16)].pack('U') }
        rescue RangeError
          value
        end
      end
    end
  end
end
