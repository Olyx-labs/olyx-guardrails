# frozen_string_literal: true

require 'uri'

module Olyx
  module Guardrails
    module Text
      # Decodes one layer of URL-encoded text.
      module UrlDecoder
        module_function

        def call(value)
          URI.decode_www_form_component(value)
        rescue ArgumentError
          value
        end
      end
    end
  end
end
