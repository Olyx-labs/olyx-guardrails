# frozen_string_literal: true

require 'cgi'

module Olyx
  module Guardrails
    module Text
      # Decodes one bounded layer of HTML entities.
      module HtmlDecoder
        module_function

        def call(value)
          CGI.unescapeHTML(value)
        end
      end
    end
  end
end
