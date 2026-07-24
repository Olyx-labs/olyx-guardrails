# frozen_string_literal: true

require_relative 'message_content'

module Olyx
  module Guardrails
    # Produces a bounded plain-text representation of structured messages.
    module MessageSource
      module_function

      def call(messages)
        messages.map { |message| MessageContent.text(message) }.join("\n")
      end
    end
  end
end
