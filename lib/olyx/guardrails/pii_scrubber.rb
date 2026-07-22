# frozen_string_literal: true

require_relative 'pii/message_scrubber'
require_relative 'pii/text_scrubber'

module Olyx
  module Guardrails
    # Stable facade for free-text and chat-message PII redaction.
    class PiiScrubber
      def self.scrub(text)
        Pii::TextScrubber.call(text)
      end

      def self.scrub_messages(messages)
        scrub_messages_with_detection(messages)[:messages]
      end

      def self.scrub_messages_with_detection(messages)
        Pii::MessageScrubber.call(messages)
      end
    end
  end
end
