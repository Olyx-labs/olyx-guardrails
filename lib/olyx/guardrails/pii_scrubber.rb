# frozen_string_literal: true

require_relative 'pii/message_scrubber'
require_relative 'pii/text_scrubber'

module Olyx # :nodoc:
  module Guardrails
    # Redacts documented PII formats from text and structured chat messages.
    #
    # Detection is format-based and intentionally bounded. It is not a complete
    # international PII taxonomy. See docs/OPERATIONS.md#pii for limitations.
    class PiiScrubber
      # :call-seq:
      #   PiiScrubber.scrub(text) -> String or object
      #
      # Returns a redacted String when +text+ is a String. Non-String values are
      # returned unchanged.
      def self.scrub(text)
        Pii::TextScrubber.call(text)
      end

      # :call-seq:
      #   PiiScrubber.scrub_messages(messages) -> Array
      #
      # Returns a copy of +messages+ with supported String content redacted.
      # Message and content-block key style is preserved. Raises ArgumentError
      # unless +messages+ is an Array of Hashes.
      def self.scrub_messages(messages)
        scrub_messages_with_detection(messages)[:messages]
      end

      # :call-seq:
      #   PiiScrubber.scrub_messages_with_detection(messages) -> Hash
      #
      # Redacts +messages+ and returns both the transformed Array and a
      # +:detected+ Boolean. Raises ArgumentError unless +messages+ is an Array
      # of Hashes.
      def self.scrub_messages_with_detection(messages)
        Pii::MessageScrubber.call(messages)
      end
    end
  end
end
