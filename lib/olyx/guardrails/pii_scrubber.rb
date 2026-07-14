module Olyx
  module Guardrails
    class PiiScrubber
      EMAIL_PATTERN = /\b[A-Za-z0-9._%+\-]+@[A-Za-z0-9.\-]+\.[A-Za-z]{2,}\b/
      PHONE_PATTERN = /(?:\+?\d[\s\-.]?){7,15}\d/
      SSN_PATTERN   = /\b\d{3}[- ]\d{2}[- ]\d{4}\b/
      CARD_PATTERN  = /\b(?:\d[ \-]?){13,19}\b/
      IPV4_PATTERN  = /\b(?:\d{1,3}\.){3}\d{1,3}\b/
      TOKEN_PATTERN = /\b(?:Bearer\s+|sk-|ak_live_|fy-ent-)[A-Za-z0-9._\-]{8,}\b/i

      PATTERNS = [
        [ EMAIL_PATTERN, "[EMAIL]" ],
        [ SSN_PATTERN,   "[SSN]"   ],
        [ IPV4_PATTERN,  "[IP]"    ],
        [ TOKEN_PATTERN, "[TOKEN]" ],
        [ CARD_PATTERN,  "[CARD]"  ],
        [ PHONE_PATTERN, "[PHONE]" ]
      ].freeze

      def self.scrub(text)
        return text unless text.is_a?(String)
        PATTERNS.reduce(text) { |t, (pattern, replacement)| t.gsub(pattern, replacement) }
      end

      def self.scrub_messages(messages)
        scrub_messages_with_detection(messages)[:messages]
      end

      def self.scrub_messages_with_detection(messages)
        detected = false

        scrubbed = messages.map do |msg|
          content = msg["content"] || msg[:content]
          next msg unless content.is_a?(String)

          redacted = scrub(content)
          detected = true if redacted != content

          msg.merge("content" => redacted).tap { |m| m.delete(:content) }
        end

        { messages: scrubbed, detected: detected }
      end
    end
  end
end
