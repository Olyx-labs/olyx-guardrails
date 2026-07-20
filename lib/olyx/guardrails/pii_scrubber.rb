# frozen_string_literal: true

module Olyx
  module Guardrails
    # Detects and redacts common PII formats (email, phone, SSN, credit
    # card, IPv4, API tokens, passport numbers, IBANs, dates of birth) from
    # free text and chat-style message arrays.
    #
    # REVIEW: pattern coverage is biased toward US/Western formats — non-US
    #   national identifiers and unicode-obfuscated text (spaced-out or
    #   homoglyph substitution) aren't reliably caught. See the README
    #   Limitations section.
    class PiiScrubber
      EMAIL_PATTERN    = /\b[A-Za-z0-9._%+\-]+@[A-Za-z0-9.\-]+\.[A-Za-z]{2,}\b/
      # Require either an international "+" prefix or conventional separators;
      # bare numeric identifiers must not be destroyed as alleged phone data.
      PHONE_PATTERN    = /(?<!\d)(?:\+\d(?:[\s\-.]?\d){7,15}|\(?\d{3}\)?[\s\-.]\d{3}[\s\-.]\d{4})(?!\d)/
      SSN_PATTERN      = /\b\d{3}[- ]\d{2}[- ]\d{4}\b/
      # Anchored on a mandatory trailing digit (not a separator) so the match
      # can't absorb a trailing space/hyphen that belongs to surrounding text.
      #
      # REVIEW: digit-count + Luhn is a structural check, not proof of a real
      #   card number — it will still occasionally match a Luhn-valid ID that
      #   happens not to be a card. There's no way to fully disambiguate
      #   without an issuer/BIN lookup.
      CARD_PATTERN     = /\b\d(?:[ \-]?\d){12,18}\b/
      IPV4_PATTERN     = /\b(?:\d{1,3}\.){3}\d{1,3}\b/
      TOKEN_PATTERN    = /\b(?:Bearer\s+|sk-|ak_live_|fy-ent-)[A-Za-z0-9._\-]{8,}\b/i

      # Passport: most countries use 6-9 alphanumeric chars; anchor with context words
      # to avoid matching arbitrary codes.
      PASSPORT_PATTERN = /\b(?:passport(?:\s+(?:no|number|#))?[\s:]+)([A-Z]{1,2}\d{6,9})\b/i

      # IBAN: 2-letter country code + 2 check digits + up to 30 alphanumeric chars.
      IBAN_PATTERN     = /\b[A-Z]{2}\d{2}[A-Z0-9]{4,30}\b/

      # Date of birth — common formats: MM/DD/YYYY, DD-MM-YYYY, YYYY-MM-DD, spelled out.
      DOB_PATTERN      = /
        \b(?:dob|date\s+of\s+birth|born\s+on|birthday)[\s:]+
        (?:\d{1,2}[\/\-]\d{1,2}[\/\-]\d{2,4}
        |\d{4}[\/\-]\d{1,2}[\/\-]\d{1,2}
        |(?:Jan|Feb|Mar|Apr|May|Jun|Jul|Aug|Sep|Oct|Nov|Dec)[a-z]*\.?\s+\d{1,2},?\s+\d{4})
      /ix

      # Third element is an optional validator — when present, a match is
      # only redacted if it passes. Lets a pattern be a cheap structural
      # filter (digit count) backed by an accuracy check (Luhn) without
      # special-casing any one pattern in `scrub`.
      PATTERNS = [
        [ EMAIL_PATTERN,    "[EMAIL]"    ],
        [ SSN_PATTERN,      "[SSN]",      ->(match) { ssn_valid?(match) } ],
        [ PASSPORT_PATTERN, "[PASSPORT]" ],
        [ IBAN_PATTERN,     "[IBAN]",     ->(match) { iban_valid?(match) } ],
        [ DOB_PATTERN,      "[DOB]"      ],
        [ IPV4_PATTERN,     "[IP]",       ->(match) { ipv4_valid?(match) } ],
        [ TOKEN_PATTERN,    "[TOKEN]"    ],
        [ CARD_PATTERN,     "[CARD]",    ->(match) { luhn_valid?(match) } ],
        [ PHONE_PATTERN,    "[PHONE]"    ]
      ].freeze

      # Redacts every recognized PII pattern in `text`, replacing each match
      # with a bracketed tag (e.g. `[EMAIL]`).
      #
      # @param text [Object] the text to scrub. Non-String values are
      #   returned unchanged.
      # @return [Object] the redacted String, or `text` itself if it wasn't
      #   a String.
      def self.scrub(text)
        return text unless text.is_a?(String)
        PATTERNS.reduce(text) do |t, (pattern, replacement, validator)|
          if validator
            t.gsub(pattern) { |match| validator.call(match) ? replacement : match }
          else
            t.gsub(pattern, replacement)
          end
        end
      end

      # Luhn checksum — filters CARD_PATTERN's digit-count heuristic down to
      # numbers that are actually structurally valid card numbers, so plain
      # numeric IDs (order #s, timestamps, tracking #s) aren't mislabeled.
      #
      # @param number_str [String] a digit sequence, optionally with spaces
      #   or hyphens.
      # @return [Boolean] whether the digits pass the Luhn checksum.
      def self.luhn_valid?(number_str)
        digits = number_str.gsub(/\D/, "").chars.map(&:to_i)
        return false if digits.length < 13

        sum = digits.reverse.each_with_index.sum do |digit, index|
          next digit if index.even?
          doubled = digit * 2
          doubled > 9 ? doubled - 9 : doubled
        end

        (sum % 10).zero?
      end
      private_class_method :luhn_valid?

      # Rejects structurally impossible U.S. SSNs.
      private_class_method def self.ssn_valid?(ssn)
        area, group, serial = ssn.split(/[- ]/)
        return false unless area && group && serial
        !area.match?(/\A(?:000|666|9\d{2})\z/) && group != "00" && serial != "0000"
      end

      # Validates every IPv4 octet instead of accepting values such as
      # 999.999.999.999.
      private_class_method def self.ipv4_valid?(address)
        octets = address.split(".")
        octets.length == 4 && octets.all? { |octet| octet.to_i.between?(0, 255) }
      end

      # ISO 13616 mod-97 validation for IBAN candidates.
      private_class_method def self.iban_valid?(iban)
        compact = iban.delete(" ").upcase
        return false unless compact.match?(/\A[A-Z]{2}\d{2}[A-Z0-9]{11,30}\z/)
        return false unless compact.length.between?(15, 34)

        rearranged = compact[4..] + compact[0, 4]
        remainder = rearranged.each_char.reduce(0) do |value, char|
          digits = char.match?(/[A-Z]/) ? (char.ord - 55).to_s : char
          digits.each_char.reduce(value) { |memo, digit| ((memo * 10) + digit.to_i) % 97 }
        end
        remainder == 1
      end

      # @param messages [Array<Hash>] chat-style messages with `"content"`
      #   or `:content` keys.
      # @return [Array<Hash>] `messages` with String content redacted via
      #   {scrub}.
      def self.scrub_messages(messages)
        scrub_messages_with_detection(messages)[:messages]
      end

      # @param messages [Array<Hash>] chat-style messages with `"content"`
      #   or `:content` keys.
      # @return [Hash] `:messages` (Array, redacted like {scrub_messages})
      #   and `:detected` (Boolean, whether any redaction occurred).
      def self.scrub_messages_with_detection(messages)
        unless messages.is_a?(Array) && messages.all? { |message| message.is_a?(Hash) }
          raise ArgumentError, "messages must be an Array of Hash values"
        end

        detected = false
        scrubbed = messages.map do |msg|
          content_key = msg.key?("content") ? "content" : (msg.key?(:content) ? :content : nil)
          next msg unless content_key

          redacted, content_detected = scrub_content(msg[content_key])
          detected ||= content_detected
          content_detected ? msg.merge(content_key => redacted) : msg
        end

        { messages: scrubbed, detected: detected }
      end

      private_class_method def self.scrub_content(content)
        case content
        when String
          redacted = scrub(content)
          [redacted, redacted != content]
        when Array
          detected = false
          blocks = content.map do |block|
            next block unless block.is_a?(Hash)
            text_key = block.key?("text") ? "text" : (block.key?(:text) ? :text : nil)
            next block unless text_key && block[text_key].is_a?(String)

            redacted = scrub(block[text_key])
            changed  = redacted != block[text_key]
            detected ||= changed
            changed ? block.merge(text_key => redacted) : block
          end
          [blocks, detected]
        else
          [content, false]
        end
      end
    end
  end
end
