# frozen_string_literal: true

module Olyx
  module Guardrails
    # Detects prompt injection and jailbreak attempts in chat-style
    # messages via structural tag patterns, a jailbreak-phrase blocklist,
    # and multi-turn split-attack detection.
    #
    # REVIEW: this is phrase/structure matching, not semantic understanding
    #   — paraphrasing, translation, or encoding (base64, ROT13, etc.) will
    #   evade it. See the README Limitations section.
    class InjectionDetector
      STRUCTURAL_PATTERNS = [
        /\[\s*(?:SYSTEM|INST|INSTRUCTION|OVERRIDE)\s*\]/i,
        /<<\s*(?:sys|system|instructions?)\s*>>/i,
        /#{Regexp.escape("<|system|>")}/i,
        /---+\s*(?:new\s+)?instructions?\s*---+/i,
        /={3,}\s*(?:instructions?|override)\s*={3,}/i,
        /###\s*(?:override|instructions?)/i
      ].freeze

      PHRASE_PATTERNS = [
        /ignore\s+(?:all\s+)?(?:previous|prior)\s+instructions?/i,
        /disregard\s+(?:all\s+)?(?:previous|prior|your)\s+(?:instructions?|rules?|training)/i,
        /forget\s+(?:all\s+)?(?:your|previous)\s+instructions?/i,
        /your\s+(?:new\s+)?(?:instructions?\s+are|rules?\s+are)/i,
        /(?:override|bypass|ignore)\s+your\s+(?:instructions?|safety|restrictions?|filters?|rules?|training)/i,
        /(?:pretend|act)\s+(?:you\s+are|as\s+if\s+you|as\s+a(?:n?\s+AI)?)/i,
        /you\s+are\s+now\s+(?:a|an|free|DAN|unrestricted)/i,
        /(?:jailbreak|dan\s+mode|developer\s+mode|god\s+mode|unrestricted\s+mode)/i,
        /do\s+anything\s+now/i,
        /you\s+have\s+no\s+(?:restrictions?|limits?|rules?|filters?)/i,
        /without\s+(?:any\s+)?(?:restrictions?|filters?|limits?|rules?|safety)/i,
        /new\s+(?:system\s+)?persona/i,
        /system\s*(?:prompt|message|instruction)\s*:/i,
        /reveal\s+(?:your\s+)?(?:system\s+)?(?:prompt|instructions?)/i,
        /repeat\s+(?:your\s+)?(?:system\s+)?(?:prompt|instructions?)/i
      ].freeze

      ALL_PATTERNS = (STRUCTURAL_PATTERNS + PHRASE_PATTERNS).freeze

      # Multi-turn fragment pairs: an attacker can split a jailbreak across two
      # consecutive messages so no single message trips a single-message scanner.
      # Each entry is [user_fragment, assistant_fragment] — both must appear in
      # adjacent user→assistant turns to flag as injection.
      MULTI_TURN_PAIRS = [
        [ /hypothetically/i,        /no\s+restrictions?/i ],
        [ /for\s+a\s+story/i,       /ignore\s+(?:your\s+)?(?:guidelines?|rules?)/i ],
        [ /pretend\s+you('re|\s+are)/i, /as\s+(an?\s+)?(?:AI|assistant)\s+without/i ],
        [ /let'?s?\s+play\s+a\s+game/i, /you\s+(?:must|have\s+to)\s+answer/i ]
      ].freeze

      # Scans a chat-style message array for structural, phrase, and
      # multi-turn injection patterns.
      #
      # @param messages [Array<Hash>] hashes with `"role"`/`:role` and
      #   `"content"`/`:content` keys. `content` may be a String or an
      #   Array of content-block Hashes (each with a `"text"`/`:text` key).
      # @return [Hash] `:injection_attempt` (Boolean) and `:patterns` (Array
      #   of `{ role:, match: }` Hashes, deduplicated by matched text).
      def self.scan(messages)
        detected = []

        messages.each do |msg|
          content = extract_content(msg)
          next if content.strip.empty?

          role = msg["role"] || msg[:role] || "unknown"

          ALL_PATTERNS.each do |pattern|
            match = content.match(pattern)
            next unless match
            detected << { role: role, match: match[0].strip }
          end
        end

        detected.concat(scan_multi_turn(messages))

        {
          injection_attempt: detected.any?,
          patterns: detected.uniq { |d| d[:match] }
        }
      end

      # Alias for {scan}.
      #
      # @param messages [Array<Hash>] see {scan}.
      # @return [Hash] see {scan}.
      def self.check(messages)
        scan(messages)
      end

      # Convenience wrapper for checking a single piece of text as if it
      # were one user message.
      #
      # @param text [#to_s] the text to check.
      # @return [Boolean] whether any injection pattern matched.
      def self.injection?(text)
        scan([ { "role" => "user", "content" => text.to_s } ])[:injection_attempt]
      end

      # @param msg [Hash] see {scan}.
      # @return [String] the message's text content, joining Array-style
      #   content blocks with a space, or `""` if there's no usable content.
      private_class_method def self.extract_content(msg)
        content = msg["content"] || msg[:content]
        case content
        when String then content
        when Array  then content.filter_map { |c| c.is_a?(Hash) ? (c["text"] || c[:text]) : nil }.join(" ")
        else ""
        end
      end

      # @param messages [Array<Hash>] see {scan}.
      # @return [Array<Hash>] `{ role: "multi-turn", match: }` entries for
      #   every adjacent message pair matching a {MULTI_TURN_PAIRS} entry.
      private_class_method def self.scan_multi_turn(messages)
        detected = []
        messages.each_cons(2) do |first, second|
          first_content  = extract_content(first).to_s
          second_content = extract_content(second).to_s
          MULTI_TURN_PAIRS.each do |user_pat, followup_pat|
            first_match  = first_content.match(user_pat)
            second_match = second_content.match(followup_pat)
            next unless first_match && second_match
            detected << {
              role:  "multi-turn",
              match: "#{first_match[0].strip} / #{second_match[0].strip}"
            }
          end
        end
        detected
      end
    end
  end
end
