module Olyx
  module Guardrails
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

      def self.scan(messages)
        detected = []

        messages.each do |msg|
          content = extract_content(msg)
          next if content.nil?

          case content
          when String then next if content.strip.empty?
          when Array  then next if content.empty?
          end

          role = msg["role"] || msg[:role] || "unknown"

          ALL_PATTERNS.each do |pattern|
            match = content.match(pattern)
            next unless match
            detected << { role: role, match: match[0].strip }
          end
        end

        {
          injection_attempt: detected.any?,
          patterns: detected.uniq { |d| d[:match] }
        }
      end

      def self.check(messages)
        scan(messages)
      end

      def self.injection?(text)
        scan([ { "role" => "user", "content" => text.to_s } ])[:injection_attempt]
      end

      private_class_method def self.extract_content(msg)
        content = msg["content"] || msg[:content]
        case content
        when String then content
        when Array  then content.filter_map { |c| c.is_a?(Hash) ? (c["text"] || c[:text]) : nil }.join(" ")
        else ""
        end
      end
    end
  end
end
