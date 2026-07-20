# frozen_string_literal: true

require "digest"

module Olyx
  module Guardrails
    # Detects leaked secrets, internal endpoints, private network
    # addresses, and vendor token formats in free text, with `alert`,
    # `redact`, and `block` response modes.
    #
    # REVIEW: vendor token coverage is a fixed list (GitHub, GitLab, Slack,
    #   npm, AWS, Anthropic, SendGrid, JWT). GCP, Azure, Stripe,
    #   PEM-encoded private keys, and generic high-entropy strings are not
    #   covered. See the README Limitations section.
    class SecretScanner
      # Raised by {scan!} when a secret is found. Carries the same safe,
      # masked `findings` shape {scan} returns.
      class Blocked < StandardError
        attr_reader :findings

        def initialize(findings)
          @findings = findings
          super("Response blocked: secret leakage detected")
        end
      end

      CONFIDENTIALITY_MARKERS = [
        "confidential", "proprietary", "restricted",
        "internal use only", "not for distribution", "do not share",
        "do not distribute", "top secret", "trade secret", "need to know",
        "company confidential", "attorney-client privilege",
        "attorney client privilege", "work product", "privileged and confidential"
      ].map { |m| Regexp.new(Regexp.escape(m), Regexp::IGNORECASE) }.freeze

      INTERNAL_SUFFIXES = /
        \.internal\b | \.corp\b | \.intranet\b | \.local\/ |
        \bvpc\. | \.private\. | \.lan[\/:]
      /xi.freeze

      PRIVATE_IP_IN_URL = /
        (?:https?:\/\/|:\/\/|host[=:\s]+|endpoint[=:\s]+|@)
        (?:10\.\d{1,3}\.\d{1,3}\.\d{1,3}
        |172\.(?:1[6-9]|2\d|3[01])\.\d{1,3}\.\d{1,3}
        |192\.168\.\d{1,3}\.\d{1,3})
      /xi.freeze

      # AWS access key IDs: 20-char all-caps alphanumeric starting with AKIA/ASIA/AROA/ABIA/ACCA/AIPA.
      AWS_ACCESS_KEY = /\b(AKIA|ASIA|AROA|ABIA|ACCA|AIPA)[A-Z0-9]{16}\b/.freeze

      # AWS secret access keys: 40-char base64 string, often preceded by a label.
      AWS_SECRET_KEY = /
        (?:aws[_\-\s]?(?:secret[_\-\s]?)?(?:access[_\-\s]?)?key
        |secret[_\-\s]access[_\-\s]key)
        [\s=:\"']+([A-Za-z0-9\/+=]{40})\b
      /xi.freeze

      EXTRA_TOKEN_PREFIXES = /
        \bghp_\w+ | \bghs_\w+ | \bgho_\w+ | \bghr_\w+ |
        \bxoxb-\S+ | \bxoxp-\S+ | \bxoxs-\S+ | \bxoxe-\S+ |
        \bglpat-\w+ | \bgldt-\w+ |
        \bnpm_\w+ |
        \bSG\.[A-Za-z0-9._\-]{20,} |
        \bey[A-Za-z0-9._\-]{20,}\.[A-Za-z0-9._\-]{20,} |
        \bsk-(?:ant-|proj-)?[A-Za-z0-9_\-]{20,} |
        \bkey-\S+
      /xi.freeze

      SIMPLE_FINDING_PATTERNS = {
        "private_network_address" => PRIVATE_IP_IN_URL,
        "aws_access_key"          => AWS_ACCESS_KEY,
        "aws_secret_key"          => AWS_SECRET_KEY,
        "secret_token"            => EXTRA_TOKEN_PREFIXES
      }.freeze

      # Detects secrets without modifying input or raising.
      #
      # @param text [#to_s] the text to scan.
      # @param custom_patterns [Array<String>] extra regex strings, compiled
      #   case-insensitively. Invalid patterns raise `ArgumentError`.
      # @return [Hash] `:leaked` and safe, masked `:findings`.
      def self.scan(text, custom_patterns: [])
        source   = text.to_s
        findings = raw_findings(source, custom_patterns: custom_patterns)
        { leaked: findings.any?, findings: findings.map { |finding| public_finding(finding) } }
      end

      # Detects and redacts every match. When a confidentiality marker is the
      # only evidence available, the whole input is redacted rather than
      # returning marked confidential content with just its label removed.
      #
      # @param text [#to_s] the text to redact.
      # @param custom_patterns [Array<String>] see {scan}.
      # @return [Hash] `:text`, `:leaked`, and safe, masked `:findings`.
      def self.redact(text, custom_patterns: [])
        source   = text.to_s
        findings = raw_findings(source, custom_patterns: custom_patterns)
        {
          text:     findings.empty? ? source : apply_redactions(source, findings),
          leaked:   findings.any?,
          findings: findings.map { |finding| public_finding(finding) }
        }
      end

      # Detects secrets and raises when any are found.
      #
      # @param text [#to_s] the text to scan.
      # @param custom_patterns [Array<String>] see {scan}.
      # @return [Hash] the same shape as {scan} when no secret is found.
      # @raise [Blocked] when a secret is found.
      def self.scan!(text, custom_patterns: [])
        result = scan(text, custom_patterns: custom_patterns)
        raise Blocked.new(result[:findings]) if result[:leaked]
        result
      end

      # Detection pass shared by scan, redact, and scan!. Every finding carries
      # the private full match and its source offsets; only public_finding may
      # cross the API boundary.
      #
      # @param text [#to_s]
      # @param custom_patterns [Array<String>]
      # @return [Array<Hash>] private finding Hashes.
      private_class_method def self.raw_findings(text, custom_patterns: [])
        patterns = compile_custom_patterns(custom_patterns)
        findings = []
        t = text.to_s

        CONFIDENTIALITY_MARKERS.each do |re|
          t.to_enum(:scan, re).each do
            match = Regexp.last_match
            findings << raw_finding("confidentiality_marker", match)
          end
        end

        t.to_enum(:scan, INTERNAL_SUFFIXES).each do
          match      = Regexp.last_match
          word_start = t[0...match.begin(0)].rindex(/[\s"']/).then { |index| index ? index + 1 : 0 }
          findings << {
            category: "internal_endpoint",
            full:     t[word_start...match.end(0)],
            start:    word_start,
            end:      match.end(0)
          }
        end

        SIMPLE_FINDING_PATTERNS.each do |category, pattern|
          t.to_enum(:scan, pattern).each do
            findings << raw_finding(category, Regexp.last_match)
          end
        end

        patterns.each do |pattern|
          t.to_enum(:scan, pattern).each do
            match = Regexp.last_match
            findings << raw_finding("custom_pattern", match) unless match[0].empty?
          end
        end

        findings
          .uniq { |finding| [finding[:category], finding[:start], finding[:end]] }
          .sort_by { |finding| [finding[:start], finding[:end], finding[:category]] }
      end

      private_class_method def self.compile_custom_patterns(custom_patterns)
        unless custom_patterns.is_a?(Array) && custom_patterns.all? { |pattern| pattern.is_a?(String) }
          raise ArgumentError, "custom_patterns must be an Array of String values"
        end

        custom_patterns.map do |pattern|
          Regexp.new(pattern, Regexp::IGNORECASE)
        rescue RegexpError => e
          raise ArgumentError, "invalid custom pattern #{pattern.inspect}: #{e.message}"
        end
      end

      private_class_method def self.raw_finding(category, match)
        {
          category: category,
          full:     match[0].to_s,
          start:    match.begin(0),
          end:      match.end(0)
        }
      end

      # Returns useful correlation data without exposing plaintext credentials.
      private_class_method def self.public_finding(finding)
        full = finding[:full]
        {
          category:    finding[:category],
          matched:     masked_value(full),
          fingerprint: "sha256:#{Digest::SHA256.hexdigest(full)[0, 12]}",
          start:       finding[:start],
          end:         finding[:end]
        }
      end

      private_class_method def self.masked_value(value)
        return "[REDACTED]" if value.length < 12
        "#{value[0, 4]}…#{value[-4, 4]}"
      end

      private_class_method def self.apply_redactions(text, findings)
        return "[REDACTED]" if findings.any? { |finding| finding[:category] == "confidentiality_marker" }

        spans = findings
          .map { |finding| [finding[:start], finding[:end]] }
          .select { |start_pos, end_pos| end_pos > start_pos }
          .sort

        merged = spans.each_with_object([]) do |(start_pos, end_pos), result|
          if result.empty? || start_pos > result.last[1]
            result << [start_pos, end_pos]
          else
            result.last[1] = [result.last[1], end_pos].max
          end
        end

        merged.reverse_each.with_object(text.dup) do |(start_pos, end_pos), output|
          output[start_pos...end_pos] = "[REDACTED]"
        end
      end
    end
  end
end
