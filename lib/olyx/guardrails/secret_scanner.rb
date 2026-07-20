# frozen_string_literal: true

require "digest"
require_relative "validation"

module Olyx
  module Guardrails
    # Detects leaked secrets, internal endpoints, private network
    # addresses, and vendor token formats in free text, with distinct detect,
    # redact, and exception-driven enforcement operations.
    #
    # REVIEW: vendor token coverage is a fixed list (GitHub, GitLab, Slack,
    #   npm, AWS, Anthropic, SendGrid, JWT). GCP, Azure, Stripe,
    #   PEM-encoded private keys, and generic high-entropy strings are not
    #   covered. See the README Limitations section.
    class SecretScanner
      CUSTOM_PATTERN_TIMEOUT = 0.1
      REGEXP_TIMEOUT_ERROR = defined?(Regexp::TimeoutError) ? Regexp::TimeoutError : RegexpError

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
      ].map { |marker| Regexp.new(Regexp.escape(marker), Regexp::IGNORECASE) }.freeze

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
        source = text.to_s
        findings = confidentiality_findings(source)
        findings.concat(internal_endpoint_findings(source))
        findings.concat(simple_pattern_findings(source))
        findings.concat(custom_pattern_findings(source, custom_patterns))
        normalize_findings(findings)
      end

      private_class_method def self.compile_custom_patterns(custom_patterns)
        Validation.array_of!(custom_patterns, String, name: "custom_patterns")
        custom_patterns.map { |pattern| compile_custom_pattern(pattern) }
      end

      private_class_method def self.compile_custom_pattern(pattern)
        Regexp.new(pattern, Regexp::IGNORECASE, timeout: CUSTOM_PATTERN_TIMEOUT)
      rescue RegexpError => error
        raise ArgumentError, "invalid custom pattern #{pattern.inspect}: #{error.message}"
      end

      private_class_method def self.confidentiality_findings(source)
        CONFIDENTIALITY_MARKERS.flat_map do |pattern|
          pattern_findings(source, "confidentiality_marker", pattern)
        end
      end

      private_class_method def self.internal_endpoint_findings(source)
        scan_matches(source, INTERNAL_SUFFIXES).map do |match|
          endpoint_finding(source, match)
        end
      end

      private_class_method def self.endpoint_finding(source, match)
        match_end = match.end(0)
        word_start = source[0...match.begin(0)].rindex(/[\s"']/)
        word_start = word_start ? word_start + 1 : 0
        {
          category: "internal_endpoint",
          full:     source[word_start...match_end],
          start:    word_start,
          end:      match_end
        }
      end

      private_class_method def self.simple_pattern_findings(source)
        SIMPLE_FINDING_PATTERNS.flat_map do |category, pattern|
          findings = pattern_findings(source, category, pattern)
          next findings unless category == "private_network_address"

          findings.select { |finding| valid_private_network_match?(finding[:full]) }
        end
      end

      private_class_method def self.custom_pattern_findings(source, custom_patterns)
        compile_custom_patterns(custom_patterns).flat_map do |pattern|
          pattern_findings(source, "custom_pattern", pattern).reject { |finding| finding[:full].empty? }
        rescue REGEXP_TIMEOUT_ERROR
          raise ArgumentError, "custom pattern timed out"
        end
      end

      private_class_method def self.pattern_findings(source, category, pattern)
        scan_matches(source, pattern).map { |match| raw_finding(category, match) }
      end

      private_class_method def self.scan_matches(source, pattern)
        source.to_enum(:scan, pattern).map { Regexp.last_match }
      end

      private_class_method def self.normalize_findings(findings)
        unique = findings.uniq { |finding| finding_identity(finding) }
        unique.sort_by { |finding| finding_sort_key(finding) }
      end

      private_class_method def self.finding_identity(finding)
        [finding[:category], finding[:start], finding[:end]]
      end

      private_class_method def self.finding_sort_key(finding)
        [finding[:start], finding[:end], finding[:category]]
      end

      private_class_method def self.raw_finding(category, match)
        {
          category: category,
          full:     match[0].to_s,
          start:    match.begin(0),
          end:      match.end(0)
        }
      end

      private_class_method def self.valid_private_network_match?(value)
        address = value[/\b(?:10|172|192)\.(?:\d{1,3}\.){2}\d{1,3}\b/]
        address && address.split(".").all? { |octet| octet.to_i.between?(0, 255) }
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

        merged_redaction_spans(findings).reverse_each.with_object(text.dup) do |(start_pos, end_pos), output|
          output[start_pos...end_pos] = "[REDACTED]"
        end
      end

      private_class_method def self.merged_redaction_spans(findings)
        spans = findings.filter_map do |finding|
          start_pos = finding[:start]
          end_pos = finding[:end]
          [start_pos, end_pos] if end_pos > start_pos
        end
        spans.sort.each_with_object([]) { |span, merged| merge_span(merged, span) }
      end

      private_class_method def self.merge_span(merged, span)
        previous = merged.last
        previous_end = previous&.last
        return merged << span unless previous_end && span.first <= previous_end

        previous[1] = [previous_end, span.last].max
      end
    end
  end
end
