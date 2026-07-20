# frozen_string_literal: true

require_relative "validation"

module Olyx
  module Guardrails
    # Collects private, offset-aware secret findings. Callers must sanitize
    # these records before exposing them outside the process.
    class SecretFindingCollector
      CUSTOM_PATTERN_TIMEOUT = 0.1
      REGEXP_TIMEOUT_ERROR = defined?(Regexp::TimeoutError) ? Regexp::TimeoutError : RegexpError

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

      AWS_ACCESS_KEY = /\b(AKIA|ASIA|AROA|ABIA|ACCA|AIPA)[A-Z0-9]{16}\b/.freeze

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

      SIMPLE_PATTERNS = {
        "private_network_address" => PRIVATE_IP_IN_URL,
        "aws_access_key" => AWS_ACCESS_KEY,
        "aws_secret_key" => AWS_SECRET_KEY,
        "secret_token" => EXTRA_TOKEN_PREFIXES
      }.freeze

      def self.call(source, custom_patterns: [])
        new(source, custom_patterns).call
      end

      def initialize(source, custom_patterns)
        @source = source.to_s
        @custom_patterns = custom_patterns
      end

      def call
        findings = confidentiality_findings
        findings.concat(internal_endpoint_findings)
        findings.concat(simple_pattern_findings)
        findings.concat(custom_pattern_findings)
        finding_key = ->(finding) { [finding[:start], finding[:end], finding[:category]] }
        findings.uniq(&finding_key).sort_by(&finding_key)
      end

      private

      def confidentiality_findings
        CONFIDENTIALITY_MARKERS.flat_map do |pattern|
          pattern_findings("confidentiality_marker", pattern)
        end
      end

      def internal_endpoint_findings
        scan_matches(INTERNAL_SUFFIXES).map { |match| endpoint_finding(match) }
      end

      def endpoint_finding(match)
        match_end = match.end(0)
        word_start = @source[0...match.begin(0)].rindex(/[\s"']/)
        word_start = word_start ? word_start + 1 : 0
        {
          category: "internal_endpoint",
          full: @source[word_start...match_end],
          start: word_start,
          end: match_end
        }
      end

      def simple_pattern_findings
        SIMPLE_PATTERNS.flat_map do |category, pattern|
          findings = pattern_findings(category, pattern)
          category == "private_network_address" ? valid_network_findings(findings) : findings
        end
      end

      def valid_network_findings(findings)
        findings.select { |finding| valid_private_network_match?(finding[:full]) }
      end

      def custom_pattern_findings
        compile_custom_patterns.flat_map do |pattern|
          pattern_findings("custom_pattern", pattern).reject { |finding| finding[:full].empty? }
        rescue REGEXP_TIMEOUT_ERROR
          raise ArgumentError, "custom pattern timed out"
        end
      end

      def compile_custom_patterns
        Validation.array_of!(@custom_patterns, String, name: "custom_patterns")
        @custom_patterns.map { |pattern| compile_custom_pattern(pattern) }
      end

      def compile_custom_pattern(pattern)
        Regexp.new(pattern, Regexp::IGNORECASE, timeout: CUSTOM_PATTERN_TIMEOUT)
      rescue RegexpError => error
        raise ArgumentError, "invalid custom pattern #{pattern.inspect}: #{error.message}"
      end

      def pattern_findings(category, pattern)
        scan_matches(pattern).map { |match| raw_finding(category, match) }
      end

      def scan_matches(pattern)
        @source.to_enum(:scan, pattern).map { Regexp.last_match }
      end

      def raw_finding(category, match)
        {
          category: category,
          full: match[0].to_s,
          start: match.begin(0),
          end: match.end(0)
        }
      end

      def valid_private_network_match?(value)
        address = value[/\b(?:10|172|192)\.(?:\d{1,3}\.){2}\d{1,3}\b/]
        address && address.split(".").all? { |octet| octet.to_i.between?(0, 255) }
      end
    end
  end
end
