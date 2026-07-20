# frozen_string_literal: true

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
      # Raised by {scan} when `secret_action: "block"` and a secret is
      # found. Carries the same `findings` shape {scan} would otherwise
      # return.
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

      # Categories whose full match is longer than what's safe to surface in
      # findings/logs get truncated for display — but redaction always acts on
      # the untruncated value tracked internally, never the display string.
      DISPLAY_TRUNCATE_AT = {
        "aws_secret_key" => 25,
        "secret_token"   => 40,
        "custom_pattern" => 81
      }.freeze

      # Findings that are just "pattern matched → record the whole match" with
      # no extra logic — unlike confidentiality_marker (first-match-wins) and
      # internal_endpoint (word-boundary expansion), which stay as explicit
      # blocks in raw_findings since their behavior genuinely differs.
      SIMPLE_FINDING_PATTERNS = {
        "private_network_address" => PRIVATE_IP_IN_URL,
        "aws_access_key"          => AWS_ACCESS_KEY,
        "aws_secret_key"          => AWS_SECRET_KEY,
        "secret_token"            => EXTRA_TOKEN_PREFIXES
      }.freeze

      # Runs only the built-in detection patterns — no custom patterns, no
      # redaction/blocking side effects.
      #
      # @param text [#to_s] the text to scan.
      # @return [Hash] `:leaked` (Boolean) and `:findings` (Array of
      #   `{ category:, matched: }` Hashes).
      def self.baseline_scan(text)
        findings = raw_findings(text)
        { leaked: findings.any?, findings: findings.map { |f| display_finding(f) } }
      end

      # Standalone scan — no Rails deps. For project-aware scanning with
      # custom patterns, use SecretLeakageScanner in olyx-api which wraps this.
      #
      # @param text [#to_s] the text to scan.
      # @param secret_action ["alert", "redact", "block"] `"alert"` returns
      #   the original text and marks leakage; `"redact"` replaces matched
      #   secrets with `[REDACTED]`; `"block"` raises {Blocked}.
      # @param custom_patterns [Array<String>] extra regex strings, compiled
      #   case-insensitively. Invalid patterns are silently skipped.
      # @return [Hash] `:text` (String, possibly redacted), `:leaked`
      #   (Boolean), and `:findings` (Array of `{ category:, matched: }`
      #   Hashes).
      # @raise [Blocked] when `secret_action: "block"` and a secret is found.
      def self.scan(text, secret_action: "alert", custom_patterns: [])
        findings = raw_findings(text.to_s)

        custom_patterns.each do |pattern_str|
          re = Regexp.new(pattern_str, Regexp::IGNORECASE)
          m  = re.match(text.to_s)
          next unless m
          findings << { category: "custom_pattern", full: m[0].to_s }
        rescue RegexpError
          next
        end

        leaked      = findings.any?
        output_text = text.to_s

        if leaked
          case secret_action
          when "redact"
            output_text = apply_redactions(output_text, findings)
          when "block"
            raise Blocked.new(findings.map { |f| display_finding(f) })
          end
        end

        { text: output_text, leaked: leaked, findings: findings.map { |f| display_finding(f) } }
      end

      # Detection pass shared by baseline_scan and scan — every finding carries
      # the full, untruncated match under :full so redaction is always exact.
      #
      # @param text [#to_s]
      # @return [Array<Hash>] `{ category:, full: }` Hashes.
      private_class_method def self.raw_findings(text)
        findings = []
        t = text.to_s

        CONFIDENTIALITY_MARKERS.each do |re|
          m = re.match(t)
          if m
            findings << { category: "confidentiality_marker", full: m[0] }
            break
          end
        end

        if (m = INTERNAL_SUFFIXES.match(t))
          word_start = t[0...m.begin(0)].rindex(/[\s"']/).then { |i| i ? i + 1 : 0 }
          findings << { category: "internal_endpoint", full: t[word_start...m.end(0)] }
        end

        SIMPLE_FINDING_PATTERNS.each do |category, pattern|
          if (m = pattern.match(t))
            findings << { category: category, full: m[0] }
          end
        end

        findings
      end

      # @param finding [Hash] a `{ category:, full: }` entry from
      #   {raw_findings}.
      # @return [Hash] `{ category:, matched: }`, with `matched` truncated
      #   per {DISPLAY_TRUNCATE_AT} where applicable.
      private_class_method def self.display_finding(finding)
        limit = DISPLAY_TRUNCATE_AT[finding[:category]]
        full  = finding[:full]
        matched = limit && full.length > limit ? "#{full[0...limit]}…" : full
        { category: finding[:category], matched: matched }
      end

      # @param text [String]
      # @param findings [Array<Hash>] `{ category:, full: }` entries.
      # @return [String] `text` with every finding's full match replaced by
      #   `[REDACTED]`.
      private_class_method def self.apply_redactions(text, findings)
        findings.each_with_object(text.dup) do |finding, t|
          raw = finding[:full].to_s
          t.gsub!(raw, "[REDACTED]") if !raw.empty?
        end
      end
    end
  end
end
