module Olyx
  module Guardrails
    class SecretScanner
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

      # AWS access key IDs: 20-char all-caps alphanumeric starting with AKIA/ASIA/AROA/ABIA/ACCA/AIPA
      AWS_ACCESS_KEY = /\b(AKIA|ASIA|AROA|ABIA|ACCA|AIPA)[A-Z0-9]{16}\b/.freeze

      # AWS secret access keys: 40-char base64 string, often preceded by a label
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

      def self.baseline_scan(text)
        findings = []
        t = text.to_s

        CONFIDENTIALITY_MARKERS.each do |re|
          m = re.match(t)
          if m
            findings << { category: "confidentiality_marker", matched: m[0] }
            break
          end
        end

        if (m = INTERNAL_SUFFIXES.match(t))
          word_start = t[0...m.begin(0)].rindex(/[\s"']/).then { |i| i ? i + 1 : 0 }
          findings << { category: "internal_endpoint", matched: t[word_start...m.end(0)] }
        end

        if (m = PRIVATE_IP_IN_URL.match(t))
          findings << { category: "private_network_address", matched: m[0] }
        end

        if (m = AWS_ACCESS_KEY.match(t))
          findings << { category: "aws_access_key", matched: m[0] }
        end

        if (m = AWS_SECRET_KEY.match(t))
          findings << { category: "aws_secret_key", matched: "#{m[0][0..24]}…" }
        end

        if (m = EXTRA_TOKEN_PREFIXES.match(t))
          findings << { category: "secret_token", matched: "#{m[0][0..39]}…" }
        end

        { leaked: findings.any?, findings: findings }
      end

      # Standalone scan — no Rails deps. For project-aware scanning with
      # custom patterns, use SecretLeakageScanner in olyx-api which wraps this.
      def self.scan(text, secret_action: "alert", custom_patterns: [])
        result   = baseline_scan(text)
        findings = result[:findings].dup

        custom_patterns.each do |pattern_str|
          re = Regexp.new(pattern_str, Regexp::IGNORECASE)
          m  = re.match(text.to_s)
          next unless m
          findings << { category: "custom_pattern", matched: m[0].to_s[0..80] }
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
            raise Blocked.new(findings)
          end
        end

        { text: output_text, leaked: leaked, findings: findings }
      end

      private_class_method def self.apply_redactions(text, findings)
        findings.each_with_object(text.dup) do |finding, t|
          raw = finding[:matched].to_s.delete_suffix("…")
          t.gsub!(raw, "[REDACTED]") if raw && !raw.empty?
        end
      end
    end
  end
end
